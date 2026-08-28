/**
 * 官服操作服务
 *
 * 以官服账号（手机号+密码）建立会话（三步登录 → account/login 拿 secret/seqnum），
 * 执行签到 / 邮件等官服操作。无状态：每次操作新建会话、完成后即弃（服务端不保留官服凭据）。
 *
 * 协议参考 reference/checkin-master（seqnum 递增、响应头更新）：
 * - POST /account/syncData          拉取玩家数据（user 字段）
 * - POST /user/checkIn              签到
 * - POST /mail/getMetaInfoList      邮件元信息
 * - POST /mail/receiveAllMail       批量领取邮件
 */
import {
  GAME_API,
  getResVersion,
  getToken,
  loginGame,
  getRandomDevices,
} from "../../../scripts/official-api";
import { pixelDataMd5, validatePixelData } from "./arkhub-pixel";
import { captureManager } from "@capture/capture-manager";
import { logger } from "@utils/logger";
import {
  GatewaySession,
  randomGatewayDeviceId,
} from "./arkhub-gateway-client";

/**
 * 记录一次官服调用请求/响应到统一抓包存储（source=ops，请求头脱敏：去除 secret）。
 * 写入失败不影响官服调用（logger.debug 记录）。
 */
async function recordOfficialCall(
  cgi: string,
  req: { body?: any; headers: Record<string, string> },
  res: { status: number; body: any },
): Promise<void> {
  const { secret: _secret, ...safeHeaders } = req.headers; // 脱敏：不落盘 secret
  try {
    await captureManager.addRecord(
      {
        ts: Date.now(),
        method: "POST",
        path: cgi,
        status: res.status,
        source: "ops",
        reqHeaders: safeHeaders,
        note: "官服操作（official-ops）",
      },
      {
        req:
          typeof req.body === "string"
            ? { kind: "json", data: req.body }
            : req.body !== undefined
              ? { kind: "json", data: req.body }
              : undefined,
        res: { kind: "json", data: res.body },
      },
    );
  } catch (e) {
    logger.debug("official-ops", "抓包记录失败:", (e as Error).message);
  }
}

/** 支持的官服操作 */
export type OfficialAction =
  | "status" // 账号状态（登录 + sync）
  | "signin" // 签到（今日已签返回 reason）
  | "mails" // 邮件列表
  | "receive" // 领取全部邮件
  | "daily"; // 一键日常（签到 + 领邮件）

/** 官服 cgi 路径校验：仅允许 /xxx/yyy 形式的官方接口路径 */
export function validateCgi(cgi: string): string {
  const p = String(cgi ?? "").trim();
  if (!/^\/[A-Za-z0-9_/]+$/.test(p)) {
    throw new Error(`非法的官服接口路径: ${cgi}（须为 /xxx/yyy 形式）`);
  }
  return p;
}

/** 官服会话（无状态操作使用，单次用完即弃） */
export class OfficialSession {
  uid = "";
  secret = "";
  seqnum = 1;
  /** 最近一次 syncData 的 user 字段 */
  data: any = null;

  /** 三步登录 + 游戏登录拿 secret */
  async login(phone: string, password: string): Promise<void> {
    const { resVersion, clientVersion } = await getResVersion();
    const devices = getRandomDevices();
    const { token, uid } = await getToken(
      phone,
      password,
      devices.deviceId,
      devices.deviceId2,
      devices.deviceId3,
    );
    this.uid = uid;
    const { secret, seqnum } = await loginGame(uid, token, resVersion, clientVersion, devices);
    this.secret = secret;
    this.seqnum = Number(seqnum) || 1;
  }

  /** 拉取官服玩家数据 */
  async sync(): Promise<any> {
    const data = await this.post("/account/syncData", { platform: 1 });
    this.data = data?.user ?? this.data;
    return this.data;
  }

  /** 官服 POST（带 secret/seqnum 头；seqnum 按响应头更新或自增；调用记录到统一抓包存储） */
  async post(cgi: string, body?: any): Promise<any> {
    const headers: Record<string, string> = {
      uid: this.uid,
      secret: this.secret,
      seqnum: String(this.seqnum),
      "Content-Type": "application/json",
      "X-Unity-Version": "2017.4.39f1",
      "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 6.0.1; X Build/V417IR)",
      Connection: "Keep-Alive",
    };
    let status = 0;
    let data: any = null;
    try {
      const res = await fetch(GAME_API + cgi, {
        method: "POST",
        headers,
        body: JSON.stringify(body ?? {}),
      });
      status = res.status;
      if (!res.ok) {
        throw new Error(`官服 HTTP ${res.status} @ ${cgi}`);
      }
      const seqnumHeader = res.headers.get("seqnum");
      this.seqnum =
        seqnumHeader && !Number.isNaN(Number(seqnumHeader))
          ? Number(seqnumHeader)
          : this.seqnum + 1;
      data = await res.json();
      if (data?.user) this.data = data.user;
      return data;
    } finally {
      // 无论成功失败都记录（请求脱敏去除 secret；响应含 status 与 body）
      void recordOfficialCall(
        cgi,
        { body: body ?? {}, headers },
        { status, body: { status, ...(data ?? { error: "请求失败" }) } },
      );
    }
  }

  /** 官服签到 */
  async checkIn(): Promise<any> {
    return this.post("/user/checkIn", {});
  }

  /** 官服 multipart POST（复用 uid/secret/seqnum 头；用于 arkhub savePixelArt 二进制上传） */
  async postMultipart(cgi: string, boundary: string, body: Buffer): Promise<any> {
    const headers: Record<string, string> = {
      uid: this.uid,
      secret: this.secret,
      seqnum: String(this.seqnum),
      "Content-Type": `multipart/form-data; boundary="${boundary}"`,
      "X-Unity-Version": "2017.4.39f1",
      "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 6.0.1; X Build/V417IR)",
      Connection: "Keep-Alive",
      "Content-Length": String(body.length),
    };
    let status = 0;
    let data: any = null;
    try {
      const res = await fetch(GAME_API + cgi, {
        method: "POST",
        headers,
        // Buffer 运行时是合法 BodyInit，仅 TS 类型不认，cast 兼容
        body: body as unknown as BodyInit,
      });
      status = res.status;
      if (!res.ok) {
        throw new Error(`官服 HTTP ${res.status} @ ${cgi}`);
      }
      const seqnumHeader = res.headers.get("seqnum");
      this.seqnum =
        seqnumHeader && !Number.isNaN(Number(seqnumHeader))
          ? Number(seqnumHeader)
          : this.seqnum + 1;
      data = await res.json();
      // 官服业务状态码校验：savePixelArt 等接口 HTTP 200 但 body.statusCode 非 0/200
      // 表示业务失败（如 "Invalid multipart payload format"）——不校验会被当成功，
      // 该张实际未保存导致批量上传缺一张、官服展示错位
      const bizCode = (data as any)?.statusCode ?? (data as any)?.code;
      if (bizCode !== undefined && bizCode !== 0 && bizCode !== 200) {
        throw new Error(`官服业务失败 statusCode=${bizCode} @ ${cgi}: ${JSON.stringify(data).slice(0, 200)}`);
      }
      return data;
    } finally {
      // 请求体为二进制不落盘完整字节，只记长度
      void recordOfficialCall(
        cgi,
        { body: `<multipart ${body.length}B>`, headers },
        { status, body: { status, ...(data ?? { error: "请求失败" }) } },
      );
    }
  }

  /** 官服卡池详情（getPoolDetail） */
  async getPoolDetail(poolId: string): Promise<any> {
    const res = await this.post("/gacha/getPoolDetail", { poolId, gachaObjGroupType: 0 });
    return res?.detailInfo ?? null;
  }

  /** 官服邮件元信息列表 */
  async listMails(): Promise<any[]> {
    const res = await this.post("/mail/getMetaInfoList", { from: 0 });
    return Array.isArray(res?.result) ? res.result : [];
  }

  /** 领取全部邮件 */
  async receiveAll(): Promise<any> {
    return this.post("/mail/receiveAllMail", {
      sysMailIdList: [],
      surveyMailIdList: [],
      mailIdList: [],
    });
  }

  /** 账号状态摘要 */
  statusSummary(): any {
    const s = this.data?.status ?? {};
    return {
      nickName: s.nickName,
      nickNumber: s.nickNumber,
      uid: s.uid,
      level: s.level,
      ap: s.ap,
      maxAp: s.maxAp,
      gold: s.gold,
      androidDiamond: s.androidDiamond,
      socialPoint: s.socialPoint,
      lggShard: s.lggShard,
      hggShard: s.hggShard,
      canCheckIn: this.data?.checkIn?.canCheckIn ?? 0,
    };
  }
}

/**
 * 无状态执行一次官服操作（每次新建会话，完成后即弃）
 * @returns { action, ok, data?|reason? }
 */
export async function runOfficialAction(
  phone: string,
  pwd: string,
  action: OfficialAction,
): Promise<{ action: string; ok: boolean; data?: any; reason?: string }> {
  const session = new OfficialSession();
  await session.login(phone, pwd);

  switch (action) {
    case "status": {
      await session.sync();
      return { action, ok: true, data: session.statusSummary() };
    }
    case "signin": {
      await session.sync();
      if (!session.data?.checkIn?.canCheckIn) {
        return { action, ok: false, reason: "今日已签到" };
      }
      await session.checkIn();
      return { action, ok: true, data: "签到成功" };
    }
    case "mails": {
      await session.sync();
      const mails = await session.listMails();
      return {
        action,
        ok: true,
        data: {
          count: mails.length,
          unread: mails.filter((m: any) => m.state === 0).length,
          mails: mails.map((m: any) => ({
            mailId: m.mailId,
            hasItem: m.hasItem,
            state: m.state,
          })),
        },
      };
    }
    case "receive": {
      await session.sync();
      const res = await session.receiveAll();
      return { action, ok: true, data: res };
    }
    case "daily": {
      await session.sync();
      const out: any = { signin: "今日已签到", mails: null };
      if (session.data?.checkIn?.canCheckIn) {
        await session.checkIn();
        out.signin = "签到成功";
      }
      const mails = await session.listMails();
      out.mails = { count: mails.length, unread: mails.filter((m: any) => m.state === 0).length };
      await session.receiveAll();
      out.received = true;
      return { action, ok: true, data: out };
    }
    default:
      throw new Error(`未知官服操作: ${action}`);
  }
}

/**
 * 官服通用 API 调用（登录后调用任意官方 cgi）
 * 无状态：每次调用新建会话登录，完成后即弃。
 * @param phone - 官服手机号
 * @param pwd - 官服密码
 * @param cgi - 官服接口路径（如 /user/checkIn、/activity/loginOnly/getReward）
 * @param body - 请求体（可选）
 * @returns 官服完整响应（result/playerDataDelta 等）
 */
export async function runOfficialCall(
  phone: string,
  pwd: string,
  cgi: string,
  body?: any,
): Promise<{ cgi: string; result: any }> {
  const path = validateCgi(cgi);
  const session = new OfficialSession();
  await session.login(phone, pwd);
  const result = await session.post(path, body ?? {});
  return { cgi: path, result };
}

/**
 * 从官服同步卡池详情（逐个调 getPoolDetail）
 * 无状态：登录一次、遍历 poolIds 抓取，完成后即弃。
 * @param phone - 官服手机号
 * @param pwd - 官服密码
 * @param poolIds - 目标卡池 poolId 列表
 * @returns 每个池的抓取结果（成功含 detailInfo；单个失败不中断）
 */
export async function runGachaSync(
  phone: string,
  pwd: string,
  poolIds: string[],
): Promise<{ poolId: string; detailInfo?: any; error?: string }[]> {
  const session = new OfficialSession();
  await session.login(phone, pwd);
  const results: { poolId: string; detailInfo?: any; error?: string }[] = [];
  for (const poolId of poolIds) {
    try {
      const detailInfo = await session.getPoolDetail(poolId);
      if (!detailInfo) {
        throw new Error("官服未返回 detailInfo（卡池可能不存在）");
      }
      results.push({ poolId, detailInfo });
    } catch (e) {
      results.push({ poolId, error: (e as Error).message });
    }
  }
  return results;
}

/**
 * 上传像素画到官服 arkhub（完整流程）
 *
 * 1. 登录官服（HTTP 会话，拿 uid/secret）
 * 2. 计算像素数据 md5
 * 3. 网关申请上传 token（arkhub-gateway:30000，登录 + RequestPixelArtUploadTokenReq）
 * 4. HTTP POST /activity/arkhub/savePixelArt（multipart：json part=brief{activityId,token} + pixelData part）
 * 5. 网关保存确认（SavePixelArtReq）
 *
 * 注意：像素画会真实写入官服账号的 act1arkhub 活动。
 * @param phone - 官服手机号
 * @param pwd - 官服密码
 * @param pixelData - 24×24×3 RGB 像素数据（1728 字节，自动校验）
 * @returns { pixelArtId, uploadToken, httpResp }
 */
export async function uploadPixelArt(
  phone: string,
  pwd: string,
  pixelData: Buffer,
): Promise<{ pixelArtId: bigint; uploadToken: string; httpResp: any }> {
  const results = await uploadPixelArtBatch(phone, pwd, [pixelData]);
  const r = results[0];
  if (!r.ok) throw new Error(r.error ?? "上传失败");
  return { pixelArtId: r.pixelArtId!, uploadToken: r.uploadToken!, httpResp: r.httpResp };
}

/**
 * 批量上传像素画到官服 arkhub（速度优化：登录一次 + 网关连接一次，循环处理全部块）
 *
 * 与单张 uploadPixelArt 相比，不再每张独立登录 HTTP 会话（多次 getResVersion/getToken/loginGame）
 * 与独立建立网关 TCP 连接（每次连接含 1.5s 场景就绪等待）——批量版只登录一次、
 * 网关连接一次，复用同一连接循环 申请 token → HTTP 上传 → 确认保存，最后统一登出。
 * 16 张 24×24（96×96 大图）从约 40s 降至数秒。
 *
 * @param phone - 官服手机号
 * @param pwd - 官服密码
 * @param pixelDataList - 多张 24×24×3 RGB 像素数据（每项自动校验）
 * @returns 逐张结果（index/ok/pixelArtId/uploadToken/httpResp/error；单张失败不中断）
 */
export async function uploadPixelArtBatch(
  phone: string,
  pwd: string,
  pixelDataList: Buffer[],
): Promise<{
  index: number;
  ok: boolean;
  pixelArtId?: bigint;
  uploadToken?: string;
  httpResp?: any;
  error?: string;
}[]> {
  const results: {
    index: number;
    ok: boolean;
    pixelArtId?: bigint;
    uploadToken?: string;
    httpResp?: any;
    error?: string;
  }[] = [];
  if (pixelDataList.length === 0) return results;

  // HTTP 会话 + 网关连接只建一次（批量版核心优化）
  const session = new OfficialSession();
  await session.login(phone, pwd);
  const deviceId = randomGatewayDeviceId();
  const gw = new GatewaySession();
  await gw.connect(session.uid, session.secret, deviceId);

  /** 单张 multipart 请求体（与真实客户端字节级一致） */
  const buildMultipart = (token: string, pixels: Buffer): { boundary: string; body: Buffer } => {
    const boundary = "AKHUB" + Date.now().toString(16).toUpperCase() + Math.floor(Math.random() * 1000).toString(16);
    const brief = JSON.stringify({ brief: { activityId: "act1arkhub", token } });
    const part = (name: string, filename: string, contentType: string, data: Buffer): Buffer =>
      Buffer.concat([
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="${name}"; filename="${filename}"\r\n` +
            `Content-Type: ${contentType}\r\nContent-Length: ${data.length}\r\n\r\n`,
        ),
        data,
        Buffer.from("\r\n"),
      ]);
    const body = Buffer.concat([
      part("json", "json_info", "application/json", Buffer.from(brief, "utf8")),
      part("pixelData", "pixelDataFile", "multipart/form-data", pixels),
      Buffer.from(`--${boundary}--\r\n`),
    ]);
    return { boundary, body };
  };

  try {
    for (let i = 0; i < pixelDataList.length; i++) {
      try {
        // 每张之间短暂等待，保证官服按上传顺序记录（展示从新到旧依赖上传完成顺序；
        // 连续提交官服可能按处理完成时间排序导致乱序）
        if (i > 0) await new Promise((r) => setTimeout(r, 400));
        const pixels = validatePixelData(pixelDataList[i]);
        const md5 = pixelDataMd5(pixels);
        // 网关申请上传 token（复用已连接网关会话）
        const cred = await gw.requestUploadToken(md5);
        // HTTP multipart 上传（复用 HTTP 会话，seqnum 自动递增）
        const { boundary, body } = buildMultipart(cred.uploadToken, pixels);
        const httpResp = await session.postMultipart("/activity/arkhub/savePixelArt", boundary, body);
        // 网关保存确认（复用同一连接）
        await gw.confirmSave(cred.pixelArtId, true, false);
        results.push({
          index: i,
          ok: true,
          pixelArtId: cred.pixelArtId,
          uploadToken: cred.uploadToken,
          httpResp,
        });
      } catch (e) {
        results.push({ index: i, ok: false, error: (e as Error).message });
      }
    }
  } finally {
    gw.close();
  }
  return results;
}

/**
 * 从官服读取已上传像素画列表（HTTP getPixelArt）
 *
 * 登录官服后 POST /activity/arkhub/getPixelArt（body { activityId, pixelArtIds }），
 * 响应 pixelArts[id] = { url, isBanned }（OSS .dat 文件地址）。随后逐个下载 .dat
 * （24×24×3 = 1728 字节 RGB），解析为像素数组返回。
 *
 * 注意：官服 syncData 的 ARK_HUB 不含已上传像素画 ID 列表（仅 coin/secretary/squads），
 * ID 只能来自上传时返回（savePixelArt 的 pixelArtId）——调用方需显式传入 pixelArtIds
 * （dashboard 用 localStorage 保存上传记录）。
 *
 * @param phone - 官服手机号
 * @param pwd - 官服密码
 * @param pixelArtIds - 像素画 ID 列表（缺省返回空数组——无法枚举官服全部）
 * @returns 每张 { id, url, isBanned, pixels?（1728 字节，下载失败为 null） }
 */
export async function getPixelArtList(
  phone: string,
  pwd: string,
  pixelArtIds?: (number | bigint)[],
): Promise<{ id: string; url: string; isBanned: boolean; pixels: number[] | null }[]> {
  const ids: (number | bigint)[] = pixelArtIds ?? [];
  if (ids.length === 0) return [];
  const session = new OfficialSession();
  await session.login(phone, pwd);

  const resp = await session.post("/activity/arkhub/getPixelArt", {
    activityId: "act1arkhub",
    pixelArtIds: ids.map((x) => Number(x)),
  });
  const pixelArts = resp?.pixelArts ?? {};
  const results: { id: string; url: string; isBanned: boolean; pixels: number[] | null }[] = [];
  for (const id of Object.keys(pixelArts)) {
    const info = pixelArts[id] ?? {};
    let pixels: number[] | null = null;
    try {
      const url = info.url as string;
      if (url) {
        const res = await fetch(url);
        if (res.ok) {
          const buf = Buffer.from(await res.arrayBuffer());
          if (buf.length === 1728) pixels = Array.from(buf);
        }
      }
    } catch {
      /* 单个下载失败保持 null */
    }
    results.push({ id, url: info.url ?? "", isBanned: !!info.isBanned, pixels });
  }
  return results;
}

/**
 * 撤销（删除）已上传像素画（网关 DeletePixelArtReq，subID 按 Save 推断）
 *
 * 网关连接一次，逐个发送删除帧。subID 未从抓包确认（协议类顺序 Save→Publish→Delete），
 * 按 SavePixelArtReq+1 推断；发送后等待响应，无响应视为成功（尽力而为）。
 *
 * @param phone - 官服手机号
 * @param pwd - 官服密码
 * @param pixelArtIds - 要删除的像素画 ID 列表
 * @returns 逐张结果
 */
export async function deletePixelArt(
  phone: string,
  pwd: string,
  pixelArtIds: (number | bigint)[],
): Promise<{ id: string; ok: boolean; error?: string }[]> {
  const results: { id: string; ok: boolean; error?: string }[] = [];
  if (pixelArtIds.length === 0) return results;

  const session = new OfficialSession();
  await session.login(phone, pwd);
  const deviceId = randomGatewayDeviceId();
  const gw = new GatewaySession();
  await gw.connect(session.uid, session.secret, deviceId);
  try {
    for (const id of pixelArtIds) {
      try {
        await gw.deletePixelArt(BigInt(id));
        results.push({ id: String(id), ok: true });
      } catch (e) {
        results.push({ id: String(id), ok: false, error: (e as Error).message });
      }
    }
  } finally {
    gw.close();
  }
  return results;
}
