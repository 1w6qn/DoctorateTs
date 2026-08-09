/**
 * arkhub 官服网关客户端（获取像素画上传 token / 保存确认）
 *
 * 官服 arkhub 网关（arkhub-gateway.hypergryph.com:30000）为长连接二进制协议，帧格式（自抓包逆向）：
 *   [4B 大端总长（含本 4 字节）][4B mainID][8B subID][protobuf 消息体]
 *
 * 消息 subID（自 tmp/arkhub-gateway/ 抓包确认，跨会话恒定）：
 *   UserLoginReq / UserLoginResp     mainID=4，subID=0x0fa1 / 0x0fa2
 *   RequestPixelArtUploadTokenReq    mainID=8，subID=0x00029CE231D603B3
 *   RequestPixelArtUploadTokenResp   mainID=8，subID=0x00029CE231D60CF6
 *   SavePixelArtReq                  mainID=8，subID=0x00029CE231D674D5
 *
 * 登录凭据即官服 HTTP 会话的 uid/secret（实测 HTTP secret 可直接网关登录，响应 code=100）。
 * RequestPixelArtUploadTokenReq 消息体带 4 字节固定前缀 `00 00 00 03`（命令码，抓包复刻）。
 */
import net from "net";
import { logger } from "@utils/logger";

/** 官服 arkhub 网关地址 */
export const ARKHUB_GATEWAY_HOST = "arkhub-gateway.hypergryph.com";
export const ARKHUB_GATEWAY_PORT = 30000;

/** 消息 subID（登录通道 mainID=4，玩法通道 mainID=8） */
export const GW_USER_LOGIN_REQ = BigInt(0x0fa1);
export const GW_USER_LOGIN_RESP = BigInt(0x0fa2);
export const GW_TOKEN_REQ = BigInt("0x00029ce231d603b3");
export const GW_TOKEN_RESP = BigInt("0x00029ce231d60cf6");
export const GW_SAVE_PIXEL_ART_REQ = BigInt("0x00029ce231d674d5");

/** 网关返回码：100 = OK */
export const GW_CODE_OK = 100;
/** 网关返回码：112 = RelayLoginSuccess（账号已有活动网关会话，中继登录——本工具无法跟随后续节点路由） */
export const GW_CODE_RELAY_LOGIN = 112;

/** 上传令牌凭据（RequestPixelArtUploadTokenResp.Credential） */
export interface UploadCredential {
  pixelArtId: bigint;
  uploadToken: string;
  expireTime: bigint;
}

/** 网关帧 */
interface GwFrame {
  mainID: number;
  subID: bigint;
  proto: Buffer;
}

/* ---------- protobuf 编解码（wire format 子集） ---------- */

/** 无符号 varint 编码 */
export function varint(v: bigint): Buffer {
  const out: number[] = [];
  let value = BigInt.asUintN(64, v);
  do {
    let byte = Number(value & BigInt(0x7f));
    value >>= BigInt(7);
    if (value !== BigInt(0)) byte |= 0x80;
    out.push(byte);
  } while (value !== BigInt(0));
  return Buffer.from(out);
}

/** 解析 varint，返回 { value, pos } */
export function readVarint(buf: Buffer, pos: number): { value: bigint; pos: number } {
  let value = BigInt(0);
  let shift = BigInt(0);
  let p = pos;
  for (;;) {
    if (p >= buf.length) throw new Error("protobuf varint 越界");
    const byte = buf[p++];
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += BigInt(7);
  }
  return { value, pos: p };
}

/** 编码 varint 字段 */
export function fv(field: number, v: bigint): Buffer {
  return Buffer.concat([Buffer.from([field << 3]), varint(v)]);
}

/** 编码 bytes/string 字段 */
export function fb(field: number, data: Buffer): Buffer {
  return Buffer.concat([Buffer.from([(field << 3) | 2]), varint(BigInt(data.length)), data]);
}

/** 解码 protobuf 顶层字段，返回 [{field, wire, value|data}] */
export function parseProto(buf: Buffer): { field: number; wire: number; value: bigint; data: Buffer }[] {
  const out: { field: number; wire: number; value: bigint; data: Buffer }[] = [];
  let pos = 0;
  while (pos < buf.length) {
    const key = buf[pos++];
    const field = key >> 3;
    const wire = key & 7;
    if (wire === 0) {
      const r = readVarint(buf, pos);
      pos = r.pos;
      out.push({ field, wire, value: r.value, data: Buffer.alloc(0) });
    } else if (wire === 2) {
      const r = readVarint(buf, pos);
      pos = r.pos;
      const data = buf.subarray(pos, pos + Number(r.value));
      pos += Number(r.value);
      out.push({ field, wire, value: BigInt(0), data });
    } else {
      throw new Error(`protobuf wire type ${wire} 不支持`);
    }
  }
  return out;
}

/* ---------- 网关连接 ---------- */

/**
 * arkhub 网关会话：登录后保持连接，可申请上传 token / 发送保存确认
 */
export class GatewaySession {
  private sock: net.Socket | null = null;
  private buffer = Buffer.alloc(0);
  private waiters: { subID: bigint; resolve: (f: GwFrame) => void; timer: NodeJS.Timeout }[] = [];
  private closed = false;

  /** 连接网关并登录（code!=100 抛错） */
  async connect(uid: string, secret: string, deviceId: string, timeoutMs = 10000): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const sock = net.connect({ host: ARKHUB_GATEWAY_HOST, port: ARKHUB_GATEWAY_PORT });
      sock.setNoDelay(true);
      sock.on("connect", () => resolve());
      sock.on("error", (e) => reject(new Error(`网关连接失败: ${e.message}`)));
      this.sock = sock;
      sock.on("data", (d) => this.onData(d));
      sock.on("close", () => {
        this.closed = true;
        for (const w of this.waiters) {
          clearTimeout(w.timer);
          w.resolve({ mainID: 0, subID: w.subID, proto: Buffer.alloc(0) });
        }
        this.waiters = [];
      });
    });

    // UserLoginReq: field1=uid, field2=secret, field3=1, field4=deviceId
    const proto = Buffer.concat([
      fb(1, Buffer.from(uid, "utf8")),
      fb(2, Buffer.from(secret, "utf8")),
      fv(3, BigInt(1)),
      fb(4, Buffer.from(deviceId, "utf8")),
    ]);
    const resp = await this.roundTrip(4, GW_USER_LOGIN_REQ, GW_USER_LOGIN_RESP, proto, timeoutMs);
    const fields = parseProto(resp.proto);
    const code = fields.find((f) => f.field === 1)?.value ?? BigInt(-1);
    // 100=正常登录成功；112=RelayLoginSuccess（账号已有活动会话，中继登录——token 请求会
    // 报 "server node not found"，报错并引导用户先清理游戏内会话再重试）
    if (code === BigInt(GW_CODE_OK)) return;
    if (code === BigInt(GW_CODE_RELAY_LOGIN)) {
      throw new Error(
        `官服网关会话被占用（RelayLogin code=112）：账号 ${uid} 已有活动网关会话。` +
          `请在游戏内退出阿卡狄亚大厅稍候重试（旧会话过期后自动恢复）`,
      );
    }
    throw new Error(`网关登录失败 code=${code}`);
  }

  /** 申请像素画上传 token */
  async requestUploadToken(md5: string, timeoutMs = 10000): Promise<UploadCredential> {
    // RequestPixelArtUploadTokenReq：固定 4B 命令码 00000003 + field2=Md5（32 字节 hex 字符串）
    const proto = Buffer.concat([
      Buffer.from([0x00, 0x00, 0x00, 0x03]),
      fb(2, Buffer.from(md5, "ascii")),
    ]);
    const resp = await this.roundTrip(8, GW_TOKEN_REQ, GW_TOKEN_RESP, proto, timeoutMs);
    if (resp.proto.length === 0) {
      throw new Error(
        "申请上传 token 失败：网关连接被关闭（会话未就绪）。官服 token 请求依赖先进入阿卡狄亚场景，" +
          "建议先在游戏内进入一次阿卡狄亚大厅再重试",
      );
    }
    // 响应带 4 字节序列前缀（与请求一致，服务端回显），剥掉后解析：field1=Code, field2=Credential
    const body =
      resp.proto.length >= 4 && resp.proto.subarray(0, 4).equals(Buffer.from([0, 0, 0, 3]))
        ? resp.proto.subarray(4)
        : resp.proto;
    const fields = parseProto(body);
    const code = fields.find((f) => f.field === 1)?.value ?? BigInt(-1);
    if (code !== BigInt(GW_CODE_OK)) {
      const errMsg = fields.find((f) => f.field === 2)?.data.toString("utf8") || "";
      throw new Error(`申请上传 token 失败 code=${code}${errMsg ? `（${errMsg}）` : ""}`);
    }
    const cred = fields.find((f) => f.field === 2);
    if (!cred) throw new Error("申请上传 token 响应缺少 Credential");
    const inner = parseProto(cred.data);
    const pixelArtId = inner.find((f) => f.field === 1)?.value ?? BigInt(0);
    const uploadToken = inner.find((f) => f.field === 2)?.data.toString("utf8") ?? "";
    const expireTime = inner.find((f) => f.field === 3)?.value ?? BigInt(0);
    return { pixelArtId, uploadToken, expireTime };
  }

  /** 保存确认（SavePixelArtReq：field1=pixelArtId, field2=UploadSuccess, field3=DoPublish） */
  async confirmSave(pixelArtId: bigint, uploadSuccess = true, doPublish = false): Promise<void> {
    const proto = Buffer.concat([
      fv(1, pixelArtId),
      fv(2, uploadSuccess ? BigInt(1) : BigInt(0)),
      fv(3, doPublish ? BigInt(1) : BigInt(0)),
    ]);
    this.sendFrame(8, GW_SAVE_PIXEL_ART_REQ, proto);
    // SavePixelArtReq 无直接响应（结果经 PixelArtDataAlterNotify 推送），发完即等 300ms 让网关处理
    await new Promise((r) => setTimeout(r, 300));
  }

  close(): void {
    this.closed = true;
    this.sock?.destroy();
    this.sock = null;
  }

  private sendFrame(mainID: number, subID: bigint, proto: Buffer): void {
    if (!this.sock || this.sock.destroyed) throw new Error("网关连接已关闭");
    const len = 16 + proto.length;
    const frame = Buffer.alloc(len);
    frame.writeUInt32BE(len, 0);
    frame.writeUInt32BE(mainID, 4);
    frame.writeBigUInt64BE(subID, 8);
    proto.copy(frame, 16);
    this.sock.write(frame);
  }

  /** 发送请求并等待指定 subID 的响应 */
  private roundTrip(
    mainID: number,
    reqSubID: bigint,
    respSubID: bigint,
    proto: Buffer,
    timeoutMs: number,
  ): Promise<GwFrame> {
    return new Promise((resolve, reject) => {
      if (this.closed || !this.sock || this.sock.destroyed) {
        reject(new Error("网关连接已关闭"));
        return;
      }
      const waiter = {
        subID: respSubID,
        resolve: (f: GwFrame) => resolve(f),
        timer: setTimeout(() => {
          this.waiters = this.waiters.filter((w) => w !== waiter);
          reject(new Error(`网关请求超时（subID=${respSubID.toString(16)}）`));
        }, timeoutMs),
      };
      this.waiters.push(waiter);
      try {
        this.sendFrame(mainID, reqSubID, proto);
      } catch (e) {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        clearTimeout(waiter.timer);
        reject(e);
      }
    });
  }

  private onData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= 4) {
      const len = this.buffer.readUInt32BE(0);
      if (len < 12 || len > 1 << 20) {
        // 帧异常，丢弃缓冲
        this.buffer = Buffer.alloc(0);
        break;
      }
      if (this.buffer.length < len) break;
      const mainID = this.buffer.readUInt32BE(4);
      const subID = this.buffer.readBigUInt64BE(8);
      const proto = this.buffer.subarray(16, len);
      this.buffer = this.buffer.subarray(len);
      const w = this.waiters.find((x) => x.subID === subID);
      if (w) {
        this.waiters = this.waiters.filter((x) => x !== w);
        clearTimeout(w.timer);
        w.resolve({ mainID, subID, proto });
      }
      // 其它 subID（登录后推送的 EnterSceneNotify 等）忽略
    }
  }
}

/**
 * 便捷函数：网关登录 + 申请像素画上传 token（一次性连接）
 *
 * @param uid - 官服账号 uid（HTTP 会话）
 * @param secret - 官服会话 secret（HTTP 会话，可直接用于网关登录）
 * @param deviceId - 网关登录用设备 id（40 hex，任意生成即可）
 * @param md5 - 像素数据 md5（hex 小写）
 * @returns 上传凭据 { pixelArtId, uploadToken, expireTime }
 */
export async function requestPixelArtUploadToken(
  uid: string,
  secret: string,
  deviceId: string,
  md5: string,
): Promise<UploadCredential> {
  const session = new GatewaySession();
  try {
    await session.connect(uid, secret, deviceId);
    const cred = await session.requestUploadToken(md5);
    logger.debug("arkhub-gateway", `申请上传 token 成功 pixelArtId=${cred.pixelArtId}`);
    return cred;
  } finally {
    session.close();
  }
}

/** 生成网关登录用设备 id（40 位 hex，对齐抓包格式） */
export function randomGatewayDeviceId(): string {
  let s = "";
  const chars = "0123456789abcdef";
  for (let i = 0; i < 40; i++) s += chars[Math.floor(Math.random() * 16)];
  return s;
}
