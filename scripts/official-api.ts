/**
 * 官服 API 客户端
 *
 * 封装明日方舟官服的登录与玩家数据拉取协议（参考 reference/checkin-master）：
 * 1. getResVersion：获取资源/客户端版本
 * 2. getToken：三步登录（token_by_phone_password → oauth2/grant → u8 getToken）
 * 3. loginGame：游戏服务器登录（拿 secret）
 * 4. syncPlayerData：拉取完整玩家数据（syncData 的 user 字段）
 *
 * 全部使用 Node 24 内置 fetch + node:crypto，零第三方依赖。
 */
import crypto from "node:crypto";

export const GAME_API = "https://ak-gs-gf.hypergryph.com";
export const ACCOUNT_API = "https://as.hypergryph.com";
export const CONF_API = "https://ak-conf.hypergryph.com";

/** u8 签名密钥（官服 SDK 固定值） */
const U8_SECRET = "91240f70c09a08a6bc72af1a5c8d4670";
/** 明日方舟官方 appCode（oauth2 grant 用） */
const ARKNIGHTS_APP_CODE = "7318def77669979d";

/** 玩家数据模型（官服 syncData 的 user 字段，与私服存档同源） */
export interface OfficialPlayerData {
  [key: string]: any;
  status: { [key: string]: any; uid: string };
}

/** u8 签名：参数按 key=value&... 排序拼接后 HMAC-SHA1 */
export function u8Sign(data: { [key: string]: any }): string {
  const signStr = Object.entries(data)
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  return crypto.createHmac("sha1", U8_SECRET).update(signStr).digest("hex");
}

export function md5(str: string): string {
  return crypto.createHash("md5").update(str).digest("hex");
}

/** 生成随机设备 ID（模拟客户端设备指纹） */
export function getRandomDevices(): {
  deviceId: string;
  deviceId2: string;
  deviceId3: string;
} {
  const hex = (len: number) =>
    Array.from({ length: len }, () =>
      Math.floor(Math.random() * 16).toString(16),
    ).join("");
  return {
    deviceId: md5(hex(12)),
    deviceId2: "85" + Array.from({ length: 13 }, () => Math.floor(Math.random() * 10)).join(""),
    deviceId3: md5(hex(12)),
  };
}

async function postJson(url: string, body?: any): Promise<any> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} @ ${url}`);
  }
  return res.json();
}

/** 获取官服资源/客户端版本 */
export async function getResVersion(): Promise<{
  resVersion: string;
  clientVersion: string;
}> {
  const res = await fetch(
    `${CONF_API}/config/prod/official/Android/version`,
  );
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} @ version`);
  }
  const data = await res.json();
  if (!data?.resVersion || !data?.clientVersion) {
    throw new Error("invalid version response");
  }
  return { resVersion: data.resVersion, clientVersion: data.clientVersion };
}

/**
 * 三步登录获取官服 access_token 与 uid
 * 参考：reference/checkin-master/index.ts get_token
 */
export async function getToken(
  phone: string,
  password: string,
  deviceId: string,
  deviceId2: string,
  deviceId3: string,
): Promise<{ token: string; uid: string }> {
  // 1. 手机号+密码换 token
  const r1 = await postJson(`${ACCOUNT_API}/user/auth/v1/token_by_phone_password`, {
    phone,
    password,
  });
  const token1 = r1?.data?.token;
  if (!token1) {
    throw new Error("登录失败：token_by_phone_password 未返回 token");
  }

  // 2. oauth2 grant 换渠道 token
  const r2 = await postJson(`${ACCOUNT_API}/user/oauth2/v2/grant`, {
    token: token1,
    appCode: ARKNIGHTS_APP_CODE,
    type: 1,
  });
  const token2 = r2?.data?.token;
  if (!token2) {
    throw new Error("登录失败：oauth2 grant 未返回 token");
  }

  // 3. u8 getToken 换游戏 access_token
  const req: { [key: string]: any } = {
    appId: "1",
    channelId: "1",
    extension: JSON.stringify({ code: token2, isSuc: true, type: 2 }),
    worldId: "1",
    platform: 1,
    subChannel: "1",
    deviceId,
    deviceId2,
    deviceId3,
  };
  req.sign = u8Sign(req);
  const r3 = await postJson(`${ACCOUNT_API}/u8/user/v1/getToken`, req);
  // 官服/参考实现返回顶层 token/uid（DoctoratePy u8.py、checkin-master 解构顶层）；兼容 data 包装
  const token = r3?.token ?? r3?.data?.token;
  const uid = r3?.uid ?? r3?.data?.uid;
  if (!token || !uid) {
    throw new Error(
      `登录失败：u8 getToken 未返回 token/uid（result=${r3?.result}, error=${r3?.error ?? r3?.msg ?? ""}）`,
    );
  }
  return { token, uid };
}

/**
 * 游戏服务器登录（拿 secret）
 * 参考：reference/checkin-master/index.ts Player.init
 */
export async function loginGame(
  uid: string,
  token: string,
  resVersion: string,
  clientVersion: string,
  devices: { deviceId: string; deviceId2: string; deviceId3: string },
): Promise<{ secret: string; seqnum: string }> {
  const res = await fetch(`${GAME_API}/account/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      networkVersion: "5",
      uid,
      token,
      assetsVersion: resVersion,
      clientVersion,
      platform: 1,
      deviceId: devices.deviceId,
      deviceId2: devices.deviceId2,
      deviceId3: devices.deviceId3,
    }),
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} @ account/login`);
  }
  const data = await res.json();
  if (!data?.secret) {
    throw new Error("登录失败：account/login 未返回 secret");
  }
  // 官服响应头带 seqnum（后续请求必须递增——参考 checkin-master post 后更新）
  const seqnum = res.headers.get("seqnum") || "1";
  return { secret: data.secret, seqnum };
}

/**
 * 完整流程：拉取官服玩家数据（syncData 的 user 字段）
 * @returns 官服玩家数据（与私服存档同源）
 */
export async function syncPlayerData(
  phone: string,
  password: string,
): Promise<OfficialPlayerData> {
  const { resVersion, clientVersion } = await getResVersion();
  const devices = getRandomDevices();
  const { token, uid } = await getToken(
    phone,
    password,
    devices.deviceId,
    devices.deviceId2,
    devices.deviceId3,
  );
  const { secret, seqnum } = await loginGame(uid, token, resVersion, clientVersion, devices);

  const res = await fetch(`${GAME_API}/account/syncData`, {
    method: "POST",
    headers: {
      uid,
      secret,
      seqnum,
      "Content-Type": "application/json",
      // 对齐参考实现（checkin-master post 头）：Unity 版本头官服可能校验
      "X-Unity-Version": "2017.4.39f1",
      "User-Agent":
        "Dalvik/2.1.0 (Linux; U; Android 6.0.1; X Build/V417IR)",
      Connection: "Keep-Alive",
    },
    body: JSON.stringify({ platform: 1 }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} @ syncData: ${body.slice(0, 200)}`);
  }
  const data = await res.json();
  if (!data?.user) {
    throw new Error("syncData 未返回玩家数据");
  }
  return data.user as OfficialPlayerData;
}
