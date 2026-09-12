/**
 * 远程配置路由（game-config 接口）
 *
 * 新版客户端请求的远程配置路径（game-config 域名）：
 *   /api/remote_config/1/prod/default/Windows/network_config
 *
 * 响应为官方格式的扁平 JSON：{ an, as, gs, hu, hv, of, sl, u8, pkgAd, prean,
 * devsdk, pkgIOS, configVer }，各 *hypergryph.com 端点替换为实际服务器地址。
 */
import { Router } from "express";
import config from "./index";
import type { NetworkEndpointValue, RemoteConfigValue } from "./index";

/**
 * 用实际服务器地址替换各端点的官方域名或 {server} 占位符（保留端口与私服路径前缀）
 * @param raw - 端点地址（调用方已过滤 null；空串原样返回）
 * @returns 指向私服的地址
 */
function resolveServer(raw: string): string {
  if (!raw) return raw;
  const server = `${config.Host}:${config.PORT}`;
  return raw
    .replace("{server}", server)
    .replace(/^[a-z]+:\/\/[a-z0-9.-]+(?::\d+)?/i, server);
  // {0} 占位符保留（客户端自行替换为版本/平台，如 hv: .../official/{0}/version）
}

/**
 * 构建网络配置 content（JSON 字符串，替换 {server} 占位符）
 * 供旧版 /official/network_config（{sign, content} 格式）使用
 */
export function buildNetworkConfigContent(): string {
  return JSON.stringify(config.NetworkConfig).replace(
    /{server}/g,
    `${config.Host}:${config.PORT}`,
  );
}

/**
 * 构建官方格式的网络配置对象（各端点域名替换为私服地址）
 * @returns 扁平端点表（configVer/devsdk/pkgIOS + network 表，secure/rc 不下发）
 */
export function buildNetworkConfig(): Record<string, NetworkEndpointValue> {
  const net = config.NetworkConfig?.configs;
  const network = net ? Object.values(net)[0]?.network ?? {} : {};
  const { configVer = "5", devsdk = false, pkgIOS = null } = config.NetworkConfig;
  const out: Record<string, NetworkEndpointValue> = { configVer };
  for (const [key, value] of Object.entries(network)) {
    if (key === "secure" || key === "rc") continue;
    // 端点值：字符串走地址替换；布尔/null（如 pkgAd/pkgIOS 空占位）原样透传
    out[key] = typeof value === "string" ? resolveServer(value) : value;
  }
  out.pkgIOS = typeof pkgIOS === "string" ? resolveServer(pkgIOS) : null;
  out.devsdk = devsdk;
  return out;
}

const router = Router();

/** 官服默认远程功能配置（remote_config 响应，可被 config.json 的 RemoteConfig 覆盖） */
const DEFAULT_REMOTE_CONFIG: Record<string, RemoteConfigValue> = {
  fapv2: 1,
  HGDownload_1: 10000,
  HGDownload_2: 10000,
  enableGameBI: true,
  showRecordNumber: false,
  enableNativeLicense: true,
  bakeMuzzleEnableRate: 0,
  enemyBakeMuzzleEnableRate: 3000,
};

/**
 * 构建远程功能配置（官方格式扁平 JSON：fapv2/HGDownload_1 等）
 * @returns 官方默认开关与 config.json RemoteConfig 覆盖的合并结果
 */
export function buildRemoteConfig(): Record<string, RemoteConfigValue> {
  return { ...DEFAULT_REMOTE_CONFIG, ...(config.RemoteConfig ?? {}) };
}

/**
 * GET /1/prod/default/Windows/network_config
 * 新版客户端启动时请求的远程网络配置
 */
router.get("/1/prod/default/Windows/network_config", async (_req, res) => {
  res.send(buildNetworkConfig());
});

/**
 * GET /1/prod/default/Windows/remote_config
 * 新版客户端启动时请求的远程功能配置（fapv2/HGDownload 等开关）
 */
router.get("/1/prod/default/Windows/remote_config", async (_req, res) => {
  res.send({});
});

/** Android 平台别名（与 Windows 同响应，覆盖 Android 客户端启动请求） */
router.get("/1/prod/default/Android/network_config", async (_req, res) => {
  res.send(buildNetworkConfig());
});
router.get("/1/prod/default/Android/remote_config", async (_req, res) => {
  res.send({});
});


/** bilibili/101 渠道变体（ODPY 对齐；客户端使用 default 渠道，此处 stub） */
router.get("/1/prod/bilibili/Android/network_config", async (_req, res) => {
  res.send(buildNetworkConfig());
});
router.get("/1/prod/bilibili/Windows/network_config", async (_req, res) => {
  res.send(buildNetworkConfig());
});
router.get("/101/prod/default/Android/ak_sdk_config", async (_req, res) => {
  res.send({});
});

export const remoteConfigRouter = router;
