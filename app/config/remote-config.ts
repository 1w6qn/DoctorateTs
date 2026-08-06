/**
 * 远程配置路由（game-config 接口）
 *
 * 新版客户端请求的远程配置路径（game-config 域名）：
 *   /api/remote_config/1/prod/default/Windows/network_config
 *
 * 响应格式与旧版 /config/prod/official/network_config 一致：{ sign, content }，
 * content 为网络配置 JSON 字符串，{server} 占位符替换为实际服务器地址。
 */
import { Router } from "express";
import config from "../config";

/**
 * 构建网络配置 content（JSON 字符串，替换 {server} 占位符）
 * 供旧版 /official/network_config 与新版 /api/remote_config 共用
 */
export function buildNetworkConfigContent(): string {
  return JSON.stringify(config.NetworkConfig).replace(
    /{server}/g,
    `${config.Host}:${config.PORT}`,
  );
}

const router = Router();

/**
 * GET /1/prod/default/Windows/network_config
 * 新版客户端启动时请求的远程网络配置
 */
router.get("/1/prod/default/Windows/network_config", async (_req, res) => {
  const content = buildNetworkConfigContent();
  const sign = "sign";
  res.send({ sign, content });
});

export const remoteConfigRouter = router;
