/**
 * 子域名分发中间件（Host 路由）
 *
 * 私服场景：客户端通过改 hosts/DNS 将 *.hypergryph.com 指向私服，
 * 请求保留官服子域名 Host 头。此中间件按子域名将路径映射到私服挂载：
 *   as.hypergryph.com/*        → /auth/*        （账号系统：auth 路由挂载点）
 *   ak-gs-gf.hypergryph.com/*  → /*             （游戏：去掉多余的 /game 前缀，挂载在根路径）
 *   ak-conf.hypergryph.com/*   → 保持           （配置：/config/prod、/api/remote_config）
 *   game-config.hypergryph.com/* → /*           （新版配置：去掉 /game-config 前缀，映射到 /api/remote_config）
 *
 * mitmweb 重定向场景（-M "|^https?://.*\.hypergryph\.com(.*)|http://127.0.0.1:8443\1"）：
 * map remote 设置 URL 时会同步改写 Host 头为 127.0.0.1:8443，子域名信息丢失。
 * 此时按「路径级兜底分发」识别各域接口（见 applyPathFallback）。
 *
 * 非 *.hypergryph.com 请求（localhost / 私服 IP 直连 / mitmweb 重写）不重写，保持原有路径分发。
 */
import { RequestHandler } from "express";
import { hasPathPrefix } from "@utils/path-prefix";

const HOST_SUFFIX = "hypergryph.com";

/**
 * 路径级兜底分发（Host 头不含子域名时按路径识别域）
 *
 * mitmweb 重定向把 URL 改为 http://127.0.0.1:8443<path> 且 Host 头同步改写，
 * 无法再从 Host 区分请求原本来自哪个官服子域名。这里用无歧义的路径前缀兜底：
 *   /game/*        → 剥 /game 基址前缀（ak-gs-* 域带基址的路径化形式）
 *   /app/*         → /auth/*（as 域应用配置，如 /app/v1/config）
 *   /u8/*          → /auth/*（as 域 U8 渠道，如 /u8/user/v1/getToken）
 *   /user/auth*    → /auth/*（as 域登录/注册/Token，游戏域无此二级段）
 *   /user/info*    → /auth/*（as 域用户信息）
 *   /user/online*  → /auth/*（as 域在线心跳/登出）
 *   /user/oauth2*  → /auth/*（as 域 OAuth2 授权）
 *
 * 注意：/user/changeSecretary、/user/buyAp 等游戏域接口的二级段不在上述列表，
 * 不会被误判，保持原路径命中游戏 /user 路由。
 */
function applyPathFallback(req: { url: string }): void {
  const url = req.url;
  // ak-gs 域带 /game 基址前缀（/game/account/login → /account/login）
  if (hasPathPrefix(url, "/game")) {
    req.url = url.slice("/game".length) || "/";
    return;
  }
  // as 域（auth 挂根后路径已与私服挂载一致，无需 /auth 前缀改写）
  // for (const prefix of [
  //   "/app",
  //   "/u8",
  //   "/user/auth",
  //   "/user/info",
  //   "/user/online",
  //   "/user/oauth2",
  // ]) {
  //   if (hasPathPrefix(url, prefix)) {
  //     req.url = "/auth" + url;
  //     return;
  //   }
  // }
}

export function createHostRouter(): RequestHandler {
  return (req, _res, next) => {
    // 路径级子域名前缀：部分客户端把子域名路径化（直连私服 IP 时 Host 不带子域名）
    // 在 Host 判断前处理（覆盖 /as/app/v1/config、/game-config/api/remote_config 等场景）
    if (req.url.startsWith("/as/")) {
      req.url = "/auth" + req.url.slice(3);
      return next();
    }
    if (req.url.startsWith("/game-config/")) {
      req.url = req.url.slice("/game-config".length) || "/";
      return next();
    }

    const host = (req.headers.host || "").toLowerCase();
    if (!host.endsWith(HOST_SUFFIX)) {
      // 非官服 Host（localhost / 私服 IP / mitmweb 重写为 127.0.0.1）：路径级兜底分发
      applyPathFallback(req);
      return next();
    }

    if (host.startsWith("as.")) {
      // 账号系统：auth 已挂根路径（index.ts app.use("/", auth)），as 域请求路径与私服挂载一致，无需重写
    } else if (host.startsWith("ak-gs-")) {
      // 游戏服务器：私服游戏挂载在根路径，若客户端基址带 /game 前缀则去掉，映射回根
      if (hasPathPrefix(req.url, "/game")) {
        req.url = req.url.slice("/game".length) || "/";
      }
    } else if (host.startsWith("game-config.")) {
      // 新版配置服务器：客户端基址带 /game-config 前缀，去掉映射到 /api/remote_config 挂载点
      if (hasPathPrefix(req.url, "/game-config")) {
        req.url = req.url.slice("/game-config".length) || "/";
      }
    }
    // ak-conf.*（以及其余 *.hypergryph 子域名）路径与私服挂载一致，无需重写
    next();
  };
}