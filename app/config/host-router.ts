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
 * 非 *.hypergryph.com 请求（localhost / 私服 IP 直连）不重写，保持原有路径分发。
 */
import { RequestHandler } from "express";

const HOST_SUFFIX = "hypergryph.com";

/** 判断路径是否精确等于 prefix 或以 prefix/ 开头（避免误剥 /gamemode 之类路径） */
function hasPathPrefix(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(prefix + "/");
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
      return next();
    }

    if (host.startsWith("as.")) {
      // 账号系统：官方 as 域路径不带前缀，补上私服 /auth 挂载点；已带前缀则保持（幂等）
      if (!hasPathPrefix(req.url, "/auth")) {
        req.url = "/auth" + req.url;
      }
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