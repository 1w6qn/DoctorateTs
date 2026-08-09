/**
 * 抓包专用官服转发中间件（capture 模式）
 *
 * 主服务器以 --capture 启动（或 config.capture.enabled=true）时，as/gs 流量不再由私服响应，
 * 而是按官服路由规则转发到官方主机并记录响应（走既有的 traffic-recorder 落盘 tmp/），
 * 用于与私服响应逐接口对比 / 协议逆向。config/asset/admin 等本地挂载点保持本地响应，
 * 客户端才能被引导连接到本代理（network_config 仍由私服本地返回）。
 *
 * 路由分发规则（与 test.ts 独立抓包代理、host-router.applyPathFallback 保持一致）：
 *   Host 优先：
 *     as.*.hypergryph.com        → as 域（账号系统：/user/auth|info|online|oauth2、/u8、/app、/general）
 *     ak-gs-*.hypergryph.com     → gs 域（游戏服务器：剥 /game 基址前缀）
 *     其余 *.hypergryph.com      → 不转发（ak-conf/game-config 等配置域，保持本地）
 *   路径兜底（Host 非官服：localhost/IP 直连 / mitmweb 重写丢子域名）：
 *     /user/auth*|/user/info*|/user/online*|/user/oauth2*、/u8/*、/app/*、/general/*、/as/*
 *                                → as 域（/u8 带 /u8 基址；/as 剥路径化前缀）
 *     /game/*                    → gs 域（剥 /game 基址前缀）
 *     其余 POST                  → gs 域根路径兜底（/account、/shop、/activity、/user/checkIn、
 *                                 /batch_event 等），排除本地挂载点避免误转发
 *     GET 非 as 路径             → 不转发（保持本地响应）
 *
 * 官服对双斜杠路径返回 404，endpoint 统一归一化去前导斜杠。
 */
import { RequestHandler } from "express";
import axios, { AxiosError } from "axios";
import { logger } from "@utils/logger";
import config from "../config";

/** 官服 as 主机（账号系统） */
export const OFFICIAL_AS_HOST = "https://as.hypergryph.com";
/** 官服 gs 主机（游戏服务器） */
export const OFFICIAL_GS_HOST = "https://ak-gs-gf.hypergryph.com";
/** 官服域名后缀（Host 判断用） */
const OFFICIAL_HOST_SUFFIX = "hypergryph.com";

/** as 域路径前缀（path-based 兜底识别，与 test.ts 注册规则一致） */
const AS_PATH_PREFIXES = [
  "/user/auth",
  "/user/info",
  "/user/online",
  "/user/oauth2",
  "/u8",
  "/app",
  "/general",
] as const;

/** 本地挂载点前缀：capture 模式的 gs 根路径 POST 兜底须排除，避免把管理/配置流量误转发官服 */
const LOCAL_ONLY_PREFIXES = [
  "/admin",
  "/assetbundle",
  "/pcSdk",
  "/config",
  "/api",
  "/audit",
  "/arkodc",
] as const;

/** 判断路径是否精确等于 prefix 或以 prefix/ 开头（避免误剥 /gamemode 之类路径） */
function hasPathPrefix(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(prefix + "/");
}

/** 转发目标：baseUrl + 转发路径（endpoint 已去前导斜杠由调用方处理） */
export interface ForwardTarget {
  baseUrl: string;
  path: string;
}

/** 主机覆写配置（缺省用 OFFICIAL_AS_HOST / OFFICIAL_GS_HOST） */
export interface ForwardHostOptions {
  asHost?: string;
  gsHost?: string;
}

/**
 * 解析请求应转发到的官服目标
 *
 * 纯函数（不依赖 config / 网络），便于单元测试。规则：
 * 1. Host 头带官服子域名 → 按 as/gs 子域分发；其余官服子域（ak-conf 等）不转发
 * 2. Host 非官服（私服直连 / mitmweb 重写）→ 按路径前缀识别 as 域，/game 剥前缀到 gs 域，
 *    其余 POST 走 gs 域根路径兜底（排除本地挂载点），GET 非 as 路径不转发
 *
 * @param method - HTTP 方法（大写）
 * @param url - 请求路径（含 query 也无妨，只取 pathname 部分）
 * @param host - Host 头（小写；无则传空串）
 * @param opts - 官服主机覆写
 * @returns 转发目标 { baseUrl, path }；null 表示保持本地（不转发）
 */
export function resolveForwardTarget(
  method: string,
  url: string,
  host: string,
  opts: ForwardHostOptions = {},
): ForwardTarget | null {
  const asHost = opts.asHost || OFFICIAL_AS_HOST;
  const gsHost = opts.gsHost || OFFICIAL_GS_HOST;
  const path = (url.split("?")[0] || "/").replace(/^\/+/, "/");

  const h = host.toLowerCase();
  if (h.endsWith(OFFICIAL_HOST_SUFFIX)) {
    if (h.startsWith("as.")) {
      // as 域：官服 as 路径无 /auth 前缀，原样转发
      return { baseUrl: asHost, path };
    }
    if (h.startsWith("ak-gs-")) {
      // gs 域：官服游戏路径无 /game 基址，若客户端带则剥掉
      const p = hasPathPrefix(path, "/game") ? path.slice("/game".length) || "/" : path;
      return { baseUrl: gsHost, path: p };
    }
    // ak-conf / game-config / 其余官方子域：配置与资源域，保持本地
    return null;
  }

  // Host 非官服（127.0.0.1 / localhost / mitmweb 重写）：路径级兜底识别
  // as 域路径化前缀（/as/user/auth/... → as 域，剥 /as）
  if (hasPathPrefix(path, "/as")) {
    return { baseUrl: asHost, path: path.slice("/as".length) || "/" };
  }
  for (const prefix of AS_PATH_PREFIXES) {
    if (hasPathPrefix(path, prefix)) {
      // /u8/* 官服挂在 as 域 /u8 基址下（as.hypergryph.com/u8/...）
      const base = prefix === "/u8" ? `${asHost}/u8` : asHost;
      return { baseUrl: base, path };
    }
  }
  // gs 域路径化形式：/game/* 剥基址前缀
  if (hasPathPrefix(path, "/game")) {
    return { baseUrl: gsHost, path: path.slice("/game".length) || "/" };
  }
  // 根路径游戏域兜底（POST）：排除本地挂载点，避免 /admin 等被误转发
  if (method.toUpperCase() === "POST" && !LOCAL_ONLY_PREFIXES.some((p) => hasPathPrefix(path, p))) {
    return { baseUrl: gsHost, path };
  }
  // GET 非 as 路径（/pcSdk、/admin、/assetbundle 等）保持本地
  return null;
}

/**
 * 创建官服转发中间件
 *
 * 仅应在 capture 模式下挂载（index.ts 按 --capture / config.capture.enabled 判断）。
 * 命中转发的请求直接 res 返回官服响应（不 next()），未命中的调用 next() 走本地路由。
 * 转发响应经外层 traffic-recorder 中间件自动落盘 tmp/（capture 模式已强制开启记录）。
 *
 * @returns Express 中间件
 */
export function createOfficialForwarder(): RequestHandler {
  const asHost = config.capture?.asHost || OFFICIAL_AS_HOST;
  const gsHost = config.capture?.gsHost || OFFICIAL_GS_HOST;

  return async (req, res, next) => {
    const target = resolveForwardTarget(req.method, req.url, req.headers.host || "", {
      asHost,
      gsHost,
    });
    if (!target) return next();

    // 官服对双斜杠路径返回 404：归一化去前导斜杠，保证拼出的转发 URL 无 //
    const endpoint = target.path.replace(/^\/+/, "");

    try {
      const response = await axios({
        method: req.method,
        url: `${target.baseUrl}/${endpoint}`,
        data: req.method === "POST" ? req.body : undefined,
        headers: { ...req.headers, Host: undefined },
        params: req.query,
        // 官服返回 401/400 等状态属正常（未带有效 secret/参数），不抛异常，原样透传
        validateStatus: () => true,
      });
      res.status(response.status).send(response.data);
    } catch (error) {
      // 仅网络层错误（官方主机不可达）返回 502；有响应则已由 validateStatus 透传
      const axiosError = error as AxiosError;
      logger.error(
        "capture",
        `官服转发失败 ${req.method} ${req.originalUrl} → ${target.baseUrl}/${endpoint}: ${axiosError.message}`,
      );
      res.status(502).send("Bad Gateway");
    }
  };
}
