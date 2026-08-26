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
import axios, { AxiosError, RawAxiosRequestHeaders } from "axios";
import http from "http";
import https from "https";
import { logger } from "@utils/logger";
import { hasPathPrefix, matchesAnyPrefix, LOCAL_ONLY_PREFIXES } from "@utils/path-prefix";
import config from "../config";
import { resolveRegion, resolveRegionAsPrefixes, resolveRegionHosts } from "../config/region";
import {
  ArkhubGatewayInfo,
  adaptArkhubEnterHallResponse,
  isArkhubEnterHall,
  updateGatewayTarget,
} from "./arkhub-gateway";

/**
 * 官服连接复用 agent（模块级共享）：所有转发请求复用同一连接池——
 * 避免每请求重新 TLS 握手（首请求冷启动实测 ~100-170ms，复用后 ~60ms 官服 RTT）。
 * Node 24 全局 agent 默认已 keep-alive，这里显式建池保证跨版本行为一致且可调。
 */
export const officialHttpAgent = new http.Agent({ keepAlive: true, maxSockets: 64 });
export const officialHttpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 64,
  keepAliveMsecs: 30000,
});

/**
 * 预热官服连接（capture 启动时调用）
 *
 * 用共享 agent 向 as/gs 各发一个轻量请求，提前建立 TLS 连接——客户端首个请求
 * （登录 getToken/oauth2 等）不再付 TLS 冷启动延迟（实测首个请求 171ms vs 之后 58-61ms）。
 * 轻量端点：as 用 /general/v1/server_time（GET 快返回），gs 用 /account/login（空 body 400 快返回）。
 *
 * @param asHost - 官服 as 主机
 * @param gsHost - 官服 gs 主机
 */
export async function warmUpOfficialConnections(
  asHost: string,
  gsHost: string,
): Promise<void> {
  await Promise.allSettled([
    axios({
      method: "GET",
      url: `${asHost}/general/v1/server_time`,
      httpAgent: officialHttpAgent,
      httpsAgent: officialHttpsAgent,
      validateStatus: () => true,
      timeout: 5000,
    }),
    axios({
      method: "POST",
      url: `${gsHost}/account/login`,
      data: {},
      headers: { "content-type": "application/json" },
      httpAgent: officialHttpAgent,
      httpsAgent: officialHttpsAgent,
      validateStatus: () => true,
      timeout: 5000,
    }),
  ]);
}

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

/**
 * 本地挂载点前缀（单一事实源在 @utils/path-prefix，此处 re-export 保持既有引用点）
 */
export { LOCAL_ONLY_PREFIXES } from "@utils/path-prefix";

/** 转发目标：baseUrl + 转发路径（endpoint 已去前导斜杠由调用方处理） */
export interface ForwardTarget {
  baseUrl: string;
  path: string;
}

/** 主机覆写配置（缺省用 OFFICIAL_AS_HOST / OFFICIAL_GS_HOST） */
export interface ForwardHostOptions {
  asHost?: string;
  gsHost?: string;
  /** 额外 as 域路径前缀（region 扩展——yostar 登录链路等；缺省不扩展） */
  asPathPrefixes?: string[];
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
  const asPathPrefixes = [...AS_PATH_PREFIXES, ...(opts.asPathPrefixes ?? [])];
  const path = (url.split("?")[0] || "/").replace(/^\/+/, "/");

  const h = host.toLowerCase();
  if (h.endsWith(OFFICIAL_HOST_SUFFIX)) {
    if (h.startsWith("as.")) {
      // as 域：官服 as 路径无 /auth 前缀，原样转发
      return { baseUrl: asHost, path };
    }
    if (h.startsWith("ak-gs-")) {
      // gs 域：官服游戏路径无 /game 基址，若客户端带则剥掉；
      // 本地挂载点（/batch_event 等）无论 Host 都不转发——事件上报由私服 home.ts 返回 {} 即可
      const p = hasPathPrefix(path, "/game") ? path.slice("/game".length) || "/" : path;
      if (matchesAnyPrefix(p, LOCAL_ONLY_PREFIXES)) {
        return null;
      }
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
  for (const prefix of asPathPrefixes) {
    if (hasPathPrefix(path, prefix)) {
      // 注意：path 保留完整原路径（含 /u8），baseUrl 只给 as 域根地址——若 baseUrl 再拼 /u8 基址
      // 会与 path 里的 /u8 双写（实测 as.hypergryph.com/u8/u8/user/v1/getToken → 404），
      // 与 Host 分支（as.* → baseUrl=asHost + 全路径）保持一致
      return { baseUrl: asHost, path };
    }
  }
  // gs 域路径化形式：/game/* 剥基址前缀
  if (hasPathPrefix(path, "/game")) {
    return { baseUrl: gsHost, path: path.slice("/game".length) || "/" };
  }
  // 根路径游戏域兜底（POST）：排除本地挂载点，避免 /admin 等被误转发
  if (method.toUpperCase() === "POST" && !matchesAnyPrefix(path, LOCAL_ONLY_PREFIXES)) {
    return { baseUrl: gsHost, path };
  }
  // GET 非 as 路径（/pcSdk、/admin、/assetbundle 等）保持本地
  return null;
}

/** 官服转发中间件选项 */
export interface OfficialForwarderOptions {
  /** arkhub 网关代理信息（capture 模式启动 30000 转发器后传入；缺省/null 时不改写 enterHall 响应） */
  arkhubGateway?: ArkhubGatewayInfo | null;
}

/**
 * 创建官服转发中间件
 *
 * 仅应在 capture 模式下挂载（index.ts 按 --capture / config.capture.enabled 判断）。
 * 命中转发的请求直接 res 返回官服响应（不 next()），未命中的调用 next() 走本地路由。
 * 转发响应经外层 traffic-recorder 中间件自动落盘 tmp/（capture 模式已强制开启记录）。
 *
 * @param opts - 转发选项（arkhub 网关代理信息）
 * @returns Express 中间件
 */
export function createOfficialForwarder(opts: OfficialForwarderOptions = {}): RequestHandler {
  // region 主机数据源（优先级：region.as/gs → capture.asHost/gsHost 现状 → OFFICIAL_*_HOST）；
  // as 域路径前缀同步扩展（region.asPathPrefixes，yostar 登录链路等）
  const region = resolveRegion();
  const fallbackAs = config.capture?.asHost || OFFICIAL_AS_HOST;
  const fallbackGs = config.capture?.gsHost || OFFICIAL_GS_HOST;
  const hosts = region
    ? resolveRegionHosts(region, fallbackAs, fallbackGs)
    : { as: fallbackAs, gs: fallbackGs };
  const asPathPrefixes = resolveRegionAsPrefixes(region, AS_PATH_PREFIXES);
  const { arkhubGateway } = opts;

  return async (req, res, next) => {
    const target = resolveForwardTarget(req.method, req.url, req.headers.host || "", {
      asHost: hosts.as,
      gsHost: hosts.gs,
      asPathPrefixes,
    });
    if (!target) return next();

    // 官服对双斜杠路径返回 404：归一化去前导斜杠，保证拼出的转发 URL 无 //
    const endpoint = target.path.replace(/^\/+/, "");

    // 转发头剥离 host/content-length/transfer-encoding：
    // 客户端原始 body 可能带空白/换行（content-length 94B），express.json 解析后 axios
    // 重序列化变短（74B）——透传 content-length 会让官服按声明长度等剩余字节而永久挂起，
    // 去掉后由 axios 按实际发送的 body 重算；transfer-encoding 同理（axios 按 data 定 chunked/定长）。
    const forwardedHeaders: RawAxiosRequestHeaders = { ...req.headers };
    delete forwardedHeaders.host;
    delete forwardedHeaders["content-length"];
    delete forwardedHeaders["transfer-encoding"];

    // POST 转发体：非 JSON（multipart 等）用 index.ts 捕获的原始字节 rawBody 原样透传——
    // express.json 不解析 multipart，透传 req.body（空 {}）会让官服 400 "Invalid multipart payload format"；
    // 无 rawBody（测试/独立挂载）时回退 req.body
    const rawBody = (req as unknown as { rawBody?: Buffer }).rawBody;
    const requestData =
      req.method === "POST"
        ? rawBody && rawBody.length > 0
          ? rawBody
          : req.body
        : undefined;

    try {
      const response = await axios({
        method: req.method,
        url: `${target.baseUrl}/${endpoint}`,
        data: requestData,
        headers: forwardedHeaders,
        // 复用共享连接池（避免每请求 TLS 握手）
        httpAgent: officialHttpAgent,
        httpsAgent: officialHttpsAgent,
        // Express ParsedQs 与 axios params 类型不兼容，cast 兼容
        params: req.query as any,
        // 官服返回 401/400 等状态属正常（未带有效 secret/参数），不抛异常，原样透传
        validateStatus: () => true,
      });
      res.status(response.status).send(
        // 特殊适配：arkhub enterHall 响应带官服网关 endpoint（2026-08-18 起为
        // arkhub-gateway-canary.hypergryph.com:30000——官服灰度迁移，老域名登录帧 0 响应），
        // 1) 先动态更新 TCP 转发器目标（updateGatewayTarget），使转发器跟随官服网关域名变化；
        // 2) 再改写为代理地址，客户端才会连到本代理、网关流量才经过代理被抓。
        isArkhubEnterHall(target.path)
          ? (updateGatewayTarget(
              (response.data as { endpoint?: string })?.endpoint ?? "",
              (response.data as { port?: number })?.port ?? 30000,
            ),
            arkhubGateway
              ? adaptArkhubEnterHallResponse(response.data, arkhubGateway)
              : response.data)
          : response.data,
      );
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
