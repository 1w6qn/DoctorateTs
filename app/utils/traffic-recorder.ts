/**
 * 调试请求/响应记录中间件
 *
 * 调试时记录每个 HTTP 请求的 request 与 response，写入统一抓包存储
 * （captureManager → tmp/capture/，SQLite 索引 + records/{rid}/ body 文件），
 * 供 Dashboard「抓包」Tab / CLI / 脚本查询与对比（官服 vs 私服逐接口）。
 *
 * 由 data/config.json 的 `debug.recordTraffic: true` 开启（默认关，避免正常运行时落盘噪音），
 * capture 模式（--capture）强制开启。与 morgan 不同：morgan 只输出一行访问日志；
 * 本中间件保存完整请求/响应体用于协议对比。
 *
 * **默认排除本地管理/资源/配置噪音**：/admin、/assetbundle、/pcSdk、/config、/api、
 * /audit、/batch_event 等本地挂载请求不记录（协议对比无意义且 /admin 轮询、资源下载量大），
 * 可通过 `debug.recordTrafficExclude` 覆盖（传空数组 [] = 全部记录）。
 *
 * 与旧版差异：不再写 tmp/{module}/{endpoint}/{timestamp}.json 散文件——
 * 全部来源（私服/capture 转发/独立代理/官服操作）统一进入 captureManager 存储。
 */
import { RequestHandler } from "express";
import { captureManager, CaptureSource } from "@capture/capture-manager";
import { logger } from "@utils/logger";

/**
 * 默认排除的本地挂载路径前缀（与 official-forward 的 LOCAL_ONLY_PREFIXES 对齐）：
 * 管理后台（/admin 页面 + API + 30s 轮询）、资源下载（/assetbundle 大文件）、
 * SDK（/pcSdk）、配置（/config /api——launcher/remote_config）、事件上报（/batch_event）、
 * 审计（/audit）。这些请求在两种模式下都由私服本地响应，记录纯属噪音。
 */
const DEFAULT_EXCLUDE_PREFIXES = [
  "/admin",
  "/assetbundle",
  "/pcSdk",
  "/config",
  "/api",
  "/audit",
  "/batch_event",
] as const;

/** 路径是否命中任一排除前缀（精确匹配前缀本身或以 前缀/ 开头，避免误伤 /apiary 之类路径） */
function isExcluded(path: string, prefixes: readonly string[]): boolean {
  return prefixes.some((p) => path === p || path.startsWith(p + "/"));
}

/**
 * 创建调试记录中间件
 *
 * 拦截 res.send/res.json，在响应发出（finish）后把 request/response 异步写入
 * captureManager 存储。写入失败仅 logger.debug，不阻塞响应。
 * 命中默认/自定义排除前缀的请求直接放行不记录（不包裹 res 方法，零开销）。
 *
 * @param config - 应用配置（读取 debug.recordTraffic / debug.recordTrafficExclude）
 * @param source - 抓包来源标记（capture 官服转发模式传 "official"，普通私服 "private"）
 * @returns Express 中间件
 */
export function createTrafficRecorder(
  config: { debug?: { recordTraffic?: boolean; recordTrafficExclude?: string[] } },
  source: CaptureSource = "private",
): RequestHandler {
  return (req, res, next) => {
    if (!config.debug?.recordTraffic) return next();
    // 排除本地管理/资源/配置噪音（recordTrafficExclude 覆盖默认列表；[] = 全部记录）
    const excludes = config.debug.recordTrafficExclude ?? DEFAULT_EXCLUDE_PREFIXES;
    const pathname = req.originalUrl.split("?")[0];
    if (isExcluded(pathname, excludes)) return next();

    const startedAt = Date.now();
    // 非 JSON（multipart 等）请求体：index.ts capture 模式用 rawBody 捕获原始字节
    const rawBody = (req as unknown as { rawBody?: Buffer }).rawBody;

    const originalSend = res.send.bind(res);
    const originalJson = res.json.bind(res);
    let body: unknown;

    res.json = ((data: unknown) => {
      body = data;
      return originalJson(data);
    }) as typeof res.json;

    res.send = ((data: unknown) => {
      body = data;
      return originalSend(data);
    }) as typeof res.send;

    // 响应结束（finish 事件）后异步落库，不阻塞响应
    res.on("finish", () => {
      void (async () => {
        try {
          // Express res.send/res.json 在链上可能已把对象序列化为字符串，统一解析回对象再落盘
          let payload: unknown = body ?? undefined;
          if (typeof payload === "string") {
            try {
              payload = JSON.parse(payload);
            } catch {
              /* 非 JSON 文本（如 404 HTML）保持原样 */
            }
          }
          const url = req.originalUrl.split("?")[0];
          const query = req.originalUrl.includes("?") ? req.originalUrl.split("?")[1] : undefined;

          // 请求体：rawBody（multipart/二进制原始字节）优先，其次 req.body（JSON）
          const reqBody =
            rawBody && rawBody.length > 0
              ? { kind: "bin" as const, data: rawBody }
              : req.body !== undefined && req.body !== null
                ? { kind: "json" as const, data: req.body }
                : undefined;

          // 响应体：对象→json；Buffer/非 JSON 字符串→bin
          const resBody =
            payload === undefined
              ? undefined
              : typeof payload === "object" && !Buffer.isBuffer(payload)
                ? { kind: "json" as const, data: payload }
                : { kind: "bin" as const, data: payload };

          await captureManager.addRecord(
            {
              ts: startedAt,
              method: req.method,
              path: url,
              query,
              status: res.statusCode,
              latencyMs: Date.now() - startedAt,
              source,
              reqHeaders: req.headers as Record<string, unknown>,
              resHeaders: res.getHeaders() as Record<string, unknown>,
            },
            {
              req: reqBody,
              res: resBody,
            },
          );
        } catch (e) {
          logger.debug("traffic-recorder", "记录失败:", (e as Error).message);
        }
      })();
    });

    next();
  };
}
