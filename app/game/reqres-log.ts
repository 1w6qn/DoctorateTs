/**
 * 临时请求/响应记录中间件（调试用）
 *
 * 用途：排查客户端与服务端交互问题（如 rlv2 开局/推进异常）时，逐请求记录
 * req body 与 res body，便于复现与分析。属临时调试设施，生产环境建议关闭。
 *
 * 记录方式与 capture 抓包系统一致：写入 captureManager 统一存储
 * （tmp/capture/index.db SQLite 索引 + records/{rid}/req.json|res.json body 文件），
 * 可在 Dashboard「抓包」Tab 查询/对比（source=private，note="reqres-log"），
 * 而非自建文本日志。
 *
 * 开关（环境变量 REQRES_LOG，默认 "rlv2"）：
 *   - "all"   记录所有请求
 *   - "rlv2"  仅记录 /rlv2/ 路径（默认，当前调试主题）
 *   - "0"/"false"/"off"/空  关闭
 *
 * 与 traffic-recorder（debug.recordTraffic 开关、全量+排除前缀）的区别：
 * 本中间件用环境变量按路径前缀精确过滤，适合临时定向抓某个接口族。
 */
import type { Request, Response, NextFunction } from "express";
import { captureManager } from "@capture/capture-manager";
import { logger } from "@utils/logger";
import { CAPTURE_RECORDED } from "@utils/traffic-recorder";

// 空字符串/缺省 → 默认 "rlv2"；显式 "0"/"false"/"off" → 关闭（用 ?? 而非 ||，空串不被覆盖）
const MODE = (process.env.REQRES_LOG ?? "rlv2").toLowerCase();

/** 路径是否命中记录模式（导出供测试） */
export function enabledFor(path: string): boolean {
  if (MODE === "0" || MODE === "false" || MODE === "off" || MODE === "") return false;
  if (MODE === "all") return true;
  if (MODE === "rlv2") return path.startsWith("/rlv2");
  // 其他值视为精确前缀匹配
  return path.startsWith(MODE.startsWith("/") ? MODE : `/${MODE}`);
}

export function reqresLogMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (!enabledFor(req.path)) {
    next();
    return;
  }
  // 共享标记：请求已被其他 HTTP 抓包中间件（traffic-recorder）记录 → 跳过，避免同一请求重复落库
  const marked = res as unknown as Record<string | symbol, unknown>;
  if (marked[CAPTURE_RECORDED]) {
    next();
    return;
  }
  marked[CAPTURE_RECORDED] = true;
  const startedAt = Date.now();
  // 非 JSON（multipart 等）请求体：capture 模式用 rawBody 捕获原始字节
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

  // 响应结束（finish 事件）后异步写入 captureManager，不阻塞响应；失败仅 logger.debug
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
        const query = req.originalUrl.includes("?")
          ? req.originalUrl.split("?")[1]
          : undefined;

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
            source: "private",
            note: "reqres-log",
            reqHeaders: req.headers as Record<string, unknown>,
            resHeaders: res.getHeaders() as Record<string, unknown>,
          },
          { req: reqBody, res: resBody },
        );
      } catch (e) {
        logger.debug("reqres-log", "记录失败:", (e as Error).message);
      }
    })();
  });

  next();
}
