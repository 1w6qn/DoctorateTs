/**
 * 调试请求/响应记录中间件
 *
 * 调试时记录每个 HTTP 请求的 request 与 response，落盘到 tmp/ 目录，
 * 目录格式与 test.ts（官服抓包代理）一致，便于与官服响应逐接口对比：
 *   tmp/{module}/{endpoint}/{timestamp}.json         ← response（完整响应体）
 *   tmp/request_{module}/{endpoint}/{timestamp}.json ← request（method/url/headers/body/query）
 *
 * 由 data/config.json 的 `debug.recordTraffic: true` 开启（默认关，避免正常运行时落盘噪音）。
 * 与 morgan 不同：morgan 只输出一行访问日志；本中间件保存完整请求/响应体用于协议对比。
 */
import { RequestHandler } from "express";
import { mkdir, writeFile } from "fs/promises";
import * as path from "path";

/** 记录目录根（与 test.ts 一致，相对进程 cwd） */
const RECORD_ROOT = "tmp";

/**
 * 生成记录目录路径
 *
 * @param req - 请求对象（用 originalUrl 提取 module/endpoint，兼容 host-router 前缀剥除）
 * @param prefix - 目录前缀（""=response、"request_"=request）
 * @returns 形如 tmp/account/syncData 或 tmp/request_account/syncData
 */
function recordDir(req: any, prefix: string): string {
  // originalUrl 去掉 query 后按 / 分段；host-router 已把 /auth/... 剥为 /u8/...，
  // 这里按最终路径分段（与官服抓包 tmp/ 目录一致——官服抓包也是无 /auth 前缀的目录）
  const url = req.originalUrl.split("?")[0];
  const segments = url.split("/").filter(Boolean);
  if (!segments.length) return path.join(RECORD_ROOT, prefix + "root");
  const [module, ...rest] = segments;
  const endpoint = rest.join("/") || module;
  return path.join(RECORD_ROOT, prefix + module, endpoint);
}

/**
 * 创建调试记录中间件
 *
 * 拦截 res.send/res.json，在响应发出后把 request/response 落盘。
 * 开启条件：config.debug?.recordTraffic === true。
 *
 * @param config - 应用配置（读取 debug.recordTraffic）
 * @returns Express 中间件
 */
export function createTrafficRecorder(config: { debug?: { recordTraffic?: boolean } }): RequestHandler {
  return (req, res, next) => {
    if (!config.debug?.recordTraffic) return next();

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const requestData = {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body ?? {},
      query: req.query,
      timestamp: new Date().toISOString(),
    };

    const originalSend = res.send.bind(res);
    const originalJson = res.json.bind(res);
    let body: any;

    res.json = ((data: any) => {
      body = data;
      return originalJson(data);
    }) as any;

    res.send = ((data: any) => {
      body = data;
      return originalSend(data);
    }) as any;

    // 响应结束（finish 事件）后异步落盘，不阻塞响应
    res.on("finish", () => {
      void (async () => {
        try {
          // Express res.send/res.json 在链上可能已把对象序列化为字符串，统一解析回对象再落盘
          let payload = body ?? null;
          if (typeof payload === "string") {
            try {
              payload = JSON.parse(payload);
            } catch {
              /* 非 JSON 文本（如 404 HTML）保持原样 */
            }
          }
          const reqDir = recordDir(req, "request_");
          const resDir = recordDir(req, "");
          await mkdir(reqDir, { recursive: true });
          await mkdir(resDir, { recursive: true });
          await writeFile(
            path.join(resDir, `${timestamp}.json`),
            JSON.stringify(payload, null, 2),
            "utf-8",
          );
          await writeFile(
            path.join(reqDir, `${timestamp}.json`),
            JSON.stringify(requestData, null, 2),
            "utf-8",
          );
        } catch (e) {
          // 记录失败不影响正常响应
          console.error("[traffic-recorder]", (e as Error).message);
        }
      })();
    });

    next();
  };
}
