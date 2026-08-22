/**
 * 响应骨架校验中间件（全局，可开关）
 *
 * 在响应真正发出前对 res.send/res.json 的响应对象做**骨架级**校验：
 * 仅验证顶层结构（如 playerDataDelta.modified/deleted 为对象），不递归下钻深对象，
 * 避免对超大响应（战斗战报、user 全量等）造成显著的深遍历开销。
 *
 * 设计要点：
 * - 单点挂载（app.use 一次），复用 reqres-log 的 res.send/res.json 包装模式，
 *   无论 handler 用 send 还是 json、提前 return 的响应都能被捕获。
 * - 校验失败仅 logger.warn 告警，**不阻断响应**（避免误伤已对齐的客户端协议）。
 * - 开关节环境变量 RESP_SCHEMA：缺省开启；设 "0"/"false" 关闭。
 * - 仅对对象/数组响应校验；字符串响应（如 syncData 的紧凑 JSON）跳过解析，零开销。
 *
 * 开销回退策略：若实测骨架校验耗时过高，只需关闭 RESP_SCHEMA 即可整体回退，
 * 无需回改任何路由。
 */
import type { Request, Response, NextFunction } from "express";
import { z } from "zod";
import { logger } from "@utils/logger";

/** 响应校验开关（环境变量 RESP_SCHEMA，默认开启；设 "0"/"false" 关闭） */
const RESP_SCHEMA_ENABLED = (() => {
  const raw = process.env.RESP_SCHEMA ?? "1";
  const v = raw.toLowerCase();
  return v !== "0" && v !== "false" && v !== "off" && v !== "";
})();

/**
 * 响应骨架 schema（宽松）
 *
 * 仅校验「规范化游戏响应」的通用骨架：
 * - 顶层可为任意业务字段（passthrough），不限制未知键；
 * - 若带 playerDataDelta，则其 modified/deleted 必须是对象（客户端合并增量依赖）。
 * 该骨架不深检业务载荷（battleData/squad/user 全量等），保证开销恒为 O(顶层键数)。
 */
const responseSkeletonSchema = z
  .object({
    playerDataDelta: z
      .object({
        modified: z.record(z.string(), z.unknown()).optional(),
        deleted: z.record(z.string(), z.unknown()).optional(),
      })
      .partial()
      .optional(),
  })
  .passthrough();

/** 是否为可校验的纯对象（排除 null/数组/Buffer/字符串） */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !Buffer.isBuffer(v);
}

/**
 * 对响应体做骨架校验并记录告警（不抛出、不阻断）
 * @param data - 待校验的响应体（对象）
 */
function checkResponse(data: Record<string, unknown>): void {
  try {
    const result = responseSkeletonSchema.safeParse(data);
    if (!result.success) {
      const first = result.error.issues[0];
      const where = first.path.length > 0 ? ` at "${first.path.join(".")}"` : "";
      logger.warn("resp-schema", `响应骨架校验未通过：${first.message}${where}`);
    }
  } catch (e) {
    // 解析异常（极不可能）不影响响应发出
    logger.debug("resp-schema", "校验异常:", (e as Error)?.message);
  }
}

/**
 * 全局响应骨架校验中间件
 *
 * 包装 res.send/res.json 截获响应对象做骨架校验，原样透传不改变响应内容。
 * 校验失败仅告警；开关关闭时直接透传，零额外开销。
 * @param req - 请求对象（本中间件不读取）
 * @param res - 响应对象（对其 send/json 做包装）
 * @param next - 放行下一中间件
 */
export function responseSchemaMiddleware(
  _req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (!RESP_SCHEMA_ENABLED) {
    next();
    return;
  }
  const originalSend = res.send.bind(res);
  const originalJson = res.json.bind(res);

  // 包装 res.json：对象响应做骨架校验后透传
  res.json = ((data: unknown) => {
    if (isPlainObject(data)) {
      checkResponse(data as Record<string, unknown>);
    }
    return originalJson(data);
  }) as typeof res.json;

  // 包装 res.send：对象响应做骨架校验后透传；字符串（如 syncData 紧凑 JSON）跳过
  res.send = ((data: unknown) => {
    if (isPlainObject(data)) {
      checkResponse(data as Record<string, unknown>);
    }
    return originalSend(data);
  }) as typeof res.send;

  next();
}

/** 导出开关值（供测试断言开启状态） */
export function responseSchemaEnabled(): boolean {
  return RESP_SCHEMA_ENABLED;
}