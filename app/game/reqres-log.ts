/**
 * 临时请求/响应记录中间件（调试用）
 *
 * 用途：排查客户端与服务端交互问题（如 rlv2 开局/推进异常）时，逐请求记录
 * req body 与 res body，便于复现与分析。属临时调试设施，生产环境建议关闭。
 *
 * 开关（环境变量 REQRES_LOG，默认 "rlv2"）：
 *   - "all"   记录所有请求
 *   - "rlv2"  仅记录 /rlv2/ 路径（默认，当前调试主题）
 *   - "0"/空  关闭
 *
 * 输出：logs/reqres-YYYYMM-DD.log（独立文件，避免污染 server log）；
 * 每行格式：时间 | 方法 | 路径 | REQ/RES | 状态码 | 耗时 | 内容
 * 响应体与请求体超过 maxLen 字符时截断（含截断标记）。
 */
import { appendFileSync } from "fs";
import { join } from "path";
import type { Request, Response, NextFunction } from "express";

// 空字符串/缺省 → 默认 "rlv2"；显式 "0"/"false"/"off" → 关闭（用 ?? 而非 ||，空串不被覆盖）
const MODE = (process.env.REQRES_LOG ?? "rlv2").toLowerCase();
/** 请求/响应体最大记录长度（超长截断） */
const MAX_LEN = 4000;

/** 路径是否命中记录模式（导出供测试） */
export function enabledFor(path: string): boolean {
  if (MODE === "0" || MODE === "false" || MODE === "off" || MODE === "") return false;
  if (MODE === "all") return true;
  if (MODE === "rlv2") return path.startsWith("/rlv2");
  // 其他值视为精确前缀匹配
  return path.startsWith(MODE.startsWith("/") ? MODE : `/${MODE}`);
}

/** 请求/响应体安全序列化（截断，导出供测试） */
export function safeJson(body: unknown): string {
  if (body === undefined || body === null) return String(body);
  if (typeof body === "string") {
    return body.length > MAX_LEN ? `${body.slice(0, MAX_LEN)}…[截断 ${body.length - MAX_LEN} 字符]` : body;
  }
  try {
    const s = JSON.stringify(body);
    if (!s) return "";
    return s.length > MAX_LEN ? `${s.slice(0, MAX_LEN)}…[截断 ${s.length - MAX_LEN} 字符]` : s;
  } catch {
    return `[不可序列化: ${typeof body}]`;
  }
}

function appendLine(line: string): void {
  try {
    const d = new Date();
    const file = join(
      __dirname,
      "..",
      "..",
      "logs",
      `reqres-${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}.log`,
    );
    appendFileSync(file, `${line}\n`, "utf8");
  } catch (e) {
    // 记录失败不阻断业务
  }
}

function ts(): string {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}.${String(d.getMilliseconds()).padStart(3, "0")}`;
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
  const start = Date.now();
  const base = `${ts()} | ${req.method} | ${req.originalUrl}`;
  appendLine(`${base} | REQ | ${safeJson(req.body)}`);

  const origSend = res.send.bind(res);
  res.send = ((body: unknown) => {
    const elapsed = Date.now() - start;
    appendLine(`${base} | RES | ${res.statusCode} | ${elapsed}ms | ${safeJson(body)}`);
    return origSend(body);
  }) as Response["send"];

  // 请求异常终止时补记（避免丢失仅有 REQ 的行）
  res.on("close", () => {
    if (!res.writableEnded) {
      appendLine(`${base} | RES | ${res.statusCode} | 中断(close)`);
    }
  });

  next();
}
