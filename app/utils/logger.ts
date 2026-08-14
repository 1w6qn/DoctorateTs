/**
 * 日志工具模块
 *
 * 统一日志输出格式，支持分级过滤与颜色标记。
 * 日志级别由环境变量 LOG_LEVEL 控制，默认 info：
 *   LOG_LEVEL=debug —— 输出所有日志
 *   LOG_LEVEL=info  —— 输出信息及以上（默认）
 *   LOG_LEVEL=warn  —— 仅输出警告与错误
 *   LOG_LEVEL=error —— 仅输出错误
 */

type LogLevel = "debug" | "info" | "warn" | "error";

const LEVELS: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

import * as fs from "fs";
import * as path from "path";

/**
 * 文件日志目录（LOG_DIR 环境变量可覆盖——测试注入临时目录用）。
 * 运行时求值：日志落盘目录不缓存，测试可动态设置后再调用。
 */
function logDir(): string {
  return process.env.LOG_DIR ?? "logs";
}

/** 当天日志文件名：server-YYYYMMDD.log（按天轮转） */
function logFilePath(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return path.join(
    logDir(),
    `server-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}.log`,
  );
}

/** 参数序列化：Error 优先 stack，对象 JSON 兜底 String()（与 console 显示保持一致） */
function formatArg(arg: unknown): string {
  if (arg instanceof Error) return arg.stack ?? arg.message;
  if (typeof arg === "string") return arg;
  try {
    const s = JSON.stringify(arg);
    return s === undefined ? String(arg) : s;
  } catch {
    return String(arg);
  }
}

/**
 * 待落盘缓冲（按行记录文件路径——跨天轮转边界安全）。
 * 每条日志不再立即同步写盘（appendFileSync 阻塞事件循环），
 * 而是 200ms 批量合并为一次 appendFile（A-1 性能优化）。
 */
const logBuffer: { file: string; line: string }[] = [];
let flushTimer: NodeJS.Timeout | null = null;
/** 批量 flush 间隔（毫秒） */
const FLUSH_INTERVAL_MS = 200;

/** 调度一次批量落盘（200ms 窗口内的多条日志合并为一次磁盘写） */
function scheduleFlush(): void {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushLogBuffer();
  }, FLUSH_INTERVAL_MS);
}

/** 同步批量落盘（按文件分组，每个文件一次 appendFile；定时器/显式 flush/进程退出调用） */
function flushLogBuffer(): void {
  if (logBuffer.length === 0) return;
  const pending = logBuffer.splice(0);
  const byFile = new Map<string, string[]>();
  for (const { file, line } of pending) {
    const lines = byFile.get(file) ?? [];
    lines.push(line);
    byFile.set(file, lines);
  }
  for (const [file, lines] of byFile) {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.appendFileSync(file, lines.join("\n") + "\n", "utf-8");
    } catch {
      /* 文件日志失败不影响服务器运行 */
    }
  }
}

// 进程退出时同步 flush 兜底（保留"已写日志不丢"语义——优雅退出路径；
// index.ts 的退出钩子在记完退出日志后也会显式 flush()）
process.on("exit", () => {
  flushLogBuffer();
});

/**
 * 显式 flush 待落盘日志（进程退出/测试断言前调用）
 */
export function flush(): void {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }
  flushLogBuffer();
}

/** 日志事件（实时订阅用——统一日志服务/SSE 尾随的数据源） */
export interface LogEvent {
  /** 落盘格式时间戳（YYYY-MM-DD HH:MM:SS） */
  ts: string;
  /** epoch 毫秒（过滤/排序用） */
  tsMs: number;
  level: LogLevel;
  tag: string;
  /** 参数拼接后的纯文本（与控制台/文件一致，去色码） */
  text: string;
}

const logListeners = new Set<(e: LogEvent) => void>();

/**
 * 订阅日志事件（通过级别过滤的实时日志）
 *
 * 统一日志服务（app/logs/log-service.ts）与 Dashboard「日志」Tab 的 SSE 尾随依赖此订阅。
 * 与文件/控制台输出并行，不影响既有行为。
 *
 * @param fn - 回调（每次 write 触发，参数为 LogEvent）
 * @returns 退订函数
 */
export function subscribeLog(fn: (e: LogEvent) => void): () => void {
  logListeners.add(fn);
  return () => {
    logListeners.delete(fn);
  };
}

function resolveLevel(): number {
  const env = process.env.LOG_LEVEL?.toLowerCase();
  if (env && env in LEVELS) return LEVELS[env as LogLevel];
  return LEVELS["info"];
}

const COLOR = {
  reset: "\x1b[0m",
  gray: "\x1b[90m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
};

const LEVEL_COLOR: Record<LogLevel, string> = {
  debug: COLOR.gray,
  info: COLOR.green,
  warn: COLOR.yellow,
  error: COLOR.red,
};

function timestamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function write(level: LogLevel, tag: string, args: unknown[]): void {
  // 运行时求值（非模块加载缓存）：支持 CLI --quiet 等启动后动态设置 LOG_LEVEL
  if (resolveLevel() > LEVELS[level]) return;
  const ts = timestamp();
  const text = args.map(formatArg).join(" ");
  const out: unknown[] = [
    `${COLOR.gray}[${ts}]${COLOR.reset}`,
    `${LEVEL_COLOR[level]}[${level.toUpperCase()}]${COLOR.reset}`,
    `${COLOR.cyan}[${tag}]${COLOR.reset}`,
    ...args,
  ];
  // 批量落盘（纯文本、去色码；200ms 窗口合并为一次磁盘写——A-1）——控制台输出保持原样
  logBuffer.push({
    file: logFilePath(),
    line: `${ts} [${level.toUpperCase()}] [${tag}] ${text}`,
  });
  scheduleFlush();
  // 实时订阅广播（统一日志服务 / Dashboard「日志」SSE 尾随）
  const event: LogEvent = { ts, tsMs: Date.now(), level, tag, text };
  for (const fn of logListeners) {
    try {
      fn(event);
    } catch {
      /* 订阅者异常不影响日志输出 */
    }
  }
  switch (level) {
    case "error":
      console.error(...out);
      break;
    case "warn":
      console.warn(...out);
      break;
    default:
      console.log(...out);
  }
}

/**
 * 统一日志记录器
 *
 * 所有方法第一个参数为模块标签，后续参数为日志内容。
 * 例：logger.info("BattleManager", "start", stageId);
 */
export const logger = {
  debug: (tag: string, ...args: unknown[]): void => write("debug", tag, args),
  info: (tag: string, ...args: unknown[]): void => write("info", tag, args),
  log: (tag: string, ...args: unknown[]): void => write("info", tag, args),
  warn: (tag: string, ...args: unknown[]): void => write("warn", tag, args),
  error: (tag: string, ...args: unknown[]): void => write("error", tag, args),
};

/**
 * 角色稀有度颜色映射
 *
 * 根据角色稀有度等级返回对应的颜色值，用于日志输出或 UI 显示。
 */
export const text2color = {
    "TIER_6": "#FF0000",  // 六星角色 - 红色
    "TIER_5": "#FFFF00",  // 五星角色 - 黄色
    "TIER_4": "#FF00FF",  // 四星角色 - 紫色
    "TIER_3": "#0000FF",  // 三星角色 - 蓝色
    "TIER_2": "#FFFFFF",  // 二星角色 - 白色
    "TIER_1": "#FFFFFF",  // 一星角色 - 白色
}