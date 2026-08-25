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
 * 单一事实源：log-service 等日志消费方一律 import 本函数，勿再复制。
 */
export function logDir(): string {
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

/**
 * 单个日志文件大小上限（字节），超过即轮转归档，防止单文件无界膨胀。
 * 环境变量 LOG_MAX_BYTES 可覆盖（正整数）；缺省 64MB。
 */
function resolveMaxBytes(): number {
  const raw = process.env.LOG_MAX_BYTES;
  if (raw && /^\d+$/.test(raw)) return Number(raw);
  return 64 * 1024 * 1024;
}

/**
 * 日志保留天数，超过该天数的 server- 与 watchdog- 前缀日志文件会被自动清理，
 * 防止磁盘无限增长。环境变量 LOG_RETAIN_DAYS 可覆盖；0 表示不清理旧日志。
 */
function resolveRetainDays(): number {
  const raw = process.env.LOG_RETAIN_DAYS;
  if (raw && /^\d+$/.test(raw)) return Number(raw);
  return 7;
}

/** 同一日期最多保留的归档文件数（超出删除最旧归档） */
const MAX_ARCHIVES = 5;

/**
 * 删除早于保留天数的历史日志文件（server- 与 watchdog- 前缀），防止 logs/ 长期累积膨胀。
 * 同步实现、随每次批量落盘调用；任一文件删除失败不影响其余。
 */
function pruneOutdatedLogs(): void {
  const retainDays = resolveRetainDays();
  if (retainDays <= 0) return;
  const dir = logDir();
  if (!fs.existsSync(dir)) return;
  const cutoffMs = Date.now() - retainDays * 24 * 60 * 60 * 1000;
  for (const name of fs.readdirSync(dir)) {
    const m = /^(server|watchdog)-(\d{8})/.exec(name);
    if (!m) continue;
    const y = Number(m[2].slice(0, 4));
    const mo = Number(m[2].slice(4, 6)) - 1;
    const d = Number(m[2].slice(6, 8));
    const dateMs = new Date(y, mo, d).getTime();
    if (!Number.isNaN(dateMs) && dateMs < cutoffMs) {
      try {
        fs.rmSync(path.join(dir, name), { force: true });
      } catch {
        /* 清理失败不影响运行 */
      }
    }
  }
}

/**
 * 单文件超上限后的归档轮转：当前文件 → .1，旧归档依次后移，删除超出 MAX_ARCHIVES 的归档。
 * @param basePath - 日志文件路径（不含归档后缀）
 */
function rotateLogFile(basePath: string): void {
  if (!fs.existsSync(basePath)) return;
  // 删除最老的归档，为后移腾位置
  for (let i = MAX_ARCHIVES; i >= 1; i--) {
    const f = `${basePath}.${i}`;
    if (fs.existsSync(f)) {
      try {
        fs.rmSync(f, { force: true });
      } catch {
        /* 忽略单文件删除失败 */
      }
    }
  }
  // 旧归档依次后移（.MAX-1 → .MAX，…，.1 → .2）
  for (let i = MAX_ARCHIVES - 1; i >= 1; i--) {
    const src = `${basePath}.${i}`;
    const dst = `${basePath}.${i + 1}`;
    if (fs.existsSync(src)) {
      try {
        fs.renameSync(src, dst);
      } catch {
        /* 忽略单文件移动失败 */
      }
    }
  }
  try {
    fs.renameSync(basePath, `${basePath}.1`);
  } catch {
    /* 轮转失败不阻断写入新文件 */
  }
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
  // 每次落盘先清理过期日志：短时间日志爆炸时也能及时回收磁盘，避免累积膨胀
  pruneOutdatedLogs();
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
      // 单文件超上限时先归档轮转，防止单个日志文件无界膨胀
      let size = 0;
      try {
        size = fs.statSync(file).size;
      } catch {
        size = 0;
      }
      if (size >= resolveMaxBytes()) rotateLogFile(file);
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