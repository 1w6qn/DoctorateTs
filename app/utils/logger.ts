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
 * 同步追加一行纯文本到当天日志文件（去 ANSI 色码）。
 * 失败静默——文件日志不能影响控制台输出与服务器运行（磁盘满/权限等只丢文件日志）。
 * 用 appendFileSync 保证进程被杀死/崩溃前已写入的日志不丢失（异步流缓冲会丢尾部）。
 */
function appendFileLog(line: string): void {
  try {
    fs.mkdirSync(logDir(), { recursive: true });
    fs.appendFileSync(logFilePath(), line + "\n", "utf-8");
  } catch {
    /* 文件日志失败不影响服务器运行 */
  }
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
  const out: unknown[] = [
    `${COLOR.gray}[${ts}]${COLOR.reset}`,
    `${LEVEL_COLOR[level]}[${level.toUpperCase()}]${COLOR.reset}`,
    `${COLOR.cyan}[${tag}]${COLOR.reset}`,
    ...args,
  ];
  // 同步落盘（纯文本、去色码）——控制台输出保持原样
  appendFileLog(
    `${ts} [${level.toUpperCase()}] [${tag}] ${args.map(formatArg).join(" ")}`,
  );
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