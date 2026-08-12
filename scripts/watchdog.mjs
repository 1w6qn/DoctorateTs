/**
 * 服务器看门狗：包装 `tsx index.ts -s` 子进程，防"静默退出无提示"
 *
 * - 子进程 stdout/stderr 直通本窗口（日志照常显示）
 * - 事件日记写 logs/watchdog-YYYYMMDD.log（启动/退出时间戳 + 退出码 + 运行时长）
 *   ——服务器进程被外部杀死/崩溃时，只有父进程能记录退出码，进程内无法留痕
 * - 异常退出（code≠0/130）2s 后自动重启；60s 内连续退出 5 次则停止（防循环崩溃刷屏）
 * - Ctrl+C / code=130（SIGINT）视为手动退出，不重启
 * - `--once`：单次运行不重启
 *
 * 用法：node scripts/watchdog.mjs [--once] [-- 透传给服务器的参数，如 --port 8444]
 *       npm run watch -- --port 8444
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");
const LOG_DIR = path.join(ROOT, "logs");
const TSCLI = path.join(ROOT, "node_modules", "tsx", "dist", "cli.mjs");

const argv = process.argv.slice(2);
const once = argv.includes("--once");
const serverArgs = argv.filter((a) => a !== "--once");

const MAX_CONSECUTIVE_FAILS = 5;
const FAIL_WINDOW_MS = 60_000;
const RESTART_DELAY_MS = 2_000;

let shuttingDown = false;
let fails = 0;
let firstFailTs = 0;

function timestamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function journalFile() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return path.join(LOG_DIR, `watchdog-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}.log`);
}

function journal(line) {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.appendFileSync(journalFile(), `${timestamp()} ${line}\n`, "utf-8");
  } catch {
    /* 日记失败不影响看门狗运行 */
  }
}

function log(line) {
  console.log(`[watchdog] ${line}`);
  journal(`[watchdog] ${line}`);
}

function run() {
  if (shuttingDown) return;
  const child = spawn(process.execPath, [TSCLI, "index.ts", "-s", ...serverArgs], {
    cwd: ROOT,
    stdio: "inherit",
    env: process.env,
  });
  const startedAt = Date.now();
  log(`启动服务器子进程 pid=${child.pid}（tsx index.ts -s ${serverArgs.join(" ")}）`);
  currentChild = child;

  child.on("exit", (code, signal) => {
    const uptime = Math.round((Date.now() - startedAt) / 1000);
    const reason = signal !== null ? `signal=${signal}` : `code=${code}`;
    log(`服务器进程退出：${reason}，运行 ${uptime}s`);
    if (currentChild === child) currentChild = null;
    if (shuttingDown) return;
    if (once || code === 0 || code === 130) {
      log("本次运行结束，不再重启（--once 或手动退出）");
      process.exit(0);
    }
    // 快速连续失败保护：窗口期内计数，超窗清零
    const now = Date.now();
    if (now - firstFailTs > FAIL_WINDOW_MS) {
      fails = 0;
      firstFailTs = now;
    }
    fails++;
    if (fails >= MAX_CONSECUTIVE_FAILS) {
      log(`60s 内连续退出 ${fails} 次，停止重启。排查日志：logs/server-*.log 与 process report（logs/report-*.json）`);
      process.exit(1);
    }
    log(`${RESTART_DELAY_MS / 1000}s 后自动重启（第 ${fails}/${MAX_CONSECUTIVE_FAILS} 次）...`);
    setTimeout(run, RESTART_DELAY_MS);
  });
}

/** 当前服务器子进程（用于显式终止——控制台关闭时子进程可能收不到关闭事件，会变孤儿进程） */
let currentChild = null;

/**
 * 看门狗退出前显式终止服务器子进程
 *
 * 修复"服务器未与命令行一同终止"：Windows 关闭控制台窗口时，子进程不保证收到
 * SIGINT/SIGHUP（Node 控制台关闭事件传播不稳定），若只依赖"继承控制台同时收到信号"
 * 的假设，服务器会以孤儿进程继续监听端口。此处显式 child.kill() 兜底。
 * @param code 看门狗退出码
 */
function shutdown(code) {
  shuttingDown = true;
  if (currentChild && !currentChild.killed) {
    log(`显式终止服务器子进程 pid=${currentChild.pid}`);
    try {
      currentChild.kill();
    } catch {
      /* 进程已退出则忽略 */
    }
  }
  process.exit(code);
}

// Ctrl+C / 关闭控制台 / 终止信号：显式终止服务器子进程后看门狗退出
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => {
    log(`收到 ${sig}，看门狗退出并终止服务器子进程`);
    shutdown(0);
  });
}

if (!fs.existsSync(TSCLI)) {
  console.error("[watchdog] 找不到 tsx CLI：" + TSCLI);
  console.error("[watchdog] 请先 npm install");
  process.exit(1);
}

log(`看门狗启动（node ${process.version}，重启策略：异常退出 ${RESTART_DELAY_MS / 1000}s 后重启，60s 内 ${MAX_CONSECUTIVE_FAILS} 次失败停止）`);
run();
