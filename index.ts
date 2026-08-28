/**
 * DoctorateTs 应用入口
 *
 * 仅保留进程级兜底与 CLI 调用；服务器启动编排在 app/server.ts。
 */
import * as path from "path";
import { logger, flush as flushLogs } from "./app/core/utils/logger";
import { main } from "./app/server";

// 全局错误兜底（修复：未处理 Promise 拒绝/异常会导致 Node 24 进程直接终止——
// 记录错误栈便于定位，并保持服务器存活）
process.on("unhandledRejection", (reason) => {
  logger.error(
    "process",
    `unhandledRejection: ${
      reason instanceof Error ? reason.stack ?? reason.message : String(reason)
    }`,
  );
});
process.on("uncaughtException", (err) => {
  logger.error("process", `uncaughtException: ${err.stack ?? err.message}`);
});

// 进程级诊断（防"静默退出无提示"）：
// 1) V8 致命错误（OOM/原生崩溃）落盘 report 文件——stderr 可能随终端/重定向丢失。
//    文件名启动时计算（<date>/<pid> 占位符在当前 Node 构建不可用，errno 22）
const now = new Date();
const pad = (n: number) => String(n).padStart(2, "0");
process.report.reportOnFatalError = true;
process.report.directory = path.resolve(__dirname, "logs");
process.report.filename = `report-${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}.json`;

// 2) 信号退出留痕（Ctrl+C 行为不变，仅先记录再按约定码退出）
// SIGHUP = 终端关闭（POSIX）；Windows 控制台关闭由看门狗显式终止子进程兜底
for (const sig of ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] as const) {
  process.on(sig, () => {
    logger.warn("process", `收到 ${sig}，进程退出`);
    process.exit(sig === "SIGTERM" ? 143 : 130);
  });
}

// 3) 任何退出都记录退出码（看门狗依据 code≠0/130 判断是否自动重启）
process.on("exit", (code) => {
  // 退出日志入缓冲后显式 flush（logger 批量落盘——确保退出码与最后日志都写入文件）
  logger.info("process", `进程退出: code=${code}`);
  flushLogs();
});

void main();
