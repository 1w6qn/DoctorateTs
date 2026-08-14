/**
 * 服务器内嵌命令行 REPL
 *
 * 服务器运行的同时，在同一终端使用管理 CLI 命令（日志与命令行共存）：
 * - stdin 为 TTY 时启用（`pnpm start` 交互终端）；非 TTY（日志重定向/守护进程）自动跳过
 * - 命令复用 cliExec（dispatch 同一命令集 + 输出捕获 + exitCode 恢复，不污染服务器进程）
 * - 输入 exit/quit 退出命令行，服务器继续运行
 */
import * as readline from "readline";
import { cliExec } from "./cli-exec";
import { printHelp } from "../../scripts/admin-cli";
import { logger } from "@utils/logger";

/** 启动服务器内嵌命令行 REPL（非 TTY 直接返回） */
export function startServerRepl(): void {
  if (!process.stdin.isTTY) return;
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "cli> ",
    terminal: true,
  });
  rl.prompt();
  rl.on("line", async (line) => {
    const t = line.trim();
    if (!t) {
      rl.prompt();
      return;
    }
    if (t === "exit" || t === "quit") {
      console.log("[cli] 已退出命令行（服务器继续运行）");
      rl.close();
      return;
    }
    if (t === "help") {
      // 完整命令帮助（复用 admin-cli printHelp）
      printHelp();
      console.log("[cli] exit 退出命令行（服务器继续运行）");
      rl.prompt();
      return;
    }
    const result = await cliExec(t);
    if (result.output) console.log(result.output);
    if (!result.ok) console.log("[cli] 命令失败: " + (result.error || ""));
    rl.prompt();
  });
  // stdin 关闭（终端断开/重定向结束）留痕——服务器继续运行
  rl.on("close", () => {
    logger.warn("server-repl", "stdin 已关闭（终端断开？），命令行不可用，服务器继续运行");
  });
}
