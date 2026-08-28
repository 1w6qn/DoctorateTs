/**
 * CLI 集成到默认服务
 *
 * 服务器运行中通过 /admin/api/cli/exec 执行 CLI 命令：
 * 复用 scripts/admin-cli 的 dispatch（同一套命令集），捕获 console 输出返回给调用方。
 * 放在独立模块避免 AdminService ↔ admin-cli 循环依赖（router → cli-exec → admin-cli → AdminService）。
 */
import { parseArgs, dispatch } from "../../../scripts/admin-cli";

export interface CliExecResult {
  ok: boolean;
  output: string;
  error?: string;
}

/**
 * 执行一条 CLI 命令并捕获输出
 * @param commandLine - 命令行文本（如 "users list --json"、"gacha pools"）
 * @returns { ok, output, error? }——output 为捕获的 console 输出（支持 --json 的命令返回 JSON）
 */
export async function cliExec(commandLine: string): Promise<CliExecResult> {
  const argv = String(commandLine ?? "").trim().split(/\s+/);
  if (!argv.length || !argv[0]) {
    throw new Error("命令为空");
  }
  const { command, args, flags } = parseArgs(argv);
  // 强制 --json：支持的结构化命令走 JSON 输出（表格命令以 JSON 记录）
  if (flags.json !== "true") flags.json = "true";

  // 捕获 console 输出（dispatch 内部使用 console.log/error/table）
  const orig = { log: console.log, error: console.error, table: console.table };
  const out: string[] = [];
  const fmt = (x: unknown) => (typeof x === "string" ? x : JSON.stringify(x));
  console.log = (...a: unknown[]) => out.push(a.map(fmt).join(" "));
  console.error = (...a: unknown[]) => out.push(a.map(fmt).join(" "));
  console.table = (d: unknown) => out.push(JSON.stringify(d));
  // dispatch 内命令失败以 process.exitCode=1 表达（不抛错）；保存并恢复服务器进程 exitCode
  const prevExitCode = process.exitCode;
  process.exitCode = 0;

  try {
    await dispatch(command, args, flags);
    return { ok: process.exitCode !== 1, output: out.join("\n") };
  } catch (e) {
    return { ok: false, output: out.join("\n"), error: (e as Error).message };
  } finally {
    console.log = orig.log;
    console.error = orig.error;
    console.table = orig.table;
    process.exitCode = prevExitCode;
  }
}
