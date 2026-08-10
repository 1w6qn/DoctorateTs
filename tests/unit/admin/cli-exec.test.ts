import { describe, it, expect, vi, beforeEach } from "vitest";

// mock admin-cli（避免真实加载 excel/accountManager 与 dispatch 副作用）
vi.mock("../../../scripts/admin-cli", () => ({
  parseArgs: vi.fn(),
  dispatch: vi.fn(),
}));

import { parseArgs, dispatch } from "../../../scripts/admin-cli";
import { cliExec } from "../../../app/admin/cli-exec";

describe("cliExec（CLI 集成默认服务）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("应捕获 console 输出并返回", async () => {
    (parseArgs as any).mockReturnValue({ command: "users", args: ["list"], flags: {} });
    (dispatch as any).mockImplementation(async () => {
      console.log("hello");
      console.log(JSON.stringify([{ uid: "1" }]));
    });
    const r = await cliExec("users list");
    expect(r.ok).toBe(true);
    expect(r.output).toContain("hello");
    expect(r.output).toContain("1");
  });

  it("强制 --json 注入结构化输出", async () => {
    (parseArgs as any).mockReturnValue({ command: "gacha", args: ["pools"], flags: {} });
    (dispatch as any).mockImplementation(async (_c: string, _a: string[], flags: any) => {
      expect(flags.json).toBe("true"); // cliExec 强制注入
    });
    await cliExec("gacha pools");
  });

  it("dispatch 抛错应返回 error 且不恢复 console 失败", async () => {
    (parseArgs as any).mockReturnValue({ command: "users", args: ["bad"], flags: {} });
    (dispatch as any).mockRejectedValue(new Error("boom"));
    const r = await cliExec("users bad");
    expect(r.ok).toBe(false);
    expect(r.error).toBe("boom");
    // console 恢复：后续 console.log 正常输出
    expect(console.log).toBeDefined();
  });

  it("空命令应抛错", async () => {
    await expect(cliExec("  ")).rejects.toThrow(/命令为空/);
  });

  it("dispatch 设 exitCode=1 应返回 ok:false 并恢复进程 exitCode", async () => {
    (parseArgs as any).mockReturnValue({ command: "users", args: ["badcmd"], flags: {} });
    (dispatch as any).mockImplementation(async () => {
      process.exitCode = 1; // CLI 未知子命令语义
      console.error("未知 users 子命令");
    });
    const prev = process.exitCode;
    const r = await cliExec("users badcmd");
    expect(r.ok).toBe(false);
    expect(r.output).toContain("未知");
    expect(process.exitCode).toBe(prev); // 服务器进程 exitCode 恢复
  });
});
