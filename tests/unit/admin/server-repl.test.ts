import { describe, it, expect, vi, afterEach } from "vitest";

// mock cli-exec 与 admin-cli，避免加载完整 AdminService 依赖链
vi.mock("@ops/admin/cli-exec", () => ({ cliExec: vi.fn() }));
vi.mock("../../../scripts/admin-cli", () => ({
  parseArgs: vi.fn(),
  dispatch: vi.fn(),
  printHelp: vi.fn(),
}));
// mock readline 模块（ESM 命名空间不可 spy，用模块级 mock）
const rlMock = vi.hoisted(() => ({
  createInterface: vi.fn(),
}));
vi.mock("readline", () => rlMock);

import { startServerRepl } from "@ops/admin/server-repl";
import { printHelp } from "../../../scripts/admin-cli";

describe("startServerRepl（服务器内嵌命令行）", () => {
  const origTTY = process.stdin.isTTY;

  afterEach(() => {
    process.stdin.isTTY = origTTY;
    rlMock.createInterface.mockReset();
  });

  it("非 TTY 时不应创建 readline（日志重定向/守护进程安全）", () => {
    process.stdin.isTTY = false;
    startServerRepl();
    expect(rlMock.createInterface).not.toHaveBeenCalled();
  });

  it("TTY 时创建 readline 并绑定 line 处理", () => {
    process.stdin.isTTY = true;
    const rl = {
      prompt: vi.fn(),
      close: vi.fn(),
      on: vi.fn(),
    };
    rlMock.createInterface.mockReturnValue(rl);
    startServerRepl();
    expect(rlMock.createInterface).toHaveBeenCalled();
    expect(rl.prompt).toHaveBeenCalled();
    expect(rl.on).toHaveBeenCalledWith("line", expect.any(Function));
  });

  it("line handler 收到 help 应打印完整命令帮助", async () => {
    process.stdin.isTTY = true;
    const rl = { prompt: vi.fn(), close: vi.fn(), on: vi.fn() };
    rlMock.createInterface.mockReturnValue(rl);
    startServerRepl();
    // 取出 line handler 并模拟输入 help
    const lineHandler = rl.on.mock.calls.find((c) => c[0] === "line")![1];
    await lineHandler("help");
    expect(printHelp).toHaveBeenCalled();
    expect(rl.prompt).toHaveBeenCalled();
  });
});
