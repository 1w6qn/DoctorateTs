import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import { router } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() };
}

async function call(player: ReturnType<typeof mockPlayerData>, url: string, body: Record<string, string>) {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  router({ method: "POST", url, body }, res, () => {});
  await new Promise((resolve) => setTimeout(resolve, 20));
  return res;
}

describe("bindNickName 路由参数映射", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("把客户端 nickName 映射为管理器契约的 nickname（修复绑定静默失效）", async () => {
    const player = mockPlayerData();
    await call(player, "/bindNickName", { nickName: "博士" });
    expect(player.status.bindNickName).toHaveBeenCalledWith({ nickname: "博士" });
  });
});
