import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import gachaRouter from "../../../app/game/router/gacha";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  gachaRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("gacha 路由", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      recruit: {
        cancel: vi.fn().mockResolvedValue(undefined),
      },
      delta: { modified: {} },
    });
  });

  it("cancelNormalGacha 应调用 recruit.cancel 并返回增量", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/cancelNormalGacha", body: { tagList: [1] } }, res);
    const player = vi.mocked(httpContext.get)() as any;
    expect(player.recruit.cancel).toHaveBeenCalledWith({ tagList: [1] });
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("旧拼写 /cancleNormalGacha 不应再命中（避免客户端 404 后命中错误路由）", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/cancleNormalGacha", body: {} }, res);
    expect(res.send).not.toHaveBeenCalled();
  });
});
