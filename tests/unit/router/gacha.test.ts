import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));
vi.mock("@excel/excel", () => ({
  default: {
    GachaTable: {
      gachaPoolClient: [
        { gachaPoolId: "p_single_1", gachaRuleType: "SINGLE" },
        { gachaPoolId: "p_limited_1", gachaRuleType: "LIMITED" },
      ],
    },
  },
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
  });

  it("cancelNormalGacha 应调用 recruit.cancel 并返回增量", async () => {
    const cancel = vi.fn().mockResolvedValue(undefined);
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      recruit: { cancel },
      delta: { modified: {} },
    });
    const res = mockRes();
    await call({ method: "POST", url: "/cancelNormalGacha", body: { tagList: [1] } }, res);
    expect(cancel).toHaveBeenCalledWith({ tagList: [1] });
    // CS CancelNormalGachaResponse 要求 result（2026-08-09 修复）
    expect(res.send).toHaveBeenCalledWith({ result: 0, modified: {} });
  });

  it("旧拼写 /cancleNormalGacha 不应再命中", async () => {
    const cancel = vi.fn().mockResolvedValue(undefined);
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      recruit: { cancel },
      delta: { modified: {} },
    });
    const res = mockRes();
    await call({ method: "POST", url: "/cancleNormalGacha", body: {} }, res);
    expect(res.send).not.toHaveBeenCalled();
  });

  it("choosePoolUp 应写入 gacha[gachaType][poolId].upChar（对齐 OBS bp_gacha）", async () => {
    const draft: any = { gacha: { single: { p_single_1: {} } } };
    const update = vi.fn(async (fn: (d: any) => void) => {
      fn(draft);
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    const res = mockRes();
    await call(
      { method: "POST", url: "/choosePoolUp", body: { poolId: "p_single_1", chooseChar: "char_1001" } },
      res,
    );
    expect(draft.gacha.single.p_single_1.upChar).toBe("char_1001");
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ result: 0, modified: {} }));
  });

  it("getFreeChar 应返回 result 0（OBS 为空操作）", async () => {
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      delta: { modified: {} },
    });
    const res = mockRes();
    await call({ method: "POST", url: "/getFreeChar", body: { poolId: "p_single_1" } }, res);
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ result: 0, modified: {} }));
  });
});
