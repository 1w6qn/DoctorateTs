import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import retroRouter from "../../../app/game/router/retro";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  retroRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("retro 路由（OBS 移植端点）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      delta: { modified: {} },
    });
  });

  it("typeAct20side/competitionStart 应返回 result 0 与 battleId（对齐 OBS misc_bp）", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/retro/typeAct20side/competitionStart", body: {} }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        result: 0,
        battleId: "00000000-0000-0000-0000-000000000000",
        modified: {},
      }),
    );
  });

  it("typeAct20side/competitionFinish 应返回评价结构（对齐 OBS misc_bp）", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/retro/typeAct20side/competitionFinish", body: { data: "x" } }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        performance: 0,
        expression: 0,
        operation: 0,
        total: 0,
        level: "SS",
        isNew: false,
        modified: {},
      }),
    );
  });
});
