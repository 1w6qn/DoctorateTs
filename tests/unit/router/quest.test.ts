import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import questRouter from "../../../app/game/domain/router/quest";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  questRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("quest 路由（OBS 移植端点）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("battleContinue 应返回继续战斗 stub（对齐 OBS bp_quest）", async () => {
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      delta: { modified: {} },
    });
    const res = mockRes();
    await call({ method: "POST", url: "/battleContinue", body: { data: "x" } }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        result: 1,
        battleId: "00000000-0000-0000-0000-000000000000",
        apFailReturn: 0,
        modified: {},
      }),
    );
  });

  it("finishStoryStage 应委托 battle.finishStoryStage 并合并增量", async () => {
    const finishStoryStage = vi.fn().mockResolvedValue({ result: 0, rewards: [], unlockStages: [] });
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      battle: { finishStoryStage },
      delta: { modified: {} },
    });
    const res = mockRes();
    await call({ method: "POST", url: "/finishStoryStage", body: { stageId: "main_01-01" } }, res);
    expect(finishStoryStage).toHaveBeenCalledWith({ stageId: "main_01-01" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 0, rewards: [], modified: {} }),
    );
  });

  it("editStageSixStarTag 应写入 dungeon.sixStar.stages.tagSelected", async () => {
    const draft: any = { dungeon: { sixStar: { stages: { "main_01-01": {} } } } };
    const update = vi.fn(async (fn: (d: any) => void) => {
      fn(draft);
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    const res = mockRes();
    await call(
      { method: "POST", url: "/editStageSixStarTag", body: { stageId: "main_01-01", selected: [1, 2] } },
      res,
    );
    expect(update).toHaveBeenCalled();
    expect(draft.dungeon.sixStar.stages["main_01-01"].tagSelected).toEqual([1, 2]);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
