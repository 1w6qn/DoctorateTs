import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import httpContext from "express-http-context2";
import { rootRouter } from "../../../app/game/service/activity";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("act25side（生息演算）根路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({ status: { uid: "1" } as any });
    player.battle = {
      start: vi.fn().mockResolvedValue({
        result: 0,
        battleId: "b1",
        apFailReturn: 0,
        isApProtect: 0,
        inApProtectPeriod: false,
        notifyPowerScoreNotEnoughIfFailed: false,
      }),
      finish: vi.fn().mockResolvedValue({
        apFailReturn: 0,
        expScale: 1,
        goldScale: 1,
        rewards: [],
        firstRewards: [],
        unlockStages: [],
        unusualRewards: [],
        additionalRewards: [],
        furnitureRewards: [],
        alert: [],
        suggestFriend: false,
        pryResult: [],
      }),
    };
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    rootRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /act25side/battleStart 应复用 battle.start", async () => {
    await call("/act25side/battleStart", {
      stageId: "act25side_01",
      squad: { slots: [] },
      usePracticeTicket: 0,
      assistFriend: null,
    });
    expect(player.battle.start).toHaveBeenCalledWith(
      expect.objectContaining({ stageId: "act25side_01" })
    );
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 0, battleId: "b1" })
    );
  });

  it("POST /act25side/battleFinish 应复用 battle.finish", async () => {
    await call("/act25side/battleFinish", {
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    expect(player.battle.finish).toHaveBeenCalledWith({
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ expScale: 1, goldScale: 1 })
    );
  });

  it("POST /act25side/dailyRefresh 应返回 tokenDelta 0", async () => {
    await call("/act25side/dailyRefresh", { actId: "act25side" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ tokenDelta: 0, reachRecvMax: false })
    );
  });

  it("POST /act25side/harvest 应返回空奖励", async () => {
    await call("/act25side/harvest", { actId: "act25side" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ items: [], additionalItems: [] })
    );
  });

  it("POST /act25side/investigate / finishInvestigation 应正常响应", async () => {
    await call("/act25side/investigate", { actId: "act25side", areaId: "area_1" });
    expect(res.send).toHaveBeenCalledWith({ playerDataDelta: {} });

    await call("/act25side/finishInvestigation", { actId: "act25side", areaId: "area_1" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ items: [] })
    );
  });
});
