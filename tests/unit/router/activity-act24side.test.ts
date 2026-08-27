import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// act24side 合成抽奖读取 excel tYPE_ACT24SIDE.meldingGachaBoxGoodDataMap（首字母小写，真实数据键）
vi.mock("@excel/excel", () => ({
  default: {
    ActivityTable: {
      activity: {
        tYPE_ACT24SIDE: {
          act50side: {
            meldingGachaBoxGoodDataMap: {
              gachabox1: [
                { goodId: "gachabox1_1", itemId: "item_1", itemType: "MATERIAL", perCount: 1, totalCount: 2 },
                { goodId: "gachabox1_2", itemId: "item_2", itemType: "MATERIAL", perCount: 3, totalCount: 1 },
              ],
            },
          },
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import activityRouter from "../../../app/game/domain/activity";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("act24side（怪猎）路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" } as any,
      activity: {
        TYPE_ACT24SIDE: {
          act50side: {
            tool: { tool_trap: 2, tool_bomb: 1 },
            alchemy: { item: { act50melding_6: 200 }, gacha: {} },
          },
        },
      } as any,
    });
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
    activityRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /act24side/alchemy 应消耗素材并抽奖返还奖励", async () => {
    // act50melding_6 = 200 分 → 抽 2 次（gachabox1 共 3 件，至少抽中 2 件）
    await call("/act24side/alchemy", {
      activityId: "act50side",
      gachaBox: "gachabox1",
      items: { act50melding_6: 1 },
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.rewards.length).toBeGreaterThan(0);
    // 素材被消耗
    expect(player._playerdata.activity.TYPE_ACT24SIDE.act50side.alchemy.item.act50melding_6).toBe(199);
    // 抽中记录写入 gacha
    const gacha = player._playerdata.activity.TYPE_ACT24SIDE.act50side.alchemy.gacha.gachabox1;
    const totalDrawn = Object.values(gacha).reduce((a: number, b: any) => a + b, 0);
    expect(totalDrawn).toBe(2);
    // 奖励发放事件
    expect(player._trigger.emit).toHaveBeenCalledWith(
      "items:get",
      [sent.rewards]
    );
  });

  it("POST /act24side/alchemy 素材不足应整单不消耗", async () => {
    await call("/act24side/alchemy", {
      activityId: "act50side",
      gachaBox: "gachabox1",
      items: { act50melding_6: 999 },
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.rewards).toEqual([]);
    expect(
      player._playerdata.activity.TYPE_ACT24SIDE.act50side.alchemy.item.act50melding_6
    ).toBe(200); // 未被消耗
    expect(player._trigger.emit).not.toHaveBeenCalled();
  });

  it("POST /act24side/battleStart 应复用 battle.start", async () => {
    await call("/act24side/battleStart", {
      activityId: "act50side",
      stageId: "act50side_01",
      squad: { slots: [] },
      usePracticeTicket: 0,
      assistFriend: null,
    });
    expect(player.battle.start).toHaveBeenCalledWith(
      expect.objectContaining({ stageId: "act50side_01" })
    );
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 0, battleId: "b1" })
    );
  });

  it("POST /act24side/battleFinish 应复用 battle.finish 并返回空 melding 奖励", async () => {
    await call("/act24side/battleFinish", {
      activityId: "act50side",
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    expect(player.battle.finish).toHaveBeenCalledWith({
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        meldingRewards: [],
        firstMeldingRewards: [],
        mealMeldingRewards: [],
      })
    );
  });

  it("POST /act24side/eat 应设置 meal 状态", async () => {
    await call("/act24side/eat", { activityId: "act50side", meal: "meal_1" });
    expect(
      player._playerdata.activity.TYPE_ACT24SIDE.act50side.meal
    ).toEqual({ digested: 0, chance: 0, id: "meal_1" });
  });

  it("POST /act24side/setTool 应激活列表内工具并取消其余", async () => {
    await call("/act24side/setTool", { activityId: "act50side", tools: ["tool_trap"] });
    const tool = player._playerdata.activity.TYPE_ACT24SIDE.act50side.tool;
    expect(tool.tool_trap).toBe(2);
    expect(tool.tool_bomb).toBe(1);
  });

  it("POST /act24side/getHuntCollectRewards 应返回空奖励", async () => {
    await call("/act24side/getHuntCollectRewards", { activityId: "act50side" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ rewards: [] })
    );
  });
});
