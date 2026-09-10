import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// act24side 合成抽奖读取 excel tYPE_ACT24SIDE.meldingGachaBoxGoodDataMap（首字母小写，真实数据键）
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    ActivityTable: {
      activity: {
        tYPE_ACT24SIDE: {
          act24side: {
            // 修复（2026-09-09）：真实 excel 形状 —— 素材分值表 / 炼金箱消耗 / 掉落 / 用餐
            meldingDict: {
              m1: { meldingId: "act24side_melding_1", meldingPrice: 2 },
              m6: { meldingId: "act24side_melding_6", meldingPrice: 200 },
            },
            meldingGachaBoxDataList: {
              gachabox1: {
                gachaBoxId: "gachabox1",
                gachaCost: 100,
                gachaTimesLimit: 10,
              },
              gachabox2: {
                gachaBoxId: "gachabox2",
                gachaCost: 40,
                gachaTimesLimit: 10,
              },
            },
            meldingGachaBoxGoodDataMap: {
              gachabox1: [
                { goodId: "gachabox1_1", itemId: "item_1", itemType: "MATERIAL", perCount: 1, totalCount: 2 },
                { goodId: "gachabox1_2", itemId: "item_2", itemType: "MATERIAL", perCount: 3, totalCount: 1 },
              ],
              gachabox2: [
                {
                  goodId: "gachabox2_1",
                  itemId: "item_3",
                  itemType: "MATERIAL",
                  perCount: 1,
                  totalCount: 0,
                  gachaType: "UNLIMITED",
                },
              ],
            },
            meldingDropDict: {
              act24side_01: {
                displayDetailRewards: [
                  {
                    occPercent: 0,
                    type: "ACTIVITY_ITEM",
                    id: "act24side_melding_1",
                    dropType: "COMPLETE",
                  },
                ],
              },
            },
            mealDataList: {
              meal_1: {
                mealId: "meal_1",
                mealCost: 200,
                mealRewardAP: 20,
                mealRewardItemInfo: {
                  id: "act24side_melding_1",
                  count: 30,
                  type: "ACTIVITY_ITEM",
                },
              },
            },
            constData: { mealDayTimesLimit: 1 },
          },
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import activityRouter from "@game/modules/activities";
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
      status: { uid: "1", gold: 1000, ap: 50, maxAp: 135 } as any,
      dungeon: { stages: { act24side_01: { state: 0 } } } as any,
      activity: {
        TYPE_ACT24SIDE: {
          act50side: {
            tool: { tool_trap: 2, tool_bomb: 1 },
            alchemy: { price: 0, item: { act24side_melding_6: 200 }, gacha: {} },
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
      getActiveBattle: vi.fn(() => ({
        battleId: "b1",
        stageId: "act24side_01",
        startTs: 0,
        status: "in_progress",
      })),
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

  it("POST /act24side/alchemy 应按 meldingDict 分值抽奖（修复：原 id 写错恒 0 分）", async () => {
    // act24side_melding_6 = 200 分 → 重构箱（gachaCost=100）可抽 2 次
    await call("/act24side/alchemy", {
      activityId: "act50side",
      gachaBox: "gachabox1",
      items: { act24side_melding_6: 1 },
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.rewards.length).toBeGreaterThan(0);
    // 素材被消耗
    expect(
      player._playerdata.activity.TYPE_ACT24SIDE.act50side.alchemy.item
        .act24side_melding_6,
    ).toBe(199);
    // 抽中记录写入 gacha（200 分 / 100 = 2 次）
    const gacha =
      player._playerdata.activity.TYPE_ACT24SIDE.act50side.alchemy.gacha
        .gachabox1;
    const totalDrawn = Object.values(gacha).reduce(
      (a: number, b: any) => a + b,
      0,
    );
    expect(totalDrawn).toBe(2);
    // 奖励发放事件
    expect(player._trigger.emit).toHaveBeenCalledWith(
      "items:get",
      [sent.rewards],
    );
  });

  it("POST /act24side/alchemy 转换箱按 gachaCost=40 计算且 UNLIMITED 池可抽", async () => {
    // act24side_melding_1 = 2 分 × 30 = 60 分 → 40 分/次 → 1 次，余值 20 留存
    const player2 = player;
    player2._playerdata.activity.TYPE_ACT24SIDE.act50side.alchemy.item = {
      act24side_melding_1: 30,
    };
    await call("/act24side/alchemy", {
      activityId: "act50side",
      gachaBox: "gachabox2",
      items: { act24side_melding_1: 30 },
    });
    const alchemy =
      player2._playerdata.activity.TYPE_ACT24SIDE.act50side.alchemy;
    expect(alchemy.price).toBe(20); // 余值留存（不丢弃）
    const sent = res.send.mock.calls[0][0];
    expect(sent.rewards).toEqual([
      { id: "item_3", type: "MATERIAL", count: 1 },
    ]);
  });

  it("POST /act24side/alchemy 素材不足应整单不消耗", async () => {
    await call("/act24side/alchemy", {
      activityId: "act50side",
      gachaBox: "gachabox1",
      items: { act24side_melding_6: 999 },
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.rewards).toEqual([]);
    expect(
      player._playerdata.activity.TYPE_ACT24SIDE.act50side.alchemy.item
        .act24side_melding_6,
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

  it("POST /act24side/battleFinish 应复用 battle.finish 并按 meldingDropDict 发素材", async () => {
    await call("/act24side/battleFinish", {
      activityId: "act50side",
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    expect(player.battle.finish).toHaveBeenCalledWith({
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    // 修复（2026-09-09）：原实现三字段恒空数组；现按 meldingDropDict 掉落，首通再记一份
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        meldingRewards: [
          { id: "act24side_melding_1", type: "ACTIVITY_ITEM", count: 1 },
        ],
        firstMeldingRewards: [
          { id: "act24side_melding_1", type: "ACTIVITY_ITEM", count: 1 },
        ],
        mealMeldingRewards: [],
      }),
    );
  });

  it("POST /act24side/eat 应扣龙门币、加理智并标记当日已用餐", async () => {
    await call("/act24side/eat", { activityId: "act50side", meal: "meal_1" });
    const meal = player._playerdata.activity.TYPE_ACT24SIDE.act50side.meal;
    expect(meal.digested).toBe(1);
    expect(meal.chance).toBe(0);
    expect(meal.id).toBe("meal_1");
    expect(typeof meal.day).toBe("string"); // 服务端每日限次标记
    // mealCost=200 → 龙门币 1000-200
    expect(player._playerdata.status.gold).toBe(800);
    // mealRewardAP=20 → 理智入账事件
    expect(player._trigger.emit).toHaveBeenCalledWith("items:get", [
      [{ id: "", type: "AP_GAMEPLAY", count: 20 }],
    ]);
  });

  it("POST /act24side/eat 当日重复用餐应拒绝（mealDayTimesLimit=1）", async () => {
    await call("/act24side/eat", { activityId: "act50side", meal: "meal_1" });
    const goldAfterFirst = player._playerdata.status.gold;
    await call("/act24side/eat", { activityId: "act50side", meal: "meal_1" });
    expect(player._playerdata.status.gold).toBe(goldAfterFirst); // 未再次扣费
  });

  it("POST /act24side/eat 龙门币不足应拒绝", async () => {
    player._playerdata.status.gold = 10; // < mealCost 200
    await call("/act24side/eat", { activityId: "act50side", meal: "meal_1" });
    expect(player._playerdata.status.gold).toBe(10);
    expect(
      player._playerdata.activity.TYPE_ACT24SIDE.act50side.meal,
    ).toBeUndefined();
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
