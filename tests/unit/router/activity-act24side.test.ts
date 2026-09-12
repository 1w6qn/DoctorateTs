import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// act24side 合成抽奖读取 excel tYPE_ACT24SIDE.meldingGachaBoxGoodDataMap（首字母小写，真实数据键）
/** excel mock 行形状（本文件用到的字段子集） */
interface ExcelRowMock {
  name?: string;
}

/** 干员行夹具形状（本文件用到的字段子集） */
interface ExcelCharRowMock {
  charId?: string;
  rarity?: string;
  profession?: string;
}

vi.mock("@excel/excel", () => ({
  default: {
    ItemTable: undefined as { items?: Record<string, ExcelRowMock> } | undefined,
    CharacterTable: undefined as Record<string, ExcelCharRowMock> | undefined,
    StageTable: undefined as { stages?: Record<string, ExcelRowMock> } | undefined,
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string): ExcelRowMock | undefined { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string): ExcelCharRowMock | undefined { return this.CharacterTable?.[charId]; },
    stageData(stageId: string): ExcelRowMock | undefined { return this.StageTable?.stages?.[stageId]; },

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

import type { Response } from "express";
import httpContext from "express-http-context2";
import activityRouter from "@game/modules/activities";
import { mockPlayerData, asModel } from "../../helpers";
import type { PlayerDataModel } from "@game/kernel/playerdata";

/** act24side 请求体视图（本文件各端点字段合集） */
interface Act24Body {
  activityId?: string;
  gachaBox?: string;
  items?: { [itemId: string]: number };
  stageId?: string;
  squad?: { slots?: { charInstId?: number; level?: number }[] };
  usePracticeTicket?: number;
  assistFriend?: string | null;
  data?: string;
  battleData?: { isCheat?: string; completeTime?: number };
  meal?: string;
  tools?: string[];
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: Act24Body;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

/**
 * TYPE_ACT24SIDE 活动槽读取视图
 *
 * 字段面与 `scripts/playerdata-server-adapt.ts` 的 TYPE_ACT24SIDE 覆盖一致；活动子树为三层结构，
 * 无法经 `mockPlayerData` 种子写入（TS2345），故就地声明视图后写入，运行期键与值一字不改。
 */
interface Act24SlotView {
  meal?: { chance?: number; digested?: number; id?: string; day?: string };
  alchemy?: {
    price?: number;
    item?: { [itemId: string]: number };
    gacha?: { [boxId: string]: { [goodId: string]: number } };
  };
  tool?: { [toolId: string]: number };
  favorList?: string[];
  unlockItemMap?: { [key: string]: number };
  globalBan?: number;
}

interface Act24ActivityView {
  TYPE_ACT24SIDE?: { [actId: string]: Act24SlotView };
}

type RouterReq = Parameters<typeof activityRouter>[0];

/** 战斗替身返回值（历史夹具；真实结算只 spread 后覆盖 result，故无需 result 键） */
const battleStartResult = {
  result: 0,
  battleId: "b1",
  apFailReturn: 0,
  isApProtect: 0,
  inApProtectPeriod: false,
  notifyPowerScoreNotEnoughIfFailed: false,
};

const battleFinishResult = {
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
};

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

/**
 * 组装 act24side 用例的玩家组合根
 *
 * `MockPlayerDataManager` 的窄接口不含 `getActiveBattle`（本用例 battle 替身带该历史方法），
 * 且 `battle.finish` 声明必带 `result`，故用 `Object.assign` 在运行时挂 battle 替身。
 */
function makePlayer() {
  const mock = mockPlayerData({
    status: { uid: "1", gold: 1000, ap: 50, maxAp: 135 },
    dungeon: asModel<PlayerDataModel["dungeon"]>({ stages: { act24side_01: { state: 0 } } }),
    activity: {},
  });
  // TYPE_ACT24SIDE 子树为三层结构，无法经种子写入，故就地声明视图后写入（键与值一字不改）
  (mock._playerdata.activity as Act24ActivityView).TYPE_ACT24SIDE = {
    act50side: {
      tool: { tool_trap: 2, tool_bomb: 1 },
      alchemy: { price: 0, item: { act24side_melding_6: 200 }, gacha: {} },
    },
  };
  return Object.assign(mock, {
    battle: {
      start: vi.fn().mockResolvedValue(battleStartResult),
      getActiveBattle: vi.fn(() => ({
        battleId: "b1",
        stageId: "act24side_01",
        startTs: 0,
        status: "in_progress",
      })),
      finish: vi.fn().mockResolvedValue(battleFinishResult),
    },
  });
}

type PlayerFixture = ReturnType<typeof makePlayer>;

describe("act24side（怪猎）路由", () => {
  let player: PlayerFixture;
  let res: MockRes;

  beforeEach(() => {
    vi.clearAllMocks();
    player = makePlayer();
    res = mockRes();
    vi.mocked(httpContext.get).mockReturnValue(player);
  });

  /** 读取 act24side 活动槽（见 Act24ActivityView 的说明） */
  function act24(actId = "act50side"): Act24SlotView {
    return (player._playerdata.activity as Act24ActivityView).TYPE_ACT24SIDE![actId];
  }

  async function call(url: string, body: Act24Body) {
    const req: MockReq = { method: "POST", url, body };
    // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
    activityRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /act24side/alchemy 应按 meldingDict 分值抽奖（修复：原 id 写错恒 0 分）", async () => {
    // act24side_melding_6 = 200 分 → 重构箱（gachaCost=100）可抽 2 次
    await call("/act24side/alchemy", {
      activityId: "act50side",
      gachaBox: "gachabox1",
      items: { act24side_melding_6: 1 },
    });
    const sent = vi.mocked(res.send).mock.calls[0][0];
    expect(sent.rewards.length).toBeGreaterThan(0);
    // 素材被消耗
    expect(
      act24().alchemy!.item!
        .act24side_melding_6,
    ).toBe(199);
    // 抽中记录写入 gacha（200 分 / 100 = 2 次）
    const gacha =
      act24().alchemy!.gacha!
        .gachabox1;
    const totalDrawn = Object.values(gacha).reduce(
      (a: number, b: number) => a + b,
      0,
    );
    expect(totalDrawn).toBe(2);
    // 奖励发放已收敛到 player.gainItem 管道（不再直发 items:get 事件）
    expect(player.gainItem.add).toHaveBeenCalledWith(sent.rewards[0]);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("POST /act24side/alchemy 转换箱按 gachaCost=40 计算且 UNLIMITED 池可抽", async () => {
    // act24side_melding_1 = 2 分 × 30 = 60 分 → 40 分/次 → 1 次，余值 20 留存
    act24().alchemy!.item = {
      act24side_melding_1: 30,
    };
    await call("/act24side/alchemy", {
      activityId: "act50side",
      gachaBox: "gachabox2",
      items: { act24side_melding_1: 30 },
    });
    const alchemy = act24().alchemy!;
    expect(alchemy.price).toBe(20); // 余值留存（不丢弃）
    const sent = vi.mocked(res.send).mock.calls[0][0];
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
    const sent = vi.mocked(res.send).mock.calls[0][0];
    expect(sent.rewards).toEqual([]);
    expect(
      act24().alchemy!.item!
        .act24side_melding_6,
    ).toBe(200); // 未被消耗
    // 未被消耗 → 不发奖励；领奖相关领域事件也不派发
    expect(player.gainItem.add).not.toHaveBeenCalled();
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
    const meal = act24().meal!;
    expect(meal.digested).toBe(1);
    expect(meal.chance).toBe(0);
    expect(meal.id).toBe("meal_1");
    expect(typeof meal.day).toBe("string"); // 服务端每日限次标记
    // mealCost=200 → 龙门币 1000-200
    expect(player._playerdata.status.gold).toBe(800);
    // mealRewardAP=20 → 理智经物品管道入账（不再直发 items:get）
    expect(player.gainItem.add).toHaveBeenCalledWith({
      id: "",
      type: "AP_GAMEPLAY",
      count: 20,
    });
    expect(player.gainItem.handle).toHaveBeenCalled();
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
    expect(act24().meal).toBeUndefined();
  });

  it("POST /act24side/setTool 应激活列表内工具并取消其余", async () => {
    await call("/act24side/setTool", { activityId: "act50side", tools: ["tool_trap"] });
    const tool = act24().tool!;
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
