import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * 贸易站订单模型 + 加速无人机语义（批次③④，2026-08-25 全量对齐）
 *
 * 覆盖（机制来源 prts.wiki 贸易站页/发电站页）：
 * - trade-orders.ts 纯函数：站级概率表 / 暖机 α/β/双α 改写 / 权重抽取 / 档位判定
 * - _genTradingOrder：Lv1 恒 2 金、Lv3 概率、暖机激活、违约订单（law+against）、
 *   龙舌兰收益加成（long）、开采协力（O_DIAMOND）
 * - accelerateSolution：带 cost → 3 分钟/架推进进度；缺省 → 兼容立即完成 1 方案
 */

const excelMock = vi.hoisted(() => ({
  default: {
    BuildingData: {
      orderMaxPoint: 3000,
      laborRecoverTime: 360,
      goldItems: { "3003": 500 },
      buffs: {
        "trade_ord_wt&cost[000]": {
          buffId: "trade_ord_wt&cost[000]", roomType: "TRADING", efficiency: 0,
          targets: [], description: "进驻贸易站时，小幅提升高品质贵金属订单出现概率（工作时长影响），心情每小时消耗<@cc.vdown>+0.25</>",
        },
        "trade_ord_wt&cost[010]": {
          buffId: "trade_ord_wt&cost[010]", roomType: "TRADING", efficiency: 0,
          targets: [], description: "进驻贸易站时，提升高品质贵金属订单出现概率（工作时长影响），心情每小时消耗<@cc.vdown>+0.25</>",
        },
        "trade_ord_law[000]": {
          buffId: "trade_ord_law[000]", roomType: "TRADING", efficiency: 0,
          targets: [], description: "进驻贸易站时，如果下笔赤金订单交付数小于4，则视为违约订单",
        },
        "trade_ord_against[000]": {
          buffId: "trade_ord_against[000]", roomType: "TRADING", efficiency: 0,
          targets: [], description: "进驻贸易站时，如果下笔赤金订单是违约订单，则赤金交付数额外<@cc.vup>+1</>",
        },
        "trade_ord_long[010]": {
          buffId: "trade_ord_long[010]", roomType: "TRADING", efficiency: 0,
          targets: [], description: "进驻贸易站后，如果下笔赤金订单交付数大于3，则其龙门币收益<@cc.kw>+500</>",
        },
      },
      chars: {
        char_wta: { charId: "char_wta", buffChar: [{ buffData: [{ buffId: "trade_ord_wt&cost[000]", cond: { level: 1 } }] }] },
        char_wtb: { charId: "char_wtb", buffChar: [{ buffData: [{ buffId: "trade_ord_wt&cost[010]", cond: { level: 1 } }] }] },
        char_law: { charId: "char_law", buffChar: [{ buffData: [{ buffId: "trade_ord_law[000]", cond: { level: 1 } }, { buffId: "trade_ord_against[000]", cond: { level: 1 } }] }] },
        char_long: { charId: "char_long", buffChar: [{ buffData: [{ buffId: "trade_ord_long[010]", cond: { level: 1 } }] }] },
      },
      manufactData: { phases: [{ speed: 1, outputCapacity: 24 }, { speed: 1, outputCapacity: 36 }, { speed: 1, outputCapacity: 54 }] },
      manufactFormulas: {
        "4": { formulaId: "4", itemId: "3003", count: 1, costPoint: 4320, formulaType: "F_GOLD", costs: [] },
      },
      rooms: {
        MANUFACTURE: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 1 }, { buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 2 }, { buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 3 }] },
        TRADING: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 1 }, { buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 2 }, { buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 3 }] },
        CONTROL: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 1 }] },
      },
    },
  },
}));
vi.mock("@excel/excel", () => excelMock);

const timeMock = vi.hoisted(() => ({ now: 1234567890 }));
vi.mock("@utils/time", () => ({ now: () => timeMock.now }));

vi.mock("@game/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import {
  goldOrderDistribution,
  pickGoldCount,
  warmupSkillTier,
  GOLD_ORDER_DISTRIBUTION,
} from "@game/modules/building/trade-orders";
import { BuildingManager } from "@game/modules/building/logic";

function makePlayer(building: any, extra: any = {}) {
  const mockPlayer = mockPlayerData({
    building,
    event: { building: 0 },
    pushFlags: { hasGifts: 0, hasFriendRequest: 0, hasClues: 0, hasFreeLevelGP: 0, status: 0 },
    ...extra,
  });
  const mockTrigger = mockTypedEventEmitter();
  mockPlayer._trigger = mockTrigger;
  mockPlayer.update = vi
    .fn()
    .mockImplementation(
      async (recipe: (draft: any) => Promise<any> | any) => {
        const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
        const result = await recipe(draft);
        Object.assign(mockPlayer._playerdata, draft);
        return result;
      },
    );
  return { mockPlayer, mockTrigger };
}

function baseBuilding(): any {
  return {
    status: {
      labor: { buffSpeed: 0, processPoint: 0, value: 100, lastUpdateTime: 1000, maxValue: 225 },
      workshop: { bonusActive: 0, bonus: {} },
    },
    chars: {},
    roomSlots: {
      slot_5: { level: 3, state: 2, roomId: "MANUFACTURE", charInstIds: [], completeConstructTime: -1 },
      slot_6: { level: 3, state: 2, roomId: "TRADING", charInstIds: [], completeConstructTime: -1 },
    },
    rooms: {
      CONTROL: {}, ELEVATOR: {}, POWER: {},
      MANUFACTURE: {
        slot_5: {
          state: 1, formulaId: "4", remainSolutionCnt: 10, outputSolutionCnt: 0,
          processPoint: 0, lastUpdateTime: 1000, completeWorkTime: -1, capacity: 0,
        },
      },
      TRADING: { slot_6: { state: 1, strategy: "O_GOLD", stock: [], stockLimit: 10, lastUpdateTime: 1000 } },
      CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {}, TRAINING: {}, PRIVATE: {},
    },
    furniture: {},
    diyPresetSolutions: {},
    assist: [-1, -1, -1],
    solution: { furnitureTs: {} },
    music: { inUse: false, selected: "bgm_default", state: {} },
  };
}

function draftOf(mockPlayer: any): any {
  return JSON.parse(JSON.stringify(mockPlayer._playerdata));
}

function setup() {
  const { mockPlayer, mockTrigger } = makePlayer(baseBuilding(), {
    status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
    inventory: {},
    troop: { chars: {}, charGroup: {} },
  });
  const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
  return { mockPlayer, mockTrigger, manager };
}

describe("trade-orders.ts 纯函数（概率表/暖机/抽取）", () => {
  it("站级基础概率表（1~3 级，越界钳制）", () => {
    expect(goldOrderDistribution(1)).toEqual(GOLD_ORDER_DISTRIBUTION[1]);
    expect(goldOrderDistribution(2)).toEqual(GOLD_ORDER_DISTRIBUTION[2]);
    expect(goldOrderDistribution(3)).toEqual(GOLD_ORDER_DISTRIBUTION[3]);
    expect(goldOrderDistribution(9)).toEqual(GOLD_ORDER_DISTRIBUTION[3]);
  });

  it("暖机改写：1α → α 分布；≥2α → 双α；β 激活 → β（α+β 按 β）", () => {
    expect(goldOrderDistribution(3, { alpha: 1, beta: 0 })[0]).toEqual({ gold: 4, weight: 55 });
    expect(goldOrderDistribution(3, { alpha: 2, beta: 0 })[0]).toEqual({ gold: 4, weight: 65 });
    expect(goldOrderDistribution(3, { alpha: 2, beta: 1 })[0]).toEqual({ gold: 4, weight: 85 });
    expect(goldOrderDistribution(1, { alpha: 1, beta: 0 })[0]).toEqual({ gold: 4, weight: 55 });
  });

  it("pickGoldCount 按权重区间抽取（Lv3：30/50/20）", () => {
    const dist = GOLD_ORDER_DISTRIBUTION[3];
    expect(pickGoldCount(dist, 0.0)).toBe(2);
    expect(pickGoldCount(dist, 0.29)).toBe(2);
    expect(pickGoldCount(dist, 0.31)).toBe(3);
    expect(pickGoldCount(dist, 0.79)).toBe(3);
    expect(pickGoldCount(dist, 0.81)).toBe(4);
    expect(pickGoldCount(dist, 0.999)).toBe(4);
  });

  it("warmupSkillTier：α=[00x] / β=[01x] / 其余非暖机", () => {
    expect(warmupSkillTier("trade_ord_wt&cost[000]")).toBe("alpha");
    expect(warmupSkillTier("trade_ord_wt&cost[004]")).toBe("alpha");
    expect(warmupSkillTier("trade_ord_wt&cost[010]")).toBe("beta");
    expect(warmupSkillTier("trade_ord_spd[000]")).toBeNull();
  });
});

describe("BuildingManager 订单生成（_genTradingOrder）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  /** 进驻干员到贸易站（troop + building.chars，可带暖机工时） */
  function stationChar(mockPlayer: any, instId: number, charId: string, warmupSec = 0) {
    mockPlayer._playerdata.troop.chars[String(instId)] = { charId, level: 10, evolvePhase: 0 };
    mockPlayer._playerdata.building.chars[String(instId)] = {
      charId, ap: 8640000, lastApAddTime: timeMock.now, roomSlotId: "slot_6", index: 0,
      changeScale: 0, bubble: {}, warmupSec, warmupTs: timeMock.now, warmupSlot: "slot_6",
    };
    mockPlayer._playerdata.building.roomSlots.slot_6.charInstIds.push(instId);
  }

  it("Lv1 站恒生成 2 赤金订单（官方概率 100%），收益 = 2 × 汇率", () => {
    const { manager, mockPlayer } = setup();
    const draft = draftOf(mockPlayer);
    draft.building.roomSlots.slot_6.level = 1;
    const room = draft.building.rooms.TRADING.slot_6;
    (manager as any)._genTradingOrder(draft, room, 1);
    expect(room.stock[0].delivery).toEqual([{ id: "3003", type: "MATERIAL", count: 2 }]);
    expect(room.stock[0].gain.count).toBe(1000); // 2 × 500
  });

  it("Lv3 站按概率表：roll 高位 → 4 赤金", () => {
    vi.spyOn(Math, "random").mockReturnValue(0.99);
    const { manager, mockPlayer } = setup();
    const draft = draftOf(mockPlayer);
    (manager as any)._genTradingOrder(draft, draft.building.rooms.TRADING.slot_6, 1);
    expect(draft.building.rooms.TRADING.slot_6.stock[0].delivery[0].count).toBe(4);
  });

  it("暖机 α 达 3h 后改写概率（4 金 55% 首位）", () => {
    vi.spyOn(Math, "random").mockReturnValue(0.0); // α 分布首位 = 4 金
    const { manager, mockPlayer } = setup();
    stationChar(mockPlayer, 701, "char_wta", 3 * 3600);
    const draft = draftOf(mockPlayer);
    (manager as any)._genTradingOrder(draft, draft.building.rooms.TRADING.slot_6, 1);
    expect(draft.building.rooms.TRADING.slot_6.stock[0].delivery[0].count).toBe(4);
  });

  it("暖机工时不足（<3h）不激活，仍按站级表", () => {
    vi.spyOn(Math, "random").mockReturnValue(0.0); // Lv3 基础首位 = 2 金
    const { manager, mockPlayer } = setup();
    stationChar(mockPlayer, 701, "char_wta", 2 * 3600);
    const draft = draftOf(mockPlayer);
    (manager as any)._genTradingOrder(draft, draft.building.rooms.TRADING.slot_6, 1);
    expect(draft.building.rooms.TRADING.slot_6.stock[0].delivery[0].count).toBe(2);
  });

  it("违约订单：交付 <4 视为违约，赤金交付额外 +1（against），标记 special", () => {
    vi.spyOn(Math, "random").mockReturnValue(0.0); // Lv3 → 2 金 < 4
    const { manager, mockPlayer } = setup();
    stationChar(mockPlayer, 702, "char_law");
    const draft = draftOf(mockPlayer);
    (manager as any)._genTradingOrder(draft, draft.building.rooms.TRADING.slot_6, 1);
    const order = draft.building.rooms.TRADING.slot_6.stock[0];
    expect(order.delivery[0].count).toBe(3); // 2 + 1
    expect(order.special).toBe("breach");
  });

  it("龙舌兰：非违约且交付 >3 → 收益 +500（[010] 档）", () => {
    vi.spyOn(Math, "random").mockReturnValue(0.99); // Lv3 → 4 金
    const { manager, mockPlayer } = setup();
    stationChar(mockPlayer, 703, "char_long");
    const draft = draftOf(mockPlayer);
    (manager as any)._genTradingOrder(draft, draft.building.rooms.TRADING.slot_6, 1);
    const order = draft.building.rooms.TRADING.slot_6.stock[0];
    expect(order.delivery[0].count).toBe(4);
    expect(order.gain.count).toBe(4 * 500 + 500);
  });

  it("开采协力（O_DIAMOND）：源石碎片×2 → 合成玉×20", () => {
    const { manager, mockPlayer } = setup();
    const draft = draftOf(mockPlayer);
    draft.building.rooms.TRADING.slot_6.strategy = "O_DIAMOND";
    (manager as any)._genTradingOrder(draft, draft.building.rooms.TRADING.slot_6, 1);
    const order = draft.building.rooms.TRADING.slot_6.stock[0];
    expect(order.type).toBe("O_DIAMOND");
    expect(order.delivery).toEqual([{ id: "3141", type: "MATERIAL", count: 2 }]);
    expect(order.gain).toEqual({ id: "4003", type: "DIAMOND_SHD", count: 20 });
  });
});

describe("BuildingManager 加速方案（accelerateSolution 无人机语义）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("带 cost：1 架 = 3 分钟 → 按官方速率推进进度并产出整批", async () => {
    const { manager, mockPlayer } = setup();
    // 时间基准对齐（无既有离线进度）；无干员 → 速率 1 点/秒：
    // 24 架 = 24×180 = 4320 点 = 恰完成 1 批赤金（costPoint 4320 = 官方 72 分钟）
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.lastUpdateTime = timeMock.now;
    await manager.accelerateSolution({ slotId: "slot_5", cost: 24 } as any);
    const room = mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5;
    expect(room.outputSolutionCnt).toBe(1);
    expect(room.remainSolutionCnt).toBe(9);
    expect(room.processPoint).toBe(0);
  });

  it("cost 缺省：兼容旧行为（立即完成 1 方案）", async () => {
    const { manager, mockPlayer } = setup();
    await manager.accelerateSolution({ slotId: "slot_5" } as any);
    const room = mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5;
    expect(room.outputSolutionCnt).toBe(1);
    expect(room.remainSolutionCnt).toBe(9);
  });

  it("计划耗尽（remain=0）时加速无效（停摆待收取）", async () => {
    const { manager, mockPlayer } = setup();
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.remainSolutionCnt = 0;
    await manager.accelerateSolution({ slotId: "slot_5", cost: 5 } as any);
    const room = mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5;
    expect(room.outputSolutionCnt).toBe(0);
  });
});
