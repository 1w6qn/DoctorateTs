import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * 宿舍特殊技能 + 恢复公式 + buyLabor AP 兑换（批次⑥：2026-08-25 全量对齐）
 *
 * 覆盖（机制来自 prts.wiki 宿舍页/控制中枢页 + building_data.buffs）：
 * - dorm-special.ts：技能作用域分类（all/self/single/shared）、双数值拆分 + 同种取最大
 * - 恢复公式：(1.5+0.1×等级) + 氛围×0.0004（替换旧 /160 与 /1000×0.55 拆分）
 * - 按成员分发：自身恢复仅自身 / 单体恢复给心情最低成员 / 均分恢复分给未满成员
 * - buyLabor：中枢 4 级用理智兑换（1 AP → 2 劳动力），未达级走源石兼容路径
 */

const excelMock = vi.hoisted(() => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    BuildingData: {
      laborRecoverTime: 360,
      apToLaborUnlockLevel: 4,
      apToLaborRatio: 2,
      buffs: {
        "dorm_rec_oneself[000]": {
          buffId: "dorm_rec_oneself[000]", roomType: "DORMITORY", efficiency: 0,
          targets: [], description: "进驻宿舍时，自身心情每小时恢复<@cc.vup>+0.7</>",
        },
        "dorm_rec_single[000]": {
          buffId: "dorm_rec_single[000]", roomType: "DORMITORY", efficiency: 0,
          targets: [], description: "进驻宿舍时，使该宿舍内除自身以外心情未满的某个干员每小时恢复<@cc.vup>+0.65</>（同种效果取最高）",
        },
        "dorm_rec_single&oneself[000]": {
          buffId: "dorm_rec_single&oneself[000]", roomType: "DORMITORY", efficiency: 0,
          targets: [], description: "进驻宿舍时，使该宿舍内除自身以外心情未满的某个干员每小时恢复<@cc.vup>+0.2</>（同种效果取最高）；同时自身心情每小时恢复<@cc.vup>+0.4</>",
        },
        "dorm_rec_all&single[000]": {
          buffId: "dorm_rec_all&single[000]", roomType: "DORMITORY", efficiency: 0,
          targets: [], description: "进驻宿舍时，使心情未满的宿舍成员，平均分配到总计每小时心情恢复<@cc.vup>+0.8</>的加成",
        },
        "dorm_rec_all[010]": {
          buffId: "dorm_rec_all[010]", roomType: "DORMITORY", efficiency: 0,
          targets: [], description: "进驻宿舍时，该宿舍内所有干员的心情每小时恢复<@cc.vup>+0.15</>（同种效果取最高）",
        },
      },
      chars: {
        char_self: { charId: "char_self", buffChar: [{ buffData: [{ buffId: "dorm_rec_oneself[000]", cond: { level: 1 } }] }] },
        char_single: { charId: "char_single", buffChar: [{ buffData: [{ buffId: "dorm_rec_single[000]", cond: { level: 1 } }] }] },
        char_dual: { charId: "char_dual", buffChar: [{ buffData: [{ buffId: "dorm_rec_single&oneself[000]", cond: { level: 1 } }] }] },
        char_shared: { charId: "char_shared", buffChar: [{ buffData: [{ buffId: "dorm_rec_all&single[000]", cond: { level: 1 } }] }] },
        char_all: { charId: "char_all", buffChar: [{ buffData: [{ buffId: "dorm_rec_all[010]", cond: { level: 1 } }] }] },
      },
      rooms: {
        DORMITORY: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 5 }] },
        CONTROL: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 1 }] },
      },
    },
  },
}));
vi.mock("@excel/excel", () => excelMock);

const timeMock = vi.hoisted(() => ({ now: 1234567890 }));
vi.mock("@utils/time", () => ({ now: () => timeMock.now }));

vi.mock("@game/service/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import {
  classifyDormBuff,
  splitDormBuffs,
  sumByGroupMax,
} from "@game/domain/building/dorm-special";
import { BuildingManager } from "@game/domain/building/logic";

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

const MAX = 8640000;

function dormBuilding(opts: {
  members: [number, string, number][]; // [instId, charId, ap]
  comfort?: number;
  level?: number;
  controlLevel?: number;
}): any {
  const chars: any = {};
  const troopChars: any = {};
  for (const [instId, charId, ap] of opts.members) {
    chars[String(instId)] = {
      charId, ap, lastApAddTime: timeMock.now, roomSlotId: "slot_28", index: 0,
      changeScale: 0, bubble: {},
    };
    troopChars[String(instId)] = { charId, level: 20, evolvePhase: 0 };
  }
  return {
    building: {
      status: {
        labor: { buffSpeed: 0, processPoint: 0, value: 100, lastUpdateTime: timeMock.now, maxValue: 225 },
        workshop: { bonusActive: 0, bonus: {} },
      },
      chars,
      roomSlots: {
        slot_28: { level: opts.level ?? 1, state: 2, roomId: "DORMITORY", charInstIds: opts.members.map(([i]) => i), completeConstructTime: -1 },
        slot_34: { level: opts.controlLevel ?? 1, state: 2, roomId: "CONTROL", charInstIds: [], completeConstructTime: -1 },
      },
      rooms: {
        CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
        CORRIDOR: {}, WORKSHOP: {}, MEETING: {}, HIRE: {}, TRAINING: {}, PRIVATE: {},
        DORMITORY: { slot_28: { comfort: opts.comfort ?? 0 } },
      },
      furniture: {},
      diyPresetSolutions: {},
      assist: [-1, -1, -1],
      solution: { furnitureTs: {} },
      music: { inUse: false, selected: "bgm_default", state: {} },
    },
    troop: { chars: troopChars, charGroup: {} },
  };
}

function setup(opts: Parameters<typeof dormBuilding>[0]) {
  const data = dormBuilding(opts);
  const { mockPlayer, mockTrigger } = makePlayer(data.building, {
    status: { uid: "1", gold: 10000, androidDiamond: 100, ap: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
    inventory: {},
    troop: data.troop,
  });
  const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
  return { mockPlayer, manager };
}

function recompute(manager: any, mockPlayer: any): any {
  const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
  (manager as any)._recomputeCharScales(draft);
  return draft.building.chars;
}

describe("dorm-special.ts 纯函数（作用域分类/拆分）", () => {
  it("classifyDormBuff：shared/single/self/all 前缀判定", () => {
    expect(classifyDormBuff("dorm_rec_all&single[000]")).toBe("shared");
    expect(classifyDormBuff("dorm_rec_single[000]")).toBe("single");
    expect(classifyDormBuff("dorm_rec_single&oneself[000]")).toBe("single");
    expect(classifyDormBuff("dorm_rec_oneself[000]")).toBe("self");
    expect(classifyDormBuff("dorm_rec_all[010]")).toBe("all");
    expect(classifyDormBuff("dorm_powToRecAll[000]")).toBe("all");
  });

  it("splitDormBuffs：single&oneself 双数值拆分（首=单体、次=自身）", () => {
    const split = splitDormBuffs([
      { buffId: "dorm_rec_single&oneself[000]", description: "恢复<@cc.vup>+0.2</>；同时自身<@cc.vup>+0.4</>" },
    ]);
    expect(split.single).toEqual([{ group: "dorm_rec_single&oneself", value: 0.2 }]);
    expect(split.self).toEqual([{ group: "dorm_rec_single&oneself", value: 0.4 }]);
  });

  it("sumByGroupMax：同技能取最高后求和", () => {
    expect(sumByGroupMax([
      { group: "a", value: 0.1 },
      { group: "a", value: 0.2 },
      { group: "b", value: 0.05 },
    ])).toBeCloseTo(0.25);
    expect(sumByGroupMax([])).toBe(0);
  });
});

describe("BuildingManager 宿舍恢复按成员分发（_recomputeCharScales）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("恢复公式：(1.5+0.1×级) + 氛围×0.0004（无技能，1 级 2000 氛围 → 1.6+0.8=2.4）", () => {
    const { manager, mockPlayer } = setup({ members: [[1, "char_plain" as any, MAX]], comfort: 2000, level: 1 });
    const chars = recompute(manager, mockPlayer);
    expect(chars["1"].changeScale).toBe(240);
  });

  it("自身恢复仅作用于施放者（all 全员 + self 独享）", () => {
    const { manager, mockPlayer } = setup({
      members: [[1, "char_all" as any, MAX], [2, "char_self" as any, MAX]],
      level: 1,
    });
    const chars = recompute(manager, mockPlayer);
    // 基础 1.6；char_all 全体 +0.15 → 两人共享；char_self 自身 +0.7 仅自身
    expect(chars["1"].changeScale).toBe(Math.round((1.6 + 0.15) * 100));
    expect(chars["2"].changeScale).toBe(Math.round((1.6 + 0.15 + 0.7) * 100));
  });

  it("单体恢复给除施放者外心情最低成员", () => {
    const { manager, mockPlayer } = setup({
      members: [
        [1, "char_single" as any, MAX],
        [2, "char_plain_a" as any, MAX], // 满心情，不是目标
        [3, "char_plain_b" as any, 1000], // 心情最低 → 目标
      ],
      level: 1,
    });
    const chars = recompute(manager, mockPlayer);
    expect(chars["3"].changeScale).toBe(Math.round((1.6 + 0.65) * 100));
    expect(chars["1"].changeScale).toBe(Math.round(1.6 * 100));
    expect(chars["2"].changeScale).toBe(Math.round(1.6 * 100));
  });

  it("均分恢复（小酌怡情）：总量 0.8 平分给心情未满成员", () => {
    const { manager, mockPlayer } = setup({
      members: [
        [1, "char_shared" as any, MAX], // 施放者满心情，不参与分配
        [2, "char_plain_a" as any, 100], // 未满 → +0.4
        [3, "char_plain_b" as any, 200], // 未满 → +0.4
      ],
      level: 1,
    });
    const chars = recompute(manager, mockPlayer);
    expect(chars["2"].changeScale).toBe(Math.round((1.6 + 0.4) * 100));
    expect(chars["3"].changeScale).toBe(Math.round((1.6 + 0.4) * 100));
    expect(chars["1"].changeScale).toBe(Math.round(1.6 * 100));
  });
});

describe("BuildingManager buyLabor AP 兑换（官方路径）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("中枢 4 级：理智兑换（1 AP → 2 劳动力），不扣源石", async () => {
    const { manager, mockPlayer } = setup({ members: [], controlLevel: 4 });
    mockPlayer._playerdata.building.status.labor.value = 200;
    await manager.buyLabor({ buyCount: 10 } as any);
    expect(mockPlayer._playerdata.status!.ap).toBe(95); // 100 - ceil(10/2)
    expect(mockPlayer._playerdata.building.status.labor.value).toBe(210);
    expect(mockPlayer._playerdata.status!.androidDiamond).toBe(100);
  });

  it("中枢 4 级但理智不足时 拒绝", async () => {
    const { manager, mockPlayer } = setup({ members: [], controlLevel: 4 });
    (mockPlayer._playerdata.status as any).ap = 2;
    await manager.buyLabor({ buyCount: 10 } as any);
    expect(mockPlayer._playerdata.building.status.labor.value).toBe(100);
  });

  it("中枢 <4 级：走源石兼容路径（1 源石 → 10 劳动力）", async () => {
    const { manager, mockPlayer } = setup({ members: [], controlLevel: 3 });
    await manager.buyLabor({ buyCount: 1 } as any);
    expect(mockPlayer._playerdata.status!.androidDiamond).toBe(99);
    expect(mockPlayer._playerdata.building.status.labor.value).toBe(110);
    expect(mockPlayer._playerdata.status!.ap).toBe(100); // 理智不动
  });
});
