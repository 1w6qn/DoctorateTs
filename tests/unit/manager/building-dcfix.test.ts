import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * dc-fix 回归测试（2026-08-26 用户报告 4 项修复）
 *
 * 1. workshopSynthesis：CS 请求体无 roomSlotId（BuildingWorkshopSynthesisRequest 仅
 *    formulaId+times）——schema 不得强制该字段
 * 2. deliveryOrder：CS orderId 为 Int64（客户端发数字）——schema 兼容 number
 * 3. 制造站补货：旧存档无 maxLevelReached 记录时 当前房间等级视为"曾达"级
 *    changeManufactureSolution 不得拒绝（补到 99）
 * 4. 生产速率（官方校准，2222 真存档实测）：
 *    - 制造站：1×(1+加成) 点/秒，阈值 costPoint=基础秒（赤金 4320=72 分钟）
 *    - 贸易站：速度 = 1+当前加成（每次重算，禁止 next.speed 复利回写）
 */

const excelMock = vi.hoisted(() => ({
  default: {
    BuildingData: {
      laborRecoverTime: 360,
      goldItems: { "3003": 500 },
      buffs: {},
      chars: {},
      manufactFormulas: {
        "4": { formulaId: "4", itemId: "3003", count: 1, costPoint: 4320, formulaType: "F_GOLD", costs: [], requireRooms: [{ roomId: "MANUFACTURE", roomLevel: 1, roomCount: 1 }], requireStages: [] },
      },
      workshopFormulas: {
        "1": { formulaId: "1", itemId: "3131", count: 1, goldCost: 0, apCost: 0, formulaType: "F_BUILDING", costs: [{ id: "3112", count: 2, type: "MATERIAL" }], requireRooms: [{ roomId: "WORKSHOP", roomLevel: 1, roomCount: 1 }], requireStages: [] },
      },
      manufactData: { phases: [{ speed: 1, outputCapacity: 24 }, { speed: 1, outputCapacity: 36 }, { speed: 1, outputCapacity: 54 }] },
      rooms: {
        MANUFACTURE: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 1 }, { buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 2 }, { buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 3 }] },
        TRADING: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 1 }] },
        WORKSHOP: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 1 }] },
      },
    },
  },
}));
vi.mock("@excel/excel", () => excelMock);

const timeMock = vi.hoisted(() => ({ now: 1234567890 }));
vi.mock("@utils/time", () => ({ now: () => timeMock.now }));

vi.mock("@game/service/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import {
  workshopSynthesisSchema,
  deliveryOrderSchema,
} from "@game/service/building/schemas";
import { BuildingManager } from "@game/service/building/logic";

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

/** 旧存档形态：无 maxLevelReached、制造站 lv3、贸易站带 next 进度 */
function baseBuilding(): any {
  return {
    status: {
      labor: { buffSpeed: 0, processPoint: 0, value: 100, lastUpdateTime: timeMock.now, maxValue: 225 },
      workshop: { bonusActive: 0, bonus: {} },
    },
    chars: {},
    roomSlots: {
      slot_25: { level: 3, state: 2, roomId: "MANUFACTURE", charInstIds: [], completeConstructTime: -1 },
      slot_24: { level: 3, state: 2, roomId: "TRADING", charInstIds: [], completeConstructTime: -1 },
      slot_32: { level: 1, state: 2, roomId: "WORKSHOP", charInstIds: [], completeConstructTime: -1 },
    },
    rooms: {
      CONTROL: {}, ELEVATOR: {}, POWER: {},
      MANUFACTURE: {
        slot_25: {
          state: 1, formulaId: "4", remainSolutionCnt: 0, outputSolutionCnt: 26,
          processPoint: 0, lastUpdateTime: timeMock.now, completeWorkTime: -1, capacity: 54,
        },
      },
      TRADING: {
        slot_24: {
          state: 1, strategy: "O_GOLD", stockLimit: 10, stock: [],
          lastUpdateTime: timeMock.now,
          next: { order: 28232, processPoint: 775.46, maxPoint: 12600, speed: 1.78 },
        },
      },
      CORRIDOR: {}, WORKSHOP: { slot_32: { state: 2 } }, DORMITORY: {}, MEETING: {}, HIRE: {}, TRAINING: {}, PRIVATE: {},
    },
    furniture: {},
    diyPresetSolutions: {},
    assist: [-1, -1, -1],
    solution: { furnitureTs: {} },
    music: { inUse: false, selected: "bgm_default", state: {} },
  };
}

function setup() {
  const { mockPlayer, mockTrigger } = makePlayer(baseBuilding(), {
    status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
    inventory: { "3112": 10 },
    troop: { chars: {}, charGroup: {} },
  });
  const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
  return { mockPlayer, manager };
}

describe("dc-fix #1/#2：协议请求体校验（CS 字段形态）", () => {
  it("workshopSynthesis：CS 仅发 { formulaId, times }，roomSlotId 可选", () => {
    expect(workshopSynthesisSchema.parse({ formulaId: "1", times: 1 })).toEqual({
      formulaId: "1",
      times: 1,
    });
  });

  it("deliveryOrder：CS orderId 为数字（Int64），兼容 string/number", () => {
    expect(deliveryOrderSchema.parse({ slotId: "slot_24", orderId: 28207 })).toEqual({
      slotId: "slot_24",
      orderId: 28207,
    });
    expect(deliveryOrderSchema.parse({ slotId: "slot_24", orderId: "28207" })).toEqual({
      slotId: "slot_24",
      orderId: "28207",
    });
  });

  it("deliveryOrder：数字 orderId 命中订单（manager 按 String(instId) 匹配）", async () => {
    const { mockPlayer, manager } = setup();
    const room = mockPlayer._playerdata.building.rooms.TRADING.slot_24 as any;
    room.stock = [
      { instId: 28207, delivery: [], type: "O_GOLD", gain: { id: "4001", type: "GOLD", count: 1000 }, buff: [] },
    ];
    await manager.deliveryOrder({ slotId: "slot_24", orderId: 28207 } as any);
    // update 深拷贝回写后 重新读取（原引用已陈旧）
    const roomAfter = (mockPlayer._playerdata.building.rooms.TRADING as any).slot_24;
    expect(roomAfter.stock).toHaveLength(0);
    expect(mockPlayer._playerdata.status!.gold).toBe(11000); // 10000 + 1000 收益
  });
});

describe("dc-fix #3：旧存档补货（曾达等级含当前房间等级）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("无 maxLevelReached 记录：lv3 制造站可换配方/补货到 99", async () => {
    const { mockPlayer, manager } = setup();
    expect((mockPlayer._playerdata.building as any).maxLevelReached).toBeUndefined();
    await manager.changeManufactureSolution({
      roomSlotId: "slot_25",
      targetFormulaId: "4",
      solutionCount: 99,
    } as any);
    const room = mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_25;
    expect(room.formulaId).toBe("4");
    expect(room.remainSolutionCnt).toBe(99); // 补到 99
  });
});

describe("dc-fix #4：生产速率官方校准（2222 真存档实测）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("制造站：速率 = 1×(1+加成) 点/秒——赤金一批恰需 costPoint 秒（无加成 4320s=72 分钟）", () => {
    const { mockPlayer, manager } = setup();
    const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
    const room = draft.building.rooms.MANUFACTURE.slot_25;
    room.remainSolutionCnt = 5;
    (manager as any)._accrueManufacture(draft, "slot_25", timeMock.now + 4320);
    expect(room.outputSolutionCnt).toBe(26 + 1); // 产出 1 批
    expect(room.processPoint).toBe(0);
    // 半程不产出（原实现按容量 54 点/秒，80 秒一批，快约 54 倍）
    const draft2 = JSON.parse(JSON.stringify(mockPlayer._playerdata));
    const room2 = draft2.building.rooms.MANUFACTURE.slot_25;
    room2.remainSolutionCnt = 5;
    (manager as any)._accrueManufacture(draft2, "slot_25", timeMock.now + 2000);
    expect(room2.outputSolutionCnt).toBe(26);
    expect(room2.processPoint).toBe(2000);
  });

  it("贸易站：速度 = 1+当前加成，多次推进不复利（存档 speed 1.78 不被当乘数）", () => {
    const { mockPlayer, manager } = setup();
    const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
    const room = draft.building.rooms.TRADING.slot_24;
    // 无进驻干员时 加成 0 → 速度重算 1.0（不是 1.78×(1+0) 再回写复利）
    (manager as any)._accrueTrading(draft, timeMock.now + 3600);
    expect(room.next.speed).toBeCloseTo(1.0);
    const pp1 = room.next.processPoint;
    expect(pp1).toBeCloseTo(775.46 + 3600); // < maxPoint 12600，不出单
    (manager as any)._accrueTrading(draft, timeMock.now + 7200);
    expect(room.next.speed).toBeCloseTo(1.0); // 第二次推进速度不变（无复利）
    expect(room.next.processPoint).toBeCloseTo(775.46 + 7200);
  });
});
