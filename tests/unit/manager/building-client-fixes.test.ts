import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * 客户端交互三问题修复测试（2026-08-19）
 *
 * 1. deliveryBatchOrder：兼容请求字段变体（slotList/slotIdList/roomSlotIdList/单值）
 *    ——客户端改造版字段名不同导致 200 但空循环不交付
 * 2. batchChangeWorkChar：空请求体（官方 CS 无字段）时**预设队列轮换**——
 *    客户端"换班"按钮期望应用下一组排班，原实现空体不改分配
 * 3. confirmMission：旧存档已领任务（state=3 无 confirmed 字段）不重复发放
 *    ——原实现只判 confirmed，8-12 模板迁移存档会重复发奖 + dailyPoint 无限累积
 */

const excelMock = vi.hoisted(() => ({
  default: {
    BuildingData: {
      goldItems: { "3003": 500 },
      laborRecoverTime: 360,
      buffs: {},
      chars: {},
      manufactData: { phases: [{ speed: 1, outputCapacity: 24 }] },
      meetingData: { phases: [{ friendSlotInc: 10, maxVisitorNum: 10, gatheringSpeed: 100 }] },
      hireData: { phases: [{ resSpeed: 100, refreshTimes: 3 }] },
      manufactFormulas: {},
      rooms: {
        TRADING: { phases: [{ buildCost: { items: [], time: 0, labor: 10 }, maxStationedNum: 1 }] },
        MANUFACTURE: { phases: [{ buildCost: { items: [], time: 0, labor: 10 }, maxStationedNum: 1 }] },
      },
    },
    MissionTable: {
      missions: {
        "daily_claimed": { id: "daily_claimed", type: "DAILY", periodicalPoint: 5 },
        "daily_pending": { id: "daily_pending", type: "DAILY", periodicalPoint: 5 },
      },
      periodicalRewards: {},
    },
    ActivityTable: { missionData: [] },
  },
}));
vi.mock("@excel/excel", () => excelMock);
const timeMock = vi.hoisted(() => ({ now: 1787000000 }));
vi.mock("@utils/time", () => ({ now: () => timeMock.now }));
vi.mock("@game/manager/PlayerDataManager", () => ({ PlayerDataManager: vi.fn() }));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { BuildingManager } from "@game/manager/building";
import { MissionManager } from "@game/manager/mission";

function baseBuilding(): any {
  return {
    status: {
      labor: { buffSpeed: 0, processPoint: 0, value: 100, lastUpdateTime: 1000, maxValue: 100 },
      workshop: { bonusActive: 0, bonus: {} },
    },
    chars: {},
    roomSlots: {},
    rooms: {
      CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
      CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {}, TRAINING: {}, PRIVATE: {},
    },
    furniture: {}, diyPresetSolutions: {}, assist: [-1, -1, -1], solution: { furnitureTs: {} }, music: {},
  };
}

function makePlayer(building: any, extra: any = {}) {
  const mockPlayer = mockPlayerData({
    building,
    event: { building: 0 },
    pushFlags: {},
    status: { uid: "1", gold: 1000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
    inventory: { "3003": 10 },
    troop: { chars: {}, charGroup: {} },
    ...extra,
  });
  const mockTrigger = mockTypedEventEmitter();
  mockPlayer._trigger = mockTrigger;
  mockPlayer.update = vi.fn().mockImplementation(async (recipe: any) => {
    const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
    const result = await recipe(draft);
    Object.assign(mockPlayer._playerdata, draft);
    return result;
  });
  return { mockPlayer, mockTrigger };
}

describe("deliveryBatchOrder 请求字段变体兼容", () => {
  let mockPlayer: any, mockTrigger: any, manager: BuildingManager;

  function withStock() {
    const b = baseBuilding();
    b.rooms.TRADING.slot_6 = {
      state: 1,
      stock: [
        { instId: 1, delivery: [{ id: "3003", type: "MATERIAL", count: 2 }], type: "O_GOLD", gain: { id: "4001", type: "GOLD", count: 1000 }, buff: [] },
      ],
      stockLimit: 10, strategy: "O_GOLD", lastUpdateTime: 1000,
    };
    ({ mockPlayer, mockTrigger } = makePlayer(b));
    manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
  }

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("官方字段 slotList 正常交付", async () => {
    withStock();
    await manager.deliveryBatchOrder({ slotList: ["slot_6"] } as any);
    expect(mockPlayer._playerdata.status!.gold).toBe(2000);
    expect(mockPlayer._playerdata.building.rooms.TRADING.slot_6.stock).toEqual([]);
  });

  it("变体 slotIdList 同样交付（防客户端字段名不同）", async () => {
    withStock();
    await manager.deliveryBatchOrder({ slotIdList: ["slot_6"] } as any);
    expect(mockPlayer._playerdata.status!.gold).toBe(2000);
  });

  it("变体 roomSlotIdList 同样交付", async () => {
    withStock();
    await manager.deliveryBatchOrder({ roomSlotIdList: ["slot_6"] } as any);
    expect(mockPlayer._playerdata.status!.gold).toBe(2000);
  });

  it("单值 slotId 兼容", async () => {
    withStock();
    await manager.deliveryBatchOrder({ slotId: "slot_6" } as any);
    expect(mockPlayer._playerdata.status!.gold).toBe(2000);
  });

  it("空字段不 500（无订单可交付）", async () => {
    withStock();
    const res = await manager.deliveryBatchOrder({} as any);
    expect(res).toEqual({});
    expect(mockPlayer._playerdata.status!.gold).toBe(1000); // 未交付
  });
});

describe("batchChangeWorkChar 预设队列轮换", () => {
  let mockPlayer: any, mockTrigger: any, manager: BuildingManager;

  beforeEach(() => {
    vi.restoreAllMocks();
    const b = baseBuilding();
    b.roomSlots.slot_5 = { level: 3, state: 2, roomId: "MANUFACTURE", charInstIds: [1, 2], completeConstructTime: -1 };
    b.rooms.MANUFACTURE.slot_5 = { presetQueue: [[3, 4], [5, 6]] };
    ({ mockPlayer, mockTrigger } = makePlayer(b));
    manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
  });

  it("仅指定 roomSlotId（无干员列表）：当前排班不在队列 → 应用第一组", async () => {
    // 客户端"换班"按钮：只带房间、不带排班 → 服务端轮换预设队列
    await manager.batchChangeWorkChar({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.charInstIds).toEqual([3, 4]);
  });

  it("仅指定 roomSlotId：已在队列 → 轮换到下一组（循环）", async () => {
    await manager.batchChangeWorkChar({ roomSlotId: "slot_5" } as any); // → [3,4]
    await manager.batchChangeWorkChar({ roomSlotId: "slot_5" } as any); // → [5,6]
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.charInstIds).toEqual([5, 6]);
    await manager.batchChangeWorkChar({ roomSlotId: "slot_5" } as any); // → 回第一组 [3,4]
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.charInstIds).toEqual([3, 4]);
  });

  it("完全空请求体（无房间信息）不改分配（不 500）", async () => {
    await manager.batchChangeWorkChar({} as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.charInstIds).toEqual([1, 2]);
  });

  it("无预设队列时仅带 roomSlotId 不改分配", async () => {
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5 = {};
    await manager.batchChangeWorkChar({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.charInstIds).toEqual([1, 2]);
  });

  it("显式 charInstIdList 仍直接应用（不改轮换）", async () => {
    await manager.batchChangeWorkChar({ roomSlotId: "slot_5", charInstIdList: [7, 8] } as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.charInstIds).toEqual([7, 8]);
  });
});

describe("confirmMission 旧存档已领任务不重复发放", () => {
  it("state=3 无 confirmed 字段的任务（8-12 模板迁移）不重复发奖", async () => {
    const mission = {
      missions: {
        DAILY: {
          "daily_claimed": { state: 3, progress: [{ value: 1, target: 1 }] }, // 已领但无 confirmed
        },
      },
      missionRewards: { dailyPoint: 10, weeklyPoint: 0, rewards: { DAILY: {}, WEEKLY: {} } },
      missionGroups: {},
    };
    const { mockPlayer, mockTrigger } = makePlayer(baseBuilding(), { mission });
    const manager = new MissionManager(mockPlayer as any, mockTrigger as any);
    const items = await manager.confirmMission({ missionId: "daily_claimed" } as any);
    expect(items).toEqual([]);
    // dailyPoint 不重复累积
    expect(mockPlayer._playerdata.mission!.missionRewards.dailyPoint).toBe(10);
    expect(mockPlayer._playerdata.mission!.missions.DAILY["daily_claimed"].state).toBe(3);
  });

  it("state=2 进度满无 confirmed → 正常发放置 3", async () => {
    const mission = {
      missions: {
        DAILY: {
          "daily_pending": { state: 2, progress: [{ value: 1, target: 1 }] },
        },
      },
      missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: { DAILY: {}, WEEKLY: {} } },
      missionGroups: {},
    };
    const { mockPlayer, mockTrigger } = makePlayer(baseBuilding(), { mission });
    const manager = new MissionManager(mockPlayer as any, mockTrigger as any);
    await manager.confirmMission({ missionId: "daily_pending" } as any);
    expect(mockPlayer._playerdata.mission!.missions.DAILY["daily_pending"].state).toBe(3);
    expect(mockPlayer._playerdata.mission!.missionRewards.dailyPoint).toBe(5);
  });
});
