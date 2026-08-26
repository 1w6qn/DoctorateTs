import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * BuildingManager 基建系统完整性测试
 *
 * 覆盖 2026-08 审计修复：
 * - 协议字段别名（CS 字段名 → 服务端兼容）：settleSale roomSlotIdList /
 *   changeSaleSolution roomSlotId+targetFormulaId / workshopDecomposition furniId+times /
 *   线索 clueId / receiveClueToStock clues
 * - 房间管理：buildRoom 资源校验 + 房间对象创建、completeUpgradeRoom 完成建造、
 *   upgradeRoom/degradeRoom 等级边界
 * - 干员：assignChar 训练室通用定位、setPrivateDormOwner 双端同步
 * - 生产：贸易站按 stockLimit 补单、changeDiySolution 服务端计算舒适度
 * - 事件接线：GainIntimacy / UpgradeSpecialization / BuildingManufactureProductTimes /
 *   BuildingWorkshopSynthesisGroupByID / DiyComfort
 * - 会客室：auto 操作 pushFlags、dailyRefresh 周切、changeBGM inUse
 */

// Excel BuildingData 样本（真实结构 + 家具舒适度/主题 + 多级房间相位）
const excelMock = vi.hoisted(() => ({
  default: {
    BuildingData: {
      manufactFormulas: {
        "1": { formulaId: "1", itemId: "2001", count: 1, costPoint: 2700, formulaType: "F_EXP", costs: [] },
        "4": { formulaId: "4", itemId: "3003", count: 1, costPoint: 4320, formulaType: "F_GOLD", costs: [] },
      },
      workshopFormulas: {
        "1": {
          formulaId: "1", itemId: "3131", count: 1, goldCost: 800, apCost: 360000,
          formulaType: "F_BUILDING", buffType: "W_BUILDING",
          costs: [{ id: "3112", count: 2, type: "MATERIAL" }],
          extraOutcomeRate: 0.1,
          extraOutcomeGroup: [{ weight: 100, itemId: "3112", itemCount: 1 }],
        },
      },
      rooms: {
        MANUFACTURE: {
          phases: [
            { buildCost: { items: [{ id: "3131", count: 1, type: "MATERIAL" }], time: 0, labor: 10 }, maxStationedNum: 1, electricity: -10 },
            { buildCost: { items: [{ id: "3132", count: 2, type: "MATERIAL" }], time: 0, labor: 20 }, maxStationedNum: 2, electricity: -30 },
            { buildCost: { items: [{ id: "3133", count: 3, type: "MATERIAL" }], time: 0, labor: 30 }, maxStationedNum: 3, electricity: -60 },
          ],
        },
        TRADING: {
          phases: [
            { buildCost: { items: [], time: 0, labor: 10 }, maxStationedNum: 1, electricity: -10 },
          ],
        },
        POWER: {
          phases: [
            { buildCost: { items: [{ id: "3131", count: 1, type: "MATERIAL" }], time: 0, labor: 10 }, maxStationedNum: 1, electricity: 60 },
            { buildCost: { items: [{ id: "3132", count: 3, type: "MATERIAL" }], time: 0, labor: 60 }, maxStationedNum: 1, electricity: 130 },
            { buildCost: { items: [{ id: "3133", count: 5, type: "MATERIAL" }], time: 0, labor: 120 }, maxStationedNum: 1, electricity: 270 },
          ],
        },
        WORKSHOP: {
          phases: [
            { buildCost: { items: [], time: 0, labor: 10 }, maxStationedNum: 1, electricity: -10 },
          ],
        },
      },
      workshopBonus: {
        "char_4019_ncdeer": ["ws_bonus1_40", "ws_bonus2_80"],
      },
      meetingData: {
        phases: [
          { friendSlotInc: 10, maxVisitorNum: 10, gatheringSpeed: 100 },
          { friendSlotInc: 20, maxVisitorNum: 10, gatheringSpeed: 100 },
          { friendSlotInc: 35, maxVisitorNum: 10, gatheringSpeed: 100 },
        ],
      },
      creditGuaranteed: 10,
      creditPassiveLimit: 100,
      creditInitiativeLimit: 100,
      creditCeiling: 50,
      buffs: {
        "workshop_formula_bonus1[000]": {
          buffId: "workshop_formula_bonus1[000]", roomType: "WORKSHOP",
          targets: ["F_BUILDING", "F_EVOLVE", "F_SKILL", "F_ASC"],
        },
        "workshop_formula_bonus2[000]": {
          buffId: "workshop_formula_bonus2[000]", roomType: "WORKSHOP",
          targets: ["F_BUILDING", "F_EVOLVE", "F_SKILL", "F_ASC"],
        },
      },
      manpowerDisplayFactor: 360000,
      customData: {
        furnitures: {
          furni_sofa_01: { id: "furni_sofa_01", comfort: 100, themeId: "furni_set_office", processedProductId: "30013", processedProductCount: 5 },
          furni_lamp_01: { id: "furni_lamp_01", comfort: 50, themeId: "furni_set_office", processedProductId: "30012", processedProductCount: 2 },
          furni_plant_01: { id: "furni_plant_01", comfort: 30, themeId: "furni_set_garden", processedProductId: "30014", processedProductCount: 3 },
        },
      },
      goldItems: { "3003": 500 },
      laborRecoverTime: 360,
      basicFavorPerDay: 720,
      apToLaborRatio: 2,
      manufactReduceTimeUnit: 180,
      tradingReduceTimeUnit: 180,
    },
  },
}));
vi.mock("@excel/excel", () => excelMock);

vi.mock("@game/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

vi.mock("@utils/time", () => ({
  now: () => 1234567890,
}));

vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { BuildingManager } from "@game/modules/building/logic";
import { accountManager } from "@game/manager/AccountManager";

/** 构造带指定 building 的 mock 玩家 */
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

/** 基础 building 结构（空房间 + 两个槽位 + 发电站） */
function baseBuilding(): any {
  return {
    status: { labor: { buffSpeed: 0, processPoint: 0, value: 100, lastUpdateTime: 0, maxValue: 225 }, workshop: { bonusActive: 0, bonus: {} } },
    chars: {},
    roomSlots: {
      slot_5: { level: 1, state: 2, roomId: "MANUFACTURE", charInstIds: [-1, -1], completeConstructTime: -1 },
      slot_6: { level: 1, state: 2, roomId: "TRADING", charInstIds: [-1], completeConstructTime: -1 },
      slot_24: { level: 3, state: 2, roomId: "POWER", charInstIds: [-1], completeConstructTime: -1 },
    },
    rooms: {
      CONTROL: {}, ELEVATOR: {}, POWER: {
        slot_24: { state: 2 },
      }, MANUFACTURE: {
        slot_5: { state: 1, formulaId: "4", remainSolutionCnt: 10, outputSolutionCnt: 0, processPoint: 0, lastUpdateTime: 0, completeWorkTime: -1, capacity: 24 },
      }, TRADING: {}, CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
      TRAINING: {}, PRIVATE: {},
    },
    furniture: {},
    diyPresetSolutions: {},
    assist: [-1, -1, -1],
    solution: { furnitureTs: {} },
    music: { inUse: false, selected: "bgm_default", state: {} },
  };
}

describe("BuildingManager 协议字段别名（CS → 服务端兼容）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    ({ mockPlayer, mockTrigger } = makePlayer(baseBuilding(), {
      status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
      inventory: { "3003": 10, "3112": 10, "3131": 10 },
      troop: { chars: {}, charGroup: {} },
    }));
  });

  it("settleSale 兼容 CS roomSlotIdList（数组）", async () => {
    mockPlayer._playerdata.building.rooms.TRADING.slot_6 = {
      state: 1, stock: [
        { instId: 1, delivery: [{ id: "3003", type: "MATERIAL", count: 2 }], type: "O_GOLD", gain: { id: "4001", type: "GOLD", count: 1000 }, buff: [] },
      ], stockLimit: 10, strategy: "O_GOLD", lastUpdateTime: 0,
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.settleSale({ roomSlotIdList: ["slot_6"] } as any);
    expect(mockPlayer._playerdata.building.rooms.TRADING.slot_6.stock).toEqual([]);
    expect(mockPlayer._playerdata.inventory!["3003"]).toBe(8); // 10 - 2
    expect(mockPlayer._playerdata.status!.gold).toBe(11000);
  });

  it("changeSaleSolution 兼容 CS roomSlotId/targetFormulaId/solutionCount", async () => {
    mockPlayer._playerdata.building.rooms.TRADING.slot_6 = { state: 1, stock: [], stockLimit: 10, strategy: "O_GOLD", lastUpdateTime: 0 };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.changeSaleSolution({ roomSlotId: "slot_6", targetFormulaId: "O_LMD", solutionCount: 8 } as any);
    const room = mockPlayer._playerdata.building.rooms.TRADING.slot_6;
    expect(room.strategy).toBe("O_LMD");
    expect(room.stockLimit).toBe(8);
  });

  it("workshopDecomposition 兼容 CS furniId/times 且按家具配置产出", async () => {
    mockPlayer._playerdata.building.furniture = {
      furni_sofa_01: { count: 3, inUse: 1 },
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.workshopDecomposition({ furniId: "furni_sofa_01", times: 2 } as any);
    // processedProductId=30013 × processedProductCount=5 × 2 次
    expect(mockPlayer._playerdata.building.furniture.furni_sofa_01.count).toBe(1);
    expect(mockPlayer._playerdata.inventory!["30013"]).toBe(10);
  });

  it("线索操作兼容 CS clueId（sendClue/receiveClueToStock/putClueToTheBoard/deleteOwnClue/deleteReceiveClue）", async () => {
    mockPlayer._playerdata.building.rooms.MEETING.room_001 = {
      ownStock: [{ id: "clue_own", type: "RHINE", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 0 }],
      receiveStock: [{ id: "clue_recv", type: "PENGUIN", number: 2, uid: "2", name: "B", nickNum: "1", chars: [], inUse: 0 }],
      board: {},
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.sendClue({ clueId: "clue_own", friendId: "2" } as any);
    let room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.receiveStock).toHaveLength(2); // 原 own → receive
    await manager.receiveClueToStock({ clues: ["clue_recv"] } as any);
    room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.ownStock).toHaveLength(1); // clue_recv 回到 own
    await manager.putClueToTheBoard({ clueId: "clue_recv" } as any);
    room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    // 修复：board 键为阵营（原实现键为线索 id）；线索保留库存 inUse=1
    expect(room.board["PENGUIN"]).toBe("clue_recv");
    expect(room.ownStock.find((c: any) => c.id === "clue_recv").inUse).toBe(1);
    // 取回线索（takeClueFromBoard 按阵营）→ board 条目删除、inUse 复位
    await manager.takeClueFromBoard({ type: "PENGUIN" } as any);
    room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.board["PENGUIN"]).toBeUndefined();
    expect(room.ownStock.find((c: any) => c.id === "clue_recv").inUse).toBe(0);
    await manager.deleteOwnClue({ clueId: "clue_recv" } as any);
    await manager.deleteReceiveClue({ clueId: "clue_own" } as any);
    room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.ownStock).toHaveLength(0);
    expect(room.receiveStock).toHaveLength(0);
  });
});

describe("BuildingManager 房间管理完整性", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    ({ mockPlayer, mockTrigger } = makePlayer(baseBuilding(), {
      status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
      inventory: { "3131": 10, "3132": 10, "3133": 10 },
      troop: { chars: {}, charGroup: {} },
    }));
  });

  it("buildRoom 应创建 rooms[roomId][slotId] 房间对象", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.buildRoom({ roomSlotId: "slot_9", roomId: "MANUFACTURE" } as any);
    // slot_9 不在初始 roomSlots → 防御跳过（槽位不存在不建）
    expect(mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_9).toBeUndefined();
    // 已有槽位重建（房间类型切换）→ 创建新房间对象
    await manager.buildRoom({ roomSlotId: "slot_5", roomId: "MANUFACTURE" } as any);
    expect(mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5).toBeDefined();
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.state).toBe(1);
  });

  it("buildRoom 资源不足时应拒绝（不扣成负数）", async () => {
    mockPlayer._playerdata.inventory = { "3131": 0 };
    mockPlayer._playerdata.building.status.labor.value = 0;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.buildRoom({ roomSlotId: "slot_5", roomId: "MANUFACTURE" } as any);
    // 材料/劳动力都不足 → 不建造、不扣减
    expect(mockPlayer._playerdata.inventory!["3131"]).toBe(0);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.state).toBe(2); // 保持原状
  });

  it("completeUpgradeRoom 应完成 state=1 且超时的建造", async () => {
    mockPlayer._playerdata.building.roomSlots.slot_5.state = 1;
    mockPlayer._playerdata.building.roomSlots.slot_5.completeConstructTime = 1234567890 - 1; // 已到
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.completeUpgradeRoom();
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.state).toBe(2);
  });

  it("completeUpgradeRoom 不应完成未到期的建造", async () => {
    mockPlayer._playerdata.building.roomSlots.slot_5.state = 1;
    mockPlayer._playerdata.building.roomSlots.slot_5.completeConstructTime = 1234567890 + 100; // 未到
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.completeUpgradeRoom();
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.state).toBe(1);
  });

  it("upgradeRoom 目标等级越界时应钳制到最高可用等级", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.upgradeRoom({ roomSlotId: "slot_5", targetLevel: 99 } as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.level).toBe(3); // phases.length=3
  });

  it("degradeRoom 不应降到 1 以下", async () => {
    mockPlayer._playerdata.building.roomSlots.slot_5.level = 1;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.degradeRoom({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.level).toBe(1);
  });
});

describe("BuildingManager 干员分配完整性", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    const building = baseBuilding();
    building.roomSlots.slot_13 = { level: 3, state: 2, roomId: "TRAINING", charInstIds: [-1, -1], completeConstructTime: -1 };
    building.rooms.TRAINING.slot_13 = {
      trainee: { charInstId: -1, state: 0, targetSkill: -1, processPoint: 0, speed: 1000 },
      trainer: { charInstId: -1, state: 0 },
    };
    building.rooms.PRIVATE.slot_001 = { owners: [], comfort: 0, diySolution: { wallPaper: "", floor: "", carpet: [], other: [] } };
    ({ mockPlayer, mockTrigger } = makePlayer(building, {
      status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
      inventory: {},
      troop: { chars: {}, charGroup: {} },
    }));
    mockPlayer._playerdata.building.chars = {
      "1001": { charId: "char_001", ap: 8640000, lastApAddTime: 0, roomSlotId: "", index: -1, changeScale: 0, bubble: {}, workTime: 0, privateRooms: [] },
      "1002": { charId: "char_002", ap: 8640000, lastApAddTime: 0, roomSlotId: "", index: -1, changeScale: 0, bubble: {}, workTime: 0, privateRooms: [] },
    };
  });

  it("assignChar 训练室按房间类型定位（不硬编码 slot_13）", async () => {
    // 训练室在 slot_20（非 slot_13）——旧实现硬编码 slot_13 会漏同步
    mockPlayer._playerdata.building.roomSlots.slot_20 = { level: 3, state: 2, roomId: "TRAINING", charInstIds: [-1, -1], completeConstructTime: -1 };
    mockPlayer._playerdata.building.rooms.TRAINING.slot_20 = {
      trainee: { charInstId: -1, state: 0, targetSkill: -1, processPoint: 0, speed: 1000 },
      trainer: { charInstId: -1, state: 0 },
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.assignChar({ roomSlotId: "slot_20", charInstIdList: [1002, 1001] } as any);
    const room = mockPlayer._playerdata.building.rooms.TRAINING.slot_20;
    expect(room.trainer.charInstId).toBe(1002);
    expect(room.trainee.charInstId).toBe(1001);
    // speed 官方基础速度 1（修复前硬编码 1000 → processPoint 秒涨 1000，训练进度异常）
    expect(room.trainee.speed).toBe(1);
  });

  it("setPrivateDormOwner 双端同步（新 owner 加入 privateRooms、旧 owner 清除）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.setPrivateDormOwner({ slotId: "slot_001", charInsId: 1001 } as any);
    expect(mockPlayer._playerdata.building.rooms.PRIVATE.slot_001.owners).toEqual([1001]);
    expect(mockPlayer._playerdata.building.chars["1001"].privateRooms).toEqual(["slot_001"]);
    // 换 owner → 旧 owner 清除、新 owner 迁移
    await manager.setPrivateDormOwner({ slotId: "slot_001", charInsId: 1002 } as any);
    expect(mockPlayer._playerdata.building.rooms.PRIVATE.slot_001.owners).toEqual([1002]);
    expect(mockPlayer._playerdata.building.chars["1001"].privateRooms).toEqual([]);
    expect(mockPlayer._playerdata.building.chars["1002"].privateRooms).toEqual(["slot_001"]);
  });
});

describe("BuildingManager 生产/事件接线完整性", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    ({ mockPlayer, mockTrigger } = makePlayer(baseBuilding(), {
      status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
      inventory: { "3112": 10, "30012": 10 },
      troop: {
        chars: {
          "377": { charId: "char_1015_aglna2", skills: [{ skillId: "sk1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 }] },
        },
        charGroup: {},
      },
    }));
    // mockTypedEventEmitter 返回真实 TypedEventEmitter——把 emit 换成 spy 以便断言
    vi.spyOn(mockTrigger, "emit").mockResolvedValue(undefined);
  });

  it("gainIntimacy 应 emit GainIntimacy 事件（信赖任务推进）", async () => {
    mockPlayer._playerdata.troop.chars["100"] = { charId: "char_x", favorPoint: 0 } as any;
    mockPlayer._playerdata.troop.charGroup["char_x"] = { favorPoint: 0 } as any;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.gainIntimacy({ charInstId: 100 } as any);
    expect(mockTrigger.emit).toHaveBeenCalledWith("GainIntimacy", [{ count: 12 }]);
  });

  it("completeUpgradeSpecialization 应 emit UpgradeSpecialization 事件", async () => {
    mockPlayer._playerdata.building.rooms.TRAINING.slot_13 = {
      trainee: { charInstId: 377, state: 2, targetSkill: 0, processPoint: 100, speed: 1 },
      trainer: { charInstId: -1, state: 2 },
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.completeUpgradeSpecialization({} as any);
    expect(mockTrigger.emit).toHaveBeenCalledWith("UpgradeSpecialization", [{ targetLevel: 1 }]);
  });

  it("settleManufacture 应 emit BuildingManufactureProductTimes 勋章事件", async () => {
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5 = {
      state: 1, formulaId: "4", remainSolutionCnt: 73, outputSolutionCnt: 3,
      processPoint: 0, lastUpdateTime: 0, completeWorkTime: -1, capacity: 24,
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.settleManufacture({ roomSlotIdList: ["slot_5"] } as any);
    expect(mockTrigger.emit).toHaveBeenCalledWith("BuildingManufactureProductTimes", [{ count: 3 }]);
  });

  it("workshopSynthesis 应 emit BuildingWorkshopSynthesisGroupByID 勋章事件（formulaType 过滤）", async () => {
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.formulaId = "";
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.workshopSynthesis({ roomSlotId: "slot_5", times: 1, formulaId: "1" } as any);
    expect(mockTrigger.emit).toHaveBeenCalledWith("BuildingWorkshopSynthesisGroupByID", [{ groupId: "F_BUILDING" }]);
  });

  it("changeDiySolution 应服务端计算舒适度（家具 comfort 求和）并 emit DiyComfort", async () => {
    mockPlayer._playerdata.building.rooms.DORMITORY.slot_20 = { buff: {}, comfort: 0, diySolution: null };
    mockPlayer._playerdata.building.roomSlots.slot_20 = { level: 1, state: 2, roomId: "DORMITORY", charInstIds: [], completeConstructTime: -1 };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.changeDiySolution({
      roomSlotId: "slot_20",
      solution: {
        wallPaper: "furni_sofa_01", // 100
        floor: "",
        carpet: [{ id: "furni_lamp_01" }], // 50
        other: [{ id: "furni_plant_01" }], // 30
      },
    } as any);
    expect(mockPlayer._playerdata.building.rooms.DORMITORY.slot_20.comfort).toBe(180);
    expect(mockTrigger.emit).toHaveBeenCalledWith("DiyComfort", [{ comfort: 180 }]);
  });

  it("贸易站补单应尊重 stockLimit（不再恒补 2 单）", async () => {
    mockPlayer._playerdata.building.rooms.TRADING.slot_6 = {
      state: 1, stock: [], stockLimit: 5, strategy: "O_GOLD", lastUpdateTime: 0,
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.sync();
    const stock = mockPlayer._playerdata.building.rooms.TRADING.slot_6.stock;
    expect(stock.length).toBe(5);
  });
});

describe("BuildingManager 会客室/每日刷新完整性", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    const building = baseBuilding();
    building.rooms.MEETING.room_001 = {
      ownStock: [], receiveStock: [], board: {}, dailyReward: null,
      socialReward: { daily: 0, search: 0 },
      infoShare: { ts: 0, reward: 0 },
    };
    ({ mockPlayer, mockTrigger } = makePlayer(building, {
      status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
      inventory: {},
      troop: { chars: {}, charGroup: {} },
    }));
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [{ uid: "2", alias: "" }, { uid: "3", alias: "" }],
      friendRequests: [],
      visited: [],
    } as any);
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockResolvedValue({
      uid: "2", nickName: "B", nickNumber: "1", level: 1, secretary: "char_002_amiya",
      secretarySkinId: "", registerTs: 1000,
    } as any);
  });

  it("sendClueAuto 后线索转入 receiveStock（仍有待处理线索 → hasClues 保持）", async () => {
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    room.ownStock = [{ id: "clue_1", type: "RHINE", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 0 }];
    mockPlayer._playerdata.pushFlags.hasClues = 1;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.sendClueAuto({} as any);
    // update 替换 building 对象 → 重新读取
    const after = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(after.receiveStock).toHaveLength(1);
    expect(after.ownStock).toHaveLength(0);
    // 线索在 receiveStock 仍待处理 → 红点保留
    expect(mockPlayer._playerdata.pushFlags.hasClues).toBe(1);
  });

  it("putClueToTheBoardAuto 后应清除 pushFlags.hasClues（全部上板，无待处理）", async () => {
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    room.ownStock = [{ id: "clue_1", type: "RHINE", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 0 }];
    mockPlayer._playerdata.pushFlags.hasClues = 1;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.putClueToTheBoardAuto({} as any);
    // update 替换 building 对象 → 重新读取
    const after = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    // 修复：board 键为阵营（原实现键为线索 id）；线索保留库存 inUse=1
    expect(after.board["RHINE"]).toBe("clue_1");
    expect(after.ownStock).toHaveLength(1);
    expect(after.ownStock[0].inUse).toBe(1);
    expect(mockPlayer._playerdata.pushFlags.hasClues).toBe(0);
  });

  it("takeClueFromBoard 取回线索后 hasClues 恢复（未上板线索待处理）", async () => {
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    room.ownStock = [{ id: "clue_1", type: "RHINE", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 1 }];
    room.board = { RHINE: "clue_1" };
    mockPlayer._playerdata.pushFlags.hasClues = 0;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.takeClueFromBoard({ type: "RHINE" } as any);
    const after = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(after.board["RHINE"]).toBeUndefined();
    expect(after.ownStock[0].inUse).toBe(0);
    // 取回后为未上板线索 → 红点恢复
    expect(mockPlayer._playerdata.pushFlags.hasClues).toBe(1);
  });

  it("dailyRefresh 跨周应滚动 messageLeave.sp（lastWeek ← thisWeek）", async () => {
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    room.messageLeave = {
      inUse: true, lastVisitTs: 0, lastShowTs: 0,
      lastUpdateSpTs: 1234567890 - 7 * 86400, // 一周前
      sp: { lastWeek: 0, lastWeekSum: 0, thisWeek: 90, thisWeekSum: 90 },
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.dailyRefresh();
    // update 替换 building 对象 → 重新读取
    const sp = mockPlayer._playerdata.building.rooms.MEETING.room_001.messageLeave.sp;
    expect(sp.lastWeek).toBe(90); // thisWeek → lastWeek
    // 新一周：好友访问留言板累积（2 好友 × visitorBonus=30）→ thisWeek 从 0 重新累积
    expect(sp.thisWeek).toBe(60);
  });

  it("getInfoShareVisitorsNum 应返回好友数", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    const result = await manager.getInfoShareVisitorsNum();
    expect(result.num).toBe(2);
  });

  it("getRecentVisitors 应返回好友列表（结构对齐 RecentVisitor）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    const result = await manager.getRecentVisitors();
    expect(result.visitors).toHaveLength(2);
    expect(result.visitors[0]).toMatchObject({
      uid: "2", nickName: "B", secretary: "char_002_amiya", level: 1,
    });
  });

  it("changeBGM 应同步 music.inUse", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.changeBGM({ musicId: "bgm_new" } as any);
    expect(mockPlayer._playerdata.building.music.selected).toBe("bgm_new");
    expect(mockPlayer._playerdata.building.music.inUse).toBe(true);
  });
});

describe("BuildingManager 电力系统（发电站供给/建造升级校验）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    ({ mockPlayer, mockTrigger } = makePlayer(baseBuilding(), {
      status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
      inventory: { "3131": 10, "3132": 10, "3133": 10 },
      troop: { chars: {}, charGroup: {} },
    }));
  });

  it("电力充足时应允许建造（POWER 供给 > 消耗）", async () => {
    // 余额 = 270（POWER lv3）- 10（MANUFACTURE lv1）- 10（TRADING lv1）= 250
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.buildRoom({ roomSlotId: "slot_5", roomId: "MANUFACTURE" } as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.state).toBe(1);
  });

  it("电力不足时应拒绝建造（新房间耗电使余额为负）", async () => {
    // 关闭发电站（POWER lv1 = +60）→ 余额 = 60 - 10 - 10 = 40；
    // 再建一个 MANUFACTURE（-10）→ 40 - 10 = 30 ≥ 0 仍可建……
    // 直接降 POWER 到 lv1 且已有 4 个 MANUFACTURE 场景由 upgradeRoom 校验覆盖；
    // 此处构造余额 < 新房间耗电：把 POWER 移除（roomId 置空 → 不发电）
    mockPlayer._playerdata.building.roomSlots.slot_24.roomId = "ELEVATOR"; // 0 电
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.buildRoom({ roomSlotId: "slot_7", roomId: "TRADING" } as any);
    // slot_7 不存在 → 防御跳过；改测 slot_5 换建 TRADING：余额 = -20，TRADING -10 → 拒绝
    await manager.buildRoom({ roomSlotId: "slot_5", roomId: "TRADING" } as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.roomId).toBe("MANUFACTURE"); // 未换建
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.state).toBe(2);
  });

  it("upgradeRoom 电力增量校验：发电站升级可供给更多电力，耗电房间升级受限", async () => {
    // 余额 250：slot_5 MANUFACTURE lv1 → lv3（-10 → -60，增量 -50）→ 250-50 ≥ 0 允许
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.upgradeRoom({ roomSlotId: "slot_5", targetLevel: 3 } as any);
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.level).toBe(3);
    // 移除发电站（POWER → ELEVATOR 0 电）：余额 = -60 - 10 = -70
    mockPlayer._playerdata.building.roomSlots.slot_24.roomId = "ELEVATOR";
    await manager.degradeRoom({ roomSlotId: "slot_5" } as any); // lv3 → lv2（-30），余额 -40
    await manager.upgradeRoom({ roomSlotId: "slot_5", targetLevel: 3 } as any);
    // 升级回 lv3：-40 - (-30) + (-60) = -70 < 0 → 拒绝
    expect(mockPlayer._playerdata.building.roomSlots.slot_5.level).toBe(2);
  });
});

describe("BuildingManager 加工站经济（心情消耗 + ws_bonus）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    const building = baseBuilding();
    building.roomSlots.slot_32 = { level: 3, state: 2, roomId: "WORKSHOP", charInstIds: [9001], completeConstructTime: -1 };
    building.rooms.WORKSHOP.slot_32 = { state: 2 };
    building.chars = {
      "9001": { charId: "char_4019_ncdeer", ap: 360000 * 5, lastApAddTime: 0, roomSlotId: "slot_32", index: 0, changeScale: -65, bubble: {}, workTime: 0, privateRooms: [] },
    };
    ({ mockPlayer, mockTrigger } = makePlayer(building, {
      status: { uid: "1", gold: 100000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
      inventory: { "3112": 100 },
      troop: { chars: {}, charGroup: {} },
    }));
    // workshopSynthesis 内部 emit（WorkshopSynthesis/WorkshopExBonus）需要 spy
    vi.spyOn(mockTrigger, "emit").mockResolvedValue(undefined);
  });

  it("workshopSynthesis 应扣减进驻干员心情（apCost/次，1 点 = 360000 raw AP）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    // formula 1: apCost 360000 = 1 心情点/次；合成 2 次 → 扣 2 点
    await manager.workshopSynthesis({ roomSlotId: "slot_32", times: 2, formulaId: "1" } as any);
    const ch = mockPlayer._playerdata.building.chars["9001"];
    expect(ch.ap).toBe(360000 * 3); // 5 - 2
  });

  it("workshopSynthesis 心情不足时应按可承担次数合成（不扣成负）", async () => {
    mockPlayer._playerdata.building.chars["9001"].ap = 360000; // 只剩 1 点
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    const result = await manager.workshopSynthesis({ roomSlotId: "slot_32", times: 5, formulaId: "1" } as any);
    expect(result).toEqual({ type: "MATERIAL", id: "3131", count: 1 }); // 只合成 1 次
    const ch = mockPlayer._playerdata.building.chars["9001"];
    expect(ch.ap).toBe(0);
  });

  it("ws_bonus 逐次合成累计点数（bonus[bonusId]=[cur,total]），满格后 bonusActive=1", async () => {
    // 初始 [16, 40] → 合成 24 次后满格（24 次 × 1 心情点 = 24 点 = 满心情 8640000）
    mockPlayer._playerdata.building.status.workshop = { bonusActive: 0, bonus: { ws_bonus1_40: [16, 40] } };
    mockPlayer._playerdata.building.chars["9001"].ap = 8640000;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.workshopSynthesis({ roomSlotId: "slot_32", times: 24, formulaId: "1" } as any);
    const ws = mockPlayer._playerdata.building.status.workshop;
    expect(ws.bonus.ws_bonus1_40).toEqual([40, 40]); // 满格
    expect(ws.bonusActive).toBe(1); // 已蓄力
  });

  it("ws_bonus 蓄力后下一次合成必定产出副产物并重置计数", async () => {
    mockPlayer._playerdata.building.status.workshop = { bonusActive: 1, bonus: { ws_bonus1_40: [40, 40] } };
    // formula 1 extraOutcomeGroup 唯一项 3112×1 → 必定 +1
    vi.spyOn(Math, "random").mockReturnValue(0.99); // 概率副产物不触发（仅蓄力必定）
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.workshopSynthesis({ roomSlotId: "slot_32", times: 1, formulaId: "1" } as any);
    expect(mockPlayer._playerdata.inventory!["3112"]).toBe(99); // 100 - 2 消耗 + 1 副产物
    const ws = mockPlayer._playerdata.building.status.workshop;
    expect(ws.bonusActive).toBe(0); // 蓄力已消耗
    expect(ws.bonus.ws_bonus1_40).toEqual([0, 40]); // 计数重置
  });

  it("ws_bonus 计数仅匹配配方类型（targets 过滤）", async () => {
    mockPlayer._playerdata.building.status.workshop = { bonusActive: 0, bonus: { ws_bonus1_40: [39, 40] } };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    // formula 1 formulaType=F_BUILDING ∈ targets → 计数推进满格
    await manager.workshopSynthesis({ roomSlotId: "slot_32", times: 1, formulaId: "1" } as any);
    expect(mockPlayer._playerdata.building.status.workshop.bonusActive).toBe(1);
  });
});

describe("BuildingManager 会客室信用经济（socialReward 循环）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    const building = baseBuilding();
    building.roomSlots.slot_36 = { level: 3, state: 2, roomId: "MEETING", charInstIds: [-1, -1], completeConstructTime: -1 };
    building.rooms.MEETING.room_001 = {
      ownStock: [], receiveStock: [], board: {}, dailyReward: null,
      socialReward: { daily: 0, search: 0 },
      infoShare: { ts: 0, reward: 0 },
    };
    ({ mockPlayer, mockTrigger } = makePlayer(building, {
      status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 50, nickName: "A", nickNumber: "1" },
      inventory: {},
      troop: { chars: {}, charGroup: {} },
    }));
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [{ uid: "2", alias: "" }, { uid: "3", alias: "" }],
      friendRequests: [],
      visited: [],
    } as any);
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockResolvedValue({
      uid: "2", nickName: "B", nickNumber: "1", level: 1, secretary: "char_002_amiya",
      secretarySkinId: "", registerTs: 1000,
    } as any);
    vi.spyOn(accountManager, "getPlayerData").mockResolvedValue(mockPlayer as any);
  });

  it("dailyRefresh 应按宿舍氛围结算当日被动信用（Cd=10+⌊Ad/125⌋，每间≤50）", async () => {
    // 2026-08-23 模型：被动信用改为宿舍氛围每日结算（取代好友数×friendSlotInc）
    const b = mockPlayer._playerdata.building;
    b.rooms.DORMITORY.room_d1 = { comfort: 5000 }; // 10+40 = 50（封顶）
    b.rooms.DORMITORY.room_d2 = { comfort: 2500 }; // 10+20 = 30
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.dailyRefresh();
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.socialReward.daily).toBe(80);
  });

  it("宿舍结算信用应封顶（每间≤50，全天≤200；覆盖昨日未领值）", async () => {
    // dailyRefresh 写入的是当日结算值（覆盖，非累加）；无宿舍时结算 0 并封顶归零
    mockPlayer._playerdata.building.rooms.MEETING.room_001.socialReward = { daily: 90, search: 0 };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.dailyRefresh();
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.socialReward.daily).toBe(0); // 无宿舍 → 当日结算 0（覆盖昨日 90）
  });

  it("getInfoShareReward 应按访客数累积主动信用（search，封顶 creditInitiativeLimit）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.getInfoShareReward();
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.socialReward.search).toBe(70); // 2 访客 × 35
    // 领取后清零 → 可再次累积（信用经济循环）
    await manager.getMeetingroomReward();
    // update 替换 building 对象 → 重新读取
    const after = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(after.socialReward.search).toBe(0);
  });

  it("getInfoShareReward 主动信用应封顶 creditInitiativeLimit（100）", async () => {
    mockPlayer._playerdata.building.rooms.MEETING.room_001.socialReward = { daily: 0, search: 90 };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.getInfoShareReward();
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.socialReward.search).toBe(100); // 90 + 70 → 封顶 100
  });

  it("visitBuilding 访问方获得信用（+30/次，每日≤10 次），不再给被访方发 passive 信用", async () => {
    // 2026-08-24 C 类好友访问信用：访问开启线索交流的好友基建 → 访问方 +30 信用
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.visitBuilding({ friendId: "2" } as any);
    expect(mockPlayer._playerdata.status!.socialPoint).toBe(80); // 50 + 30
    const st = mockPlayer._playerdata.status as any;
    expect(st.visitCreditCount).toBe(1);
    // 被访方（自己）的被动信用不受影响（无宿舍结算时为 0）
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.socialReward.daily).toBe(0);
  });

  it("getMeetingroomReward 应领取 daily+search 并清零（可持续循环）", async () => {
    mockPlayer._playerdata.building.rooms.MEETING.room_001.socialReward = { daily: 35, search: 35 };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    const res = await manager.getMeetingroomReward();
    expect(res.rewards).toEqual([{ id: "SOCIAL_PT", type: "SOCIAL_PT", count: 70 }]);
    expect(mockPlayer._playerdata.status!.socialPoint).toBe(120);
    const room = mockPlayer._playerdata.building.rooms.MEETING.room_001;
    expect(room.socialReward).toEqual({ daily: 0, search: 0 });
  });
});
