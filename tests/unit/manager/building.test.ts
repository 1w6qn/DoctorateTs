import { describe, it, expect, vi, beforeEach } from "vitest";

// Excel BuildingData 样本（真实结构，制造/加工/房间/常量——任务 2-7 复用）
const excelMock = vi.hoisted(() => ({
  default: {
    BuildingData: {
      manufactFormulas: {
        "1": { formulaId: "1", itemId: "2001", count: 1, costPoint: 2700, formulaType: "F_EXP", costs: [] },
        "4": { formulaId: "4", itemId: "3003", count: 1, costPoint: 4320, formulaType: "F_GOLD", costs: [] },
        "5": {
          formulaId: "5", itemId: "3213", count: 1, costPoint: 1, formulaType: "F_ASC",
          costs: [
            { id: "3212", count: 2, type: "MATERIAL" },
            { id: "32001", count: 1, type: "MATERIAL" },
          ],
        },
        "13": {
          formulaId: "13", itemId: "3141", count: 1, costPoint: 3600, formulaType: "F_DIAMOND",
          costs: [
            { id: "30012", count: 2, type: "MATERIAL" },
            { id: "4001", count: 1600, type: "GOLD" },
          ],
        },
      },
      workshopFormulas: {
        "1": {
          formulaId: "1", itemId: "3131", count: 1, goldCost: 800, apCost: 360000,
          costs: [{ id: "3112", count: 2, type: "MATERIAL" }],
          extraOutcomeRate: 0.1,
          extraOutcomeGroup: [{ weight: 100, itemId: "3112", itemCount: 1 }],
        },
      },
      rooms: {
        MANUFACTURE: {
          phases: [
            {
              buildCost: { items: [{ id: "3131", count: 1, type: "MATERIAL" }], time: 0, labor: 10 },
              maxStationedNum: 1,
            },
            {
              buildCost: { items: [{ id: "3132", count: 2, type: "MATERIAL" }], time: 0, labor: 20 },
              maxStationedNum: 2,
            },
          ],
        },
        TRADING: {
          phases: [
            { buildCost: { items: [], time: 0, labor: 10 }, maxStationedNum: 1 },
          ],
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

// Mock 时间工具,返回固定时间戳便于断言
vi.mock("@utils/time", () => ({
  now: () => 1234567890,
}));

vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/types_auto_gen", () => ({}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { BuildingManager } from "@game/manager/building";
import { accountManager } from "@game/manager/AccountManger";

/**
 * BuildingManager 单元测试
 * 覆盖建筑同步、BGM 切换、宿舍归属、协助干员设置及 getter 访问器
 */
describe("BuildingManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();

    mockPlayer = mockPlayerData({
      building: {
        status: {
          labor: {
            buffSpeed: 0,
            processPoint: 0,
            value: 0,
            lastUpdateTime: 0,
            maxValue: 100,
          },
          workshop: {
            bonusActive: 0,
            bonus: {},
          },
        },
        chars: {},
        roomSlots: {},
        rooms: {
          CONTROL: {},
          ELEVATOR: {},
          POWER: {},
          MANUFACTURE: {},
          TRADING: {},
          CORRIDOR: {},
          WORKSHOP: {},
          DORMITORY: {},
          MEETING: {
            room_001: {
              buff: {} as any,
              state: 0,
              speed: 0,
              processPoint: 0,
              ownStock: [],
              receiveStock: [],
              board: {
                clue_001: "1",
                clue_002: "2",
              },
              socialReward: { daily: 0, search: 0 },
              dailyReward: null,
              expiredReward: 0,
              received: 0,
              infoShare: { ts: 12345, reward: 0 },
              lastUpdateTime: 0,
              mfc: {},
              completeWorkTime: 0,
              startApCounter: {},
              mustgetClue: [],
            },
          },
          HIRE: {},
          TRAINING: {},
          PRIVATE: {
            slot_001: {
              owners: [],
              comfort: 0,
              diySolution: {
                wallPaper: "",
                floor: "",
                carpet: [],
                other: [],
              },
            },
          },
        },
        furniture: {
          furn_001: { count: 1, inUse: 0 },
          furn_002: { count: 1, inUse: 0 },
          furn_003: { count: 2, inUse: 1 },
        },
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      },
      event: {
        building: 0,
      },
    });

    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  describe("constructor", () => {
    it("应该正确初始化并注册 building:char:init 事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
      expect(onSpy).toHaveBeenCalledWith(
        "building:char:init",
        expect.any(Function)
      );
    });
  });

  describe("boardInfo", () => {
    it("应该返回 MEETING 房间公告板的 clue 列表", () => {
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager.boardInfo).toEqual(["clue_001", "clue_002"]);
    });
  });

  describe("infoShare", () => {
    it("应该返回 MEETING 房间 infoShare 的时间戳", () => {
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager.infoShare).toBe(12345);
    });
  });

  describe("furnCnt", () => {
    it("应该返回家具总数", () => {
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager.furnCnt).toBe(3);
    });
  });

  describe("sync", () => {
    it("应该设置 event.building 为 now()+5000 并返回当前时间戳", async () => {
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.sync();

      // now() mock 为 1234567890,event.building 应为 1234567890 + 5000
      expect(mockPlayer._playerdata.event!.building).toBe(1234572890);
      expect(result).toBe(1234567890);
    });
  });

  describe("changeBGM", () => {
    it("应该更新选中 BGM ID", async () => {
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.changeBGM({ musicId: "bgm_new" });

      expect(mockPlayer._playerdata.building!.music.selected).toBe("bgm_new");
    });
  });

  describe("setPrivateDormOwner", () => {
    it("应该设置私人宿舍归属干员", async () => {
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.setPrivateDormOwner({
        slotId: "slot_001",
        charInstId: 1001,
      });

      expect(
        mockPlayer._playerdata.building!.rooms.PRIVATE["slot_001"].owners
      ).toEqual([1001]);
    });
  });

  describe("setBuildingAssist", () => {
    it("应该设置指定协助位置的干员", async () => {
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.setBuildingAssist({ type: 0, charInstId: 1001 });

      expect(mockPlayer._playerdata.building!.assist[0]).toBe(1001);
    });

    it("当干员已存在于协助列表时应该先清除原位置再设置新位置", async () => {
      const manager = new BuildingManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // 预设:1001 已在位置 0
      mockPlayer._playerdata.building!.assist = [1001, -1, -1];

      // 把 1001 移到位置 1
      await manager.setBuildingAssist({ type: 1, charInstId: 1001 });

      expect(mockPlayer._playerdata.building!.assist[0]).toBe(-1);
      expect(mockPlayer._playerdata.building!.assist[1]).toBe(1001);
    });
  });

  describe("building:char:init 事件", () => {
    it("触发 building:char:init 事件应该初始化建筑干员数据", async () => {
      new BuildingManager(mockPlayer as any, mockTrigger as any);

      const char = {
        instId: 1001,
        charId: "char_001",
        level: 1,
        exp: 0,
        evolvePhase: 0,
        potentialRank: 0,
        favorPoint: 0,
        mainSkillLvl: 1,
        gainTime: 0,
        voiceLan: "CN_MANDARIN",
      };
      await mockTrigger.emit("building:char:init", [char]);

      const buildingChar =
        mockPlayer._playerdata.building!.chars["1001"];
      expect(buildingChar).toBeDefined();
      expect(buildingChar.charId).toBe("char_001");
      expect(buildingChar.ap).toBe(8640000);
      expect(buildingChar.roomSlotId).toBe("");
      expect(buildingChar.index).toBe(-1);
      expect(buildingChar.bubble.normal.add).toBe(-1);
      expect(buildingChar.bubble.assist.add).toBe(-1);
      expect(buildingChar.workTime).toBe(0);
    });
  });
});

describe("BuildingManager 内部工具方法", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 0, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {},
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("_findRoomSlotIdByChar 应找到干员所在槽位", () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    mockPlayer._playerdata.building!.roomSlots = {
      slot_1: { level: 1, state: 2, roomId: "MANUFACTURE", charInstIds: [1001, -1], completeConstructTime: 0 } as any,
      slot_2: { level: 1, state: 2, roomId: "TRADING", charInstIds: [1002], completeConstructTime: 0 } as any,
    };
    expect(manager._findRoomSlotIdByChar(1001)).toBe("slot_1");
    expect(manager._findRoomSlotIdByChar(9999)).toBeUndefined();
  });

  it("_clearCharFromRooms 应从所有槽位移除指定干员", () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    mockPlayer._playerdata.building!.roomSlots = {
      slot_1: { level: 1, state: 2, roomId: "MANUFACTURE", charInstIds: [1001, 1002], completeConstructTime: 0 } as any,
      slot_2: { level: 1, state: 2, roomId: "TRADING", charInstIds: [1002], completeConstructTime: 0 } as any,
    };
    manager._clearCharFromRooms([1002]);
    expect(mockPlayer._playerdata.building!.roomSlots.slot_1.charInstIds).toEqual([1001, -1]);
    expect(mockPlayer._playerdata.building!.roomSlots.slot_2.charInstIds).toEqual([-1]);
  });

  it("_nextClueId 应生成未占用的递增线索 ID", () => {
    mockPlayer._playerdata.building!.rooms.MEETING = {
      room_001: {
        ownStock: [{ id: "clue_001", type: "clue_1", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 0 }],
        receiveStock: [],
      } as any,
    };
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    expect(manager._nextClueId()).toBe("clue_002");
  });
});

describe("BuildingManager 批量干员", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 0, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {
          slot_5: { level: 3, state: 2, roomId: "MANUFACTURE", charInstIds: [1001, 1002, 1003], completeConstructTime: 0 },
          slot_6: { level: 3, state: 2, roomId: "TRADING", charInstIds: [1004], completeConstructTime: 0 },
        },
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("batchChangeWorkChar 应替换指定房间的干员并清空旧位置", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.batchChangeWorkChar({
      roomSlotId: "slot_5",
      charInstIdList: [1004, 1005],
    } as any);
    expect(mockPlayer._playerdata.building!.roomSlots.slot_5.charInstIds).toEqual([1004, 1005]);
    expect(mockPlayer._playerdata.building!.roomSlots.slot_6.charInstIds).toEqual([-1]);
  });

  it("batchRestChar 应清空指定干员在所有房间的占用", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.batchRestChar({ charInstIdList: [1001, 1004] } as any);
    expect(mockPlayer._playerdata.building!.roomSlots.slot_5.charInstIds).toEqual([-1, 1002, 1003]);
    expect(mockPlayer._playerdata.building!.roomSlots.slot_6.charInstIds).toEqual([-1]);
  });

  it("cleanRoomSlot 应清空房间全部干员", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.cleanRoomSlot({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.building!.roomSlots.slot_5.charInstIds).toEqual([-1, -1, -1]);
  });
});

describe("BuildingManager 信赖系统", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 0, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {
          slot_5: { level: 3, state: 2, roomId: "MANUFACTURE", charInstIds: [1001, 1002], completeConstructTime: 0 },
        },
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [1003, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      troop: {
        chars: {
          "1001": { charId: "char_001", favorPoint: 100 } as any,
          "1002": { charId: "char_002", favorPoint: 200 } as any,
          "1003": { charId: "char_003", favorPoint: 300 } as any,
        },
        charGroup: {
          char_001: { favorPoint: 100 } as any,
          char_002: { favorPoint: 200 } as any,
          char_003: { favorPoint: 300 } as any,
        },
      } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("gainIntimacy 应给指定干员加信赖（同步 chars 与 charGroup）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.gainIntimacy({ charInstId: 1001 } as any);
    expect(mockPlayer._playerdata.troop!.chars["1001"].favorPoint).toBeGreaterThan(100);
    expect(mockPlayer._playerdata.troop!.charGroup.char_001.favorPoint).toBeGreaterThan(100);
    expect(mockPlayer._playerdata.troop!.chars["1002"].favorPoint).toBe(200);
  });

  it("gainAllIntimacy 应给全部工作干员加信赖", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.gainAllIntimacy({} as any);
    expect(mockPlayer._playerdata.troop!.chars["1001"].favorPoint).toBeGreaterThan(100);
    expect(mockPlayer._playerdata.troop!.chars["1002"].favorPoint).toBeGreaterThan(200);
    expect(mockPlayer._playerdata.troop!.chars["1003"].favorPoint).toBe(300);
  });

  it("gainAssistIntimacy 应给助战列表干员加信赖", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.gainAssistIntimacy({} as any);
    expect(mockPlayer._playerdata.troop!.chars["1003"].favorPoint).toBeGreaterThan(300);
  });
});

describe("BuildingManager 贸易站", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 0, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {},
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {
   slot_6: {
     strategy: "O_GOLD",
     stock: [
       {
         instId: 28207,
         delivery: [{ id: "3003", type: "MATERIAL", count: 3 }],
         type: "O_GOLD",
         gain: { id: "4001", type: "GOLD", count: 1500 },
         buff: [],
         isViolated: true,
       },
       {
         instId: 28208,
         delivery: [{ id: "3003", type: "MATERIAL", count: 4 }],
         type: "O_GOLD",
         gain: { id: "4001", type: "GOLD", count: 2000 },
         buff: [],
         isViolated: true,
       },
     ] as any,
     stockLimit: 6,
     completeWorkTime: 0,
   } as any,
 },
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      status: { gold: 1000 } as any,
      inventory: { "3003": 10 } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("settleSale 应按 delivery/gain 结算全部订单（扣 3003 加 4001 金币）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.settleSale({ slotId: "slot_6" } as any);
    expect(mockPlayer._playerdata.building!.rooms.TRADING.slot_6.stock).toEqual([]);
    // 消耗交付物 3003（3+4=7，初始 10 → 3）
    expect(mockPlayer._playerdata.inventory!["3003"]).toBe(3);
    // 收益按 gain（1500+2000=3500，初始 1000 → 4500）
    expect(mockPlayer._playerdata.status!.gold).toBe(4500);
  });

  it("changeSaleSolution 应更新策略与库存上限", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.changeSaleSolution({ slotId: "slot_6", solution: { strategy: "O_LMD", stockLimit: 8 } } as any);
    expect(mockPlayer._playerdata.building!.rooms.TRADING.slot_6.strategy).toBe("O_LMD");
    expect(mockPlayer._playerdata.building!.rooms.TRADING.slot_6.stockLimit).toBe(8);
  });

  it("deleteOrder 应移除指定订单（按 instId）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.deleteOrder({ slotId: "slot_6", orderId: 28207 } as any);
    expect(mockPlayer._playerdata.building!.rooms.TRADING.slot_6.stock).toHaveLength(1);
    expect(mockPlayer._playerdata.building!.rooms.TRADING.slot_6.stock[0].instId).toBe(28208);
  });

  it("accelerateOrder 应按 delivery/gain 结算指定订单", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.accelerateOrder({ slotId: "slot_6", orderId: 28207 } as any);
    expect(mockPlayer._playerdata.building!.rooms.TRADING.slot_6.stock).toHaveLength(1);
    expect(mockPlayer._playerdata.inventory!["3003"]).toBe(7); // 10 - 3
    expect(mockPlayer._playerdata.status!.gold).toBe(2500); // 1000 + 1500
  });

  it("accelerateSolution 应结算全部库存订单", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.accelerateSolution({ slotId: "slot_6" } as any);
    expect(mockPlayer._playerdata.building!.rooms.TRADING.slot_6.stock).toEqual([]);
    expect(mockPlayer._playerdata.status!.gold).toBe(4500);
  });
});

describe("BuildingManager 制造站（Excel 驱动）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 100, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {},
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, TRADING: {},
          MANUFACTURE: {
            slot_5: {
              state: 1,
              formulaId: "4",
              remainSolutionCnt: 73,
              outputSolutionCnt: 2,
              lastUpdateTime: 0,
              completeWorkTime: -1,
              capacity: 24,
            } as any,
          },
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      status: { gold: 10000 } as any,
      inventory: { "3212": 10, "32001": 5, "30012": 10 } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("settleManufacture F_GOLD（formulaId 4）应产出 3003×outputSolutionCnt 并重置状态", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.settleManufacture({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.inventory!["3003"]).toBe(2);
    expect(mockPlayer._playerdata.building!.rooms.MANUFACTURE.slot_5.state).toBe(0);
    expect(mockPlayer._playerdata.building!.rooms.MANUFACTURE.slot_5.formulaId).toBe("");
  });

  it("settleManufacture F_EXP（formulaId 1）应产出 2001", async () => {
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.formulaId = "1";
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.outputSolutionCnt = 3;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.settleManufacture({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.inventory!["2001"]).toBe(3);
  });

  it("settleManufacture F_ASC（formulaId 5）应产出 3213 并消耗 3212×2 + 32001×1", async () => {
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.formulaId = "5";
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.outputSolutionCnt = 1;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.settleManufacture({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.inventory!["3213"]).toBe(1);
    expect(mockPlayer._playerdata.inventory!["3212"]).toBe(8);
    expect(mockPlayer._playerdata.inventory!["32001"]).toBe(4);
  });

  it("settleManufacture F_DIAMOND（formulaId 13）应产出 3141 并扣金币 1600×n", async () => {
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.formulaId = "13";
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.outputSolutionCnt = 1;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.settleManufacture({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.inventory!["3141"]).toBe(1);
    expect(mockPlayer._playerdata.inventory!["30012"]).toBe(8);
    expect(mockPlayer._playerdata.status!.gold).toBe(8400);
  });

  it("settleManufacture 未知配方应跳过（不崩溃）", async () => {
    mockPlayer._playerdata.building.rooms.MANUFACTURE.slot_5.formulaId = "999";
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.settleManufacture({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.building!.rooms.MANUFACTURE.slot_5.state).toBe(0);
  });
});

describe("BuildingManager 加工分解与专精", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 0, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {},
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {
          furn_001: { count: 3, inUse: 1 },
        },
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      inventory: { "30012": 1 } as any,
      troop: {
        chars: {
          "1001": {
            charId: "char_001",
            skills: [{ skillId: "skill_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 }],
          } as any,
        },
      } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("workshopDecomposition 应分解家具并增加材料", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.workshopDecomposition({ furnitureId: "furn_001", count: 1 } as any);
    expect(mockPlayer._playerdata.building!.furniture.furn_001.count).toBe(2);
    expect(mockPlayer._playerdata.inventory!["30012"]).toBeGreaterThan(1);
  });

  it("upgradeSpecialization 应记录专精目标（state=1）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.upgradeSpecialization({ charInstId: 1001, targetSkill: 0 } as any);
    expect(mockPlayer._playerdata.troop!.chars["1001"].skills[0].state).toBe(1);
  });

  it("completeUpgradeSpecialization 应提升 specializeLevel 并复位", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.upgradeSpecialization({ charInstId: 1001, targetSkill: 0 } as any);
    await manager.completeUpgradeSpecialization({ charInstId: 1001, targetSkill: 0 } as any);
    const skill = mockPlayer._playerdata.troop!.chars["1001"].skills[0];
    expect(skill.specializeLevel).toBe(1);
    expect(skill.state).toBe(0);
    expect(skill.completeUpgradeTime).toBe(-1);
  });
});

describe("BuildingManager 加工站合成（Excel 驱动）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 100, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {},
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, TRADING: {},
          MANUFACTURE: { slot_5: { formulaId: "" } as any },
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      status: { gold: 10000 } as any,
      inventory: { "3112": 10 } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("workshopSynthesis 应按 workshopFormulas 扣材料/金币并产出", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    const result = await manager.workshopSynthesis({ roomSlotId: "slot_5", times: 1, formulaId: "1" } as any);
    expect(mockPlayer._playerdata.inventory!["3112"]).toBe(8); // 10 - 2
    expect(mockPlayer._playerdata.status!.gold).toBe(9200); // 10000 - 800
    expect(mockPlayer._playerdata.inventory!["3131"]).toBe(1);
    expect(result).toEqual({ type: "MATERIAL", id: "3131", count: 1 });
  });

  it("workshopSynthesis 副产物概率触发时额外产出（extraOutcomeGroup 加权）", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0.05); // < extraOutcomeRate 0.1
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.workshopSynthesis({ roomSlotId: "slot_5", times: 1, formulaId: "1" } as any);
    expect(mockPlayer._playerdata.inventory!["3112"]).toBe(9); // 10 - 2 + 副产物 1
  });

  it("workshopSynthesis 未知配方应跳过（不崩溃）", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    const result = await manager.workshopSynthesis({ roomSlotId: "slot_5", times: 1, formulaId: "999" } as any);
    expect(result).toBeNull();
    expect(mockPlayer._playerdata.inventory!["3112"]).toBe(10);
  });
});

describe("BuildingManager 线索系统", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 0, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {},
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {
            room_001: {
              ownStock: [],
              receiveStock: [],
              board: {},
              dailyReward: null,
              socialReward: { daily: 0, search: 0 },
              mustgetClue: [],
            } as any,
          }, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      status: { uid: "1", nickName: "A", nickNumber: "1" } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
    // getClueFriendList 依赖 accountManager
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({ friends: [], friendRequests: [], visited: [] } as any);
    vi.spyOn(accountManager, "getPlayerFriendInfo").mockResolvedValue({ uid: "2", nickName: "B", nickNumber: "1", level: 1 } as any);
  });

  it("getDailyClue 应获得一条每日线索", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.getDailyClue({} as any);
    const room = mockPlayer._playerdata.building!.rooms.MEETING.room_001;
    expect(room.ownStock).toHaveLength(1);
    expect(room.dailyReward).not.toBeNull();
  });

  it("getDailyClue 重复调用不应重复发线索", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.getDailyClue({} as any);
    await manager.getDailyClue({} as any);
    expect(mockPlayer._playerdata.building!.rooms.MEETING.room_001.ownStock).toHaveLength(1);
  });

  it("sendClue 应将线索从 ownStock 移到 receiveStock", async () => {
    mockPlayer._playerdata.building!.rooms.MEETING.room_001.ownStock = [
      { id: "clue_001", type: "clue_1", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 0 },
    ] as any;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.sendClue({ id: "clue_001", friendId: "2" } as any);
    const room = mockPlayer._playerdata.building!.rooms.MEETING.room_001;
    expect(room.ownStock).toHaveLength(0);
    expect(room.receiveStock).toHaveLength(1);
  });

  it("receiveClueToStock 应将接收的线索转入库存", async () => {
    mockPlayer._playerdata.building!.rooms.MEETING.room_001.receiveStock = [
      { id: "clue_001", type: "clue_1", number: 1, uid: "2", name: "B", nickNum: "1", chars: [], inUse: 0 },
    ] as any;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.receiveClueToStock({ id: "clue_001" } as any);
    const room = mockPlayer._playerdata.building!.rooms.MEETING.room_001;
    expect(room.receiveStock).toHaveLength(0);
    expect(room.ownStock).toHaveLength(1);
  });

  it("putClueToTheBoard 应放置线索到留言板", async () => {
    mockPlayer._playerdata.building!.rooms.MEETING.room_001.ownStock = [
      { id: "clue_001", type: "clue_1", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 0 },
    ] as any;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.putClueToTheBoard({ id: "clue_001" } as any);
    const room = mockPlayer._playerdata.building!.rooms.MEETING.room_001;
    expect(room.ownStock).toHaveLength(0);
    expect(Object.keys(room.board)).toContain("clue_001");
  });

  it("deleteOwnClue 应删除自己持有的线索", async () => {
    mockPlayer._playerdata.building!.rooms.MEETING.room_001.ownStock = [
      { id: "clue_001", type: "clue_1", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 0 },
    ] as any;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.deleteOwnClue({ id: "clue_001" } as any);
    expect(mockPlayer._playerdata.building!.rooms.MEETING.room_001.ownStock).toHaveLength(0);
  });

  it("getClueBox 应返回 ownStock 与 receiveStock 合并盒", async () => {
    mockPlayer._playerdata.building!.rooms.MEETING.room_001.ownStock = [
      { id: "clue_001", type: "clue_1", number: 1, uid: "1", name: "A", nickNum: "1", chars: [], inUse: 0 },
    ] as any;
    mockPlayer._playerdata.building!.rooms.MEETING.room_001.receiveStock = [
      { id: "clue_002", type: "clue_2", number: 1, uid: "2", name: "B", nickNum: "1", chars: [], inUse: 0 },
    ] as any;
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    const box = await manager.getClueBox();
    expect(box.box).toHaveLength(2);
  });

  it("getClueFriendList 应返回好友列表", async () => {
    vi.spyOn(accountManager, "getSocial").mockResolvedValue({
      friends: [{ uid: "2", alias: "" }],
      friendRequests: [],
      visited: [],
    } as any);
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    const result = await manager.getClueFriendList();
    expect(result.result).toHaveLength(1);
    expect(result.result[0].uid).toBe("2");
  });
});

describe("BuildingManager 预设队列", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: { labor: { buffSpeed: 0, processPoint: 0, value: 0, lastUpdateTime: 0, maxValue: 100 }, workshop: { bonusActive: 0, bonus: {} } },
        chars: {},
        roomSlots: {
          slot_5: { level: 3, state: 2, roomId: "MANUFACTURE", charInstIds: [-1, -1], completeConstructTime: 0 },
        },
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {}, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("addPresetQueue 应添加预设队列", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.addPresetQueue({
      roomSlotId: "slot_5",
      presetName: "金条班",
      charInstIdList: [1001, 1002],
    } as any);
    const queues = (mockPlayer._playerdata.building! as any).presetQueues;
    expect(Object.keys(queues)).toContain("slot_5");
    expect(queues.slot_5.name).toBe("金条班");
    expect(queues.slot_5.charInstIdList).toEqual([1001, 1002]);
  });

  it("deletePresetQueue 应删除预设队列", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.addPresetQueue({ roomSlotId: "slot_5", presetName: "A", charInstIdList: [1001] } as any);
    await manager.deletePresetQueue({ roomSlotId: "slot_5" } as any);
    expect((mockPlayer._playerdata.building! as any).presetQueues.slot_5).toBeUndefined();
  });

  it("usePresetQueue 应应用预设干员到房间", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.addPresetQueue({ roomSlotId: "slot_5", presetName: "A", charInstIdList: [1001, 1002] } as any);
    await manager.usePresetQueue({ roomSlotId: "slot_5" } as any);
    expect(mockPlayer._playerdata.building!.roomSlots.slot_5.charInstIds).toEqual([1001, 1002]);
  });

  it("changePresetName 应修改预设名称", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.addPresetQueue({ roomSlotId: "slot_5", presetName: "A", charInstIdList: [1001] } as any);
    await manager.changePresetName({ roomSlotId: "slot_5", presetName: "新名字" } as any);
    expect((mockPlayer._playerdata.building! as any).presetQueues.slot_5.name).toBe("新名字");
  });
});

describe("BuildingManager 劳动力与留言板奖励", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      building: {
        status: {
          labor: { buffSpeed: 0, processPoint: 0, value: 50, lastUpdateTime: 0, maxValue: 225 },
          workshop: { bonusActive: 0, bonus: {} },
        },
        chars: {},
        roomSlots: {},
        rooms: {
          CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
          CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {}, MEETING: {
            room_001: {
              board: { clue_001: "clue_001" },
              socialReward: { daily: 10, search: 5 },
              received: 0,
            } as any,
          }, HIRE: {},
          TRAINING: {}, PRIVATE: {},
        },
        furniture: {},
        diyPresetSolutions: {},
        assist: [-1, -1, -1],
        solution: { furnitureTs: {} },
        music: { selected: "bgm_default" },
      } as any,
      status: { gold: 1000, androidDiamond: 100 } as any,
      inventory: {} as any,
      event: { building: 0 },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("buyLabor 应消耗源石并增加劳动力", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.buyLabor({ buyCount: 1 } as any);
    expect(mockPlayer._playerdata.building!.status.labor.value).toBeGreaterThan(50);
    expect(mockPlayer._playerdata.status!.androidDiamond).toBeLessThan(100);
  });

  it("confirmMessageBoardReward 应发放信用点并标记已领取", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.confirmMessageBoardReward({} as any);
    const room = mockPlayer._playerdata.building!.rooms.MEETING.room_001;
    expect(room.received).toBe(1);
    expect(mockPlayer._playerdata.inventory!["3003"]).toBe(15);
  });

  it("confirmMessageBoardReward 重复领取不应重复发放", async () => {
    const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
    await manager.confirmMessageBoardReward({} as any);
    await manager.confirmMessageBoardReward({} as any);
    expect(mockPlayer._playerdata.inventory!["3003"]).toBe(15);
  });
});
