import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => {
  return {
    default: {},
  };
});

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
