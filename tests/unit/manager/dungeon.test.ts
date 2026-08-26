import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock excel 数据表,提供 DungeonManager 依赖的最小数据
vi.mock("@excel/excel", () => {
  return {
    default: {
      // 关卡表:提供若干测试关卡
      StageTable: {
        stages: {
          stage_001: {
            stageId: "stage_001",
            stageType: "MAIN",
            code: "0-1",
            name: "测试关卡1",
          },
          stage_002: {
            stageId: "stage_002",
            stageType: "MAIN",
            code: "0-2",
            name: "测试关卡2",
          },
          stage_003: {
            stageId: "stage_003",
            stageType: "ACTIVITY",
            code: "ACT-1",
            name: "活动关卡1",
          },
        },
        runeStageGroups: {},
        mapThemes: {},
        tileInfo: {},
        forceOpenTable: {},
        timelyStageDropInfo: {},
        overrideDropInfo: {},
        overrideUnlockInfo: {},
        timelyTable: {},
        stageValidInfo: {},
        stageFogInfo: {},
        stageStartConds: {},
        diffGroupTable: {},
        storyStageShowGroup: {},
        specialBattleFinishStageData: {},
        recordRewardData: {},
        apProtectZoneInfo: {},
        antiSpoilerDict: {},
        actCustomStageDatas: {},
        spNormalStageIdFor4StarList: [],
        storylines: {},
        storylineStorySets: {},
        storylineTags: {},
        storylineConst: {},
        cgGalleryDisplays: {},
        cgGalleryGroups: {},
        cgGalleryCgs: {},
        sixStarRuneData: {},
        sixStarMilestoneInfo: {},
      },
    },
  };
});

vi.mock("@game/service/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

vi.mock("@utils/time", () => ({
  now: () => 1234567890,
}));

vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));


import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { DungeonManager } from "@game/service/manager/dungeon";

/**
 * DungeonManager 单元测试
 * 覆盖关卡初始化、事件监听注册、增量更新等核心功能
 */
describe("DungeonManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();

    mockPlayer = mockPlayerData({
      dungeon: {
        stages: {},
        cowLevel: {},
        hideStages: {},
        mainlineBannedStages: [],
      },
    });

    mockPlayer._trigger = mockTrigger;
    // 重写 update 实现,使其在 draft 上执行 recipe 并同步回 _playerdata
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
    it("应该正确初始化实例并注册 stage:update 事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      const manager = new DungeonManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
      // 应注册 stage:update 事件监听
      expect(onSpy).toHaveBeenCalledWith(
        "stage:update",
        expect.any(Function)
      );
    });
  });

  describe("initStages", () => {
    it("应该将 excel 中所有缺失的关卡初始化到玩家关卡数据中", async () => {
      const manager = new DungeonManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // 初始 stages 为空对象
      expect(Object.keys(mockPlayer._playerdata.dungeon!.stages)).toEqual([]);

      await manager.initStages();

      // 应填充全部 3 个测试关卡
      const stages = mockPlayer._playerdata.dungeon!.stages;
      expect(Object.keys(stages).length).toBe(3);
      expect(stages["stage_001"]).toBeDefined();
      expect(stages["stage_002"]).toBeDefined();
      expect(stages["stage_003"]).toBeDefined();
    });

    it("初始化的关卡应使用固定的默认值", async () => {
      const manager = new DungeonManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.initStages();

      const stage = mockPlayer._playerdata.dungeon!.stages["stage_001"];
      // 验证默认字段值
      expect(stage.stageId).toBe("stage_001");
      expect(stage.completeTimes).toBe(1);
      expect(stage.startTimes).toBe(1);
      expect(stage.practiceTimes).toBe(0);
      expect(stage.state).toBe(3);
      expect(stage.hasBattleReplay).toBe(0);
      expect(stage.noCostCnt).toBe(0);
    });

    it("不应该覆盖玩家已有的关卡数据", async () => {
      const manager = new DungeonManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // 预先存在一个 stage_001,带有自定义数据
      mockPlayer._playerdata.dungeon!.stages["stage_001"] = {
        stageId: "stage_001",
        completeTimes: 99,
        startTimes: 88,
        practiceTimes: 7,
        state: 1,
        hasBattleReplay: 1,
        noCostCnt: 5,
      };

      await manager.initStages();

      // 已有的 stage_001 数据不应被覆盖
      const stage = mockPlayer._playerdata.dungeon!.stages["stage_001"];
      expect(stage.completeTimes).toBe(99);
      expect(stage.startTimes).toBe(88);
      expect(stage.practiceTimes).toBe(7);
      // 但缺失的 stage_002、stage_003 应被新增
      expect(
        mockPlayer._playerdata.dungeon!.stages["stage_002"]
      ).toBeDefined();
      expect(
        mockPlayer._playerdata.dungeon!.stages["stage_003"]
      ).toBeDefined();
    });
  });

  describe("update", () => {
    it("调用 update 应该等价于调用 initStages", async () => {
      const manager = new DungeonManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const initSpy = vi.spyOn(manager, "initStages");
      await manager.update();

      expect(initSpy).toHaveBeenCalledTimes(1);
      // 应填充全部 3 个测试关卡
      expect(
        Object.keys(mockPlayer._playerdata.dungeon!.stages).length
      ).toBe(3);
    });
  });

  describe("stage:update 事件", () => {
    it("触发 stage:update 事件应自动调用 initStages 初始化关卡", async () => {
      new DungeonManager(mockPlayer as any, mockTrigger as any);

      // 初始为空
      expect(Object.keys(mockPlayer._playerdata.dungeon!.stages)).toEqual([]);

      // 通过事件触发 update -> initStages
      await mockTrigger.emit("stage:update", []);

      // 应已初始化关卡
      expect(
        Object.keys(mockPlayer._playerdata.dungeon!.stages).length
      ).toBe(3);
      expect(
        mockPlayer._playerdata.dungeon!.stages["stage_001"]
      ).toBeDefined();
    });
  });
});
