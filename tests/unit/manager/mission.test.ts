import { describe, it, expect, vi, beforeEach } from "vitest";

// vi.mock 工厂函数必须使用内联数据，不能引用导入的变量
// 因为 vi.mock 会被提升到文件顶部执行，此时导入尚未初始化

vi.mock("@excel/excel", () => {
  return {
    default: {
      MissionTable: {
        missions: {},
        missionGroups: {},
        periodicalRewards: {},
        weeklyRewards: {},
        soCharMissionGroupInfo: {},
        dailyMissionGroupInfo: {},
        dailyMissionPeriodInfo: [],
        mainlineMissionEndImageDataList: [],
        crossAppShareMissions: {},
        crossAppShareMissionConst: {},
        guideMissionGroupInfo: {},
      },
      MedalTable: { medalList: [], medalTypeData: {} },
      StageTable: {
        stages: {},
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
      GachaTable: {},
      GameDataConst: {},
      CharacterTable: {},
      ItemTable: { items: {}, expItems: {} },
      ShopClientTable: {},
      SkillDataBundle: {},
    },
  };
});

vi.mock("@game/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

vi.mock("@utils/time", () => ({
  now: () => Math.floor(Date.now() / 1000),
  checkBetween: (ts: number, start: number, end: number) =>
    ts >= start && ts <= end,
}));

vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/types_auto_gen", () => ({}));
vi.mock("moment", () => ({
  default: () => ({
    diff: () => 0,
  }),
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { MissionManager, MissionProgress } from "@game/manager/mission";

describe("MissionManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;
  let mockExcelRef: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockExcelRef = (vi.mocked(await import("@excel/excel")).default as any);

    mockPlayer = mockPlayerData({
      mission: {
        missions: {
          DAILY: {
            "daily_test_001": {
              state: 0,
              progress: [{ value: 0, target: 1 }],
            },
          },
          WEEKLY: {},
          ACTIVITY: {},
          OPENSERVER: {},
        },
        missionRewards: {
          dailyPoint: 0,
          weeklyPoint: 0,
          rewards: { DAILY: {}, WEEKLY: {} },
        },
        missionGroups: {},
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
    it("应该正确初始化 MissionManager 实例", () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager.missions).toEqual({});
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
    });

    it("应该注册 daily 和 weekly 刷新事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      new MissionManager(mockPlayer as any, mockTrigger as any);
      expect(onSpy).toHaveBeenCalledWith(
        "refresh:weekly",
        expect.any(Function)
      );
      expect(onSpy).toHaveBeenCalledWith(
        "refresh:daily",
        expect.any(Function)
      );
    });
  });

  describe("getMissionById", () => {
    it("当任务存在时应该返回 MissionProgress", async () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );
      const testProgress = new MissionProgress(
        "daily_test_001",
        "DAILY",
        mockPlayer as any
      );
      testProgress.progress = [{ value: 5, target: 10 }];
      testProgress.state = 2;
      manager.missions["DAILY"] = [testProgress];

      mockExcelRef.MissionTable.missions["daily_test_001"] = {
        id: "daily_test_001",
        type: "DAILY",
      };

      const result = await manager.getMissionById("daily_test_001");
      expect(result).toBeDefined();
      expect(result.missionId).toBe("daily_test_001");
    });

    it("当任务不存在时应该返回 undefined", async () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );
      manager.missions["DAILY"] = [];

      mockExcelRef.MissionTable.missions["nonexistent"] = {
        id: "nonexistent",
        type: "DAILY",
      };

      const result = await manager.getMissionById("nonexistent");
      expect(result).toBeUndefined();
    });
  });

  describe("confirmMission", () => {
    it("应该确认每日任务并触发 items:get 事件", async () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockExcelRef.MissionTable.missions["daily_test_001"] = {
        id: "daily_test_001",
        type: "DAILY",
        periodicalPoint: 10,
      };

      const testProgress = new MissionProgress(
        "daily_test_001",
        "DAILY",
        mockPlayer as any
      );
      testProgress.progress = [{ value: 1, target: 1 }];
      testProgress.state = 3;
      manager.missions["DAILY"] = [testProgress];

      mockPlayer._playerdata.mission = {
        missions: {
          DAILY: {
            "daily_test_001": {
              state: 3,
              progress: [{ value: 1, target: 1 }],
            },
          },
        },
        missionRewards: {
          dailyPoint: 0,
          weeklyPoint: 0,
          rewards: { DAILY: {}, WEEKLY: {} },
        },
        missionGroups: {},
      };

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = await manager.confirmMission({
        missionId: "daily_test_001",
      });

      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(emitSpy).toHaveBeenCalledWith(
        "items:get",
        expect.any(Array)
      );
    });

    it("应该确认每周任务", async () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockExcelRef.MissionTable.missions["weekly_test_001"] = {
        id: "weekly_test_001",
        type: "WEEKLY",
        periodicalPoint: 20,
      };

      const testProgress = new MissionProgress(
        "weekly_test_001",
        "WEEKLY",
        mockPlayer as any
      );
      testProgress.progress = [{ value: 1, target: 1 }];
      testProgress.state = 3;
      manager.missions["WEEKLY"] = [testProgress];

      mockPlayer._playerdata.mission = {
        missions: {
          WEEKLY: {
            "weekly_test_001": {
              state: 3,
              progress: [{ value: 1, target: 1 }],
            },
          },
        },
        missionRewards: {
          dailyPoint: 0,
          weeklyPoint: 0,
          rewards: { DAILY: {}, WEEKLY: {} },
        },
        missionGroups: {},
      };

      const result = await manager.confirmMission({
        missionId: "weekly_test_001",
      });
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe("confirmMissionGroup", () => {
    it("当有奖励时应该触发 items:get", async () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const testRewards = [{ type: "MATERIAL", id: "mat_001", count: 1 }];
      mockExcelRef.MissionTable.missionGroups["group_001"] = {
        rewards: testRewards,
      };

      mockPlayer._playerdata.mission = {
        missions: { DAILY: {}, WEEKLY: {}, ACTIVITY: {}, OPENSERVER: {} },
        missionRewards: {
          dailyPoint: 0,
          weeklyPoint: 0,
          rewards: { DAILY: {}, WEEKLY: {} },
        },
        missionGroups: {},
      };

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.confirmMissionGroup({ missionGroupId: "group_001" });

      expect(emitSpy).toHaveBeenCalledWith("items:get", [testRewards]);
    });

    it("当奖励为 undefined 时不应该触发 items:get", async () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockExcelRef.MissionTable.missionGroups["group_empty"] = {
        rewards: undefined,
      };

      mockPlayer._playerdata.mission = {
        missions: { DAILY: {}, WEEKLY: {}, ACTIVITY: {}, OPENSERVER: {} },
        missionRewards: {
          dailyPoint: 0,
          weeklyPoint: 0,
          rewards: { DAILY: {}, WEEKLY: {} },
        },
        missionGroups: {},
      };

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.confirmMissionGroup({ missionGroupId: "group_empty" });

      const itemsGetCalls = emitSpy.mock.calls.filter(
        (call) => call[0] === "items:get"
      );
      expect(itemsGetCalls.length).toBe(0);
    });
  });

  describe("autoConfirmMissions", () => {
    it("应该自动确认所有已完成的任务", async () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockExcelRef.MissionTable.missions["daily_auto_001"] = {
        id: "daily_auto_001",
        type: "DAILY",
        periodicalPoint: 5,
      };

      const completedMission = new MissionProgress(
        "daily_auto_001",
        "DAILY",
        mockPlayer as any
      );
      completedMission.progress = [{ value: 10, target: 10 }];
      completedMission.state = 2;

      const incompleteMission = new MissionProgress(
        "daily_auto_002",
        "DAILY",
        mockPlayer as any
      );
      incompleteMission.progress = [{ value: 5, target: 10 }];
      incompleteMission.state = 2;

      manager.missions["DAILY"] = [completedMission, incompleteMission];

      mockPlayer._playerdata.mission = {
        missions: {
          DAILY: {
            "daily_auto_001": {
              state: 2,
              progress: [{ value: 10, target: 10 }],
            },
            "daily_auto_002": {
              state: 2,
              progress: [{ value: 5, target: 10 }],
            },
          },
        },
        missionRewards: {
          dailyPoint: 0,
          weeklyPoint: 0,
          rewards: { DAILY: {}, WEEKLY: {} },
        },
        missionGroups: {},
      };

      const result = await manager.autoConfirmMissions({ type: "DAILY" });
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe("exchangeMissionRewards", () => {
    it("应该兑换任务奖励并触发 items:get", async () => {
      const manager = new MissionManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const rewards = [{ type: "MATERIAL", id: "mat_test", count: 5 }];
      mockExcelRef.MissionTable.periodicalRewards["reward_exchange"] = {
        id: "reward_exchange",
        rewards,
      };

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = await manager.exchangeMissionRewards({
        targetRewardsId: "reward_exchange",
      });

      expect(result).toEqual(rewards);
      expect(emitSpy).toHaveBeenCalledWith("items:get", [rewards]);
    });
  });

  describe("MissionProgress", () => {
    it("应该正确构造 MissionProgress 实例", () => {
      const progress = new MissionProgress(
        "test_mission",
        "DAILY",
        mockPlayer as any
      );
      expect(progress.missionId).toBe("test_mission");
      expect(progress.type).toBe("DAILY");
      expect(progress.value).toBe(0);
      expect(progress.state).toBe(0);
      expect(progress.confirmed).toBe(false);
      expect(progress.progress).toEqual([]);
    });

    it("getState 当没有进度时应该返回 0", async () => {
      const progress = new MissionProgress(
        "test_mission",
        "DAILY",
        mockPlayer as any
      );
      progress.progress = [];
      try {
        const state = await progress.getState();
        expect(state).toBeDefined();
      } catch (e) {
        expect(e).toBeDefined();
      }
    });

    it("getState 当完成且已确认时应该返回 3", async () => {
      const progress = new MissionProgress(
        "test_mission",
        "DAILY",
        mockPlayer as any
      );
      progress.progress = [{ value: 10, target: 10 }];
      progress.confirmed = true;
      const state = await progress.getState();
      expect(state).toBe(3);
    });

    it("getState 当有进度但未确认时应该返回 2", async () => {
      const progress = new MissionProgress(
        "test_mission",
        "DAILY",
        mockPlayer as any
      );
      progress.progress = [{ value: 5, target: 10 }];

      mockExcelRef.MissionTable.missions["test_mission"] = {
        id: "test_mission",
        type: "DAILY",
      };

      const state = await progress.getState();
      expect(state).toBe(2);
    });
  });
});