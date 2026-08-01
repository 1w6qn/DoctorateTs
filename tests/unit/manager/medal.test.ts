import { describe, it, expect, vi, beforeEach } from "vitest";

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
  default: () => ({ diff: () => 0 }),
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { MedalManager, MedalProgress } from "@game/manager/medal";

describe("MedalManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;
  let mockExcelRef: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockExcelRef = (vi.mocked(await import("@excel/excel")).default as any);

    mockPlayer = mockPlayerData({
      medal: {
        medals: {
          "medal_test_001": {
            id: "medal_test_001",
            val: [[50, 100]],
            rts: 0,
            fts: 0,
            reward: "",
          },
          "medal_test_002": {
            id: "medal_test_002",
            val: [[100, 100]],
            rts: 1234567890,
            fts: 1234567890,
            reward: "rewarded",
          },
        },
        custom: {
          currentIndex: "0",
          customs: {},
        },
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
    it("应该正确初始化 MedalManager 实例", () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager.medals).toEqual({});
      expect(manager._playerdata).toBe(mockPlayer._playerdata);
      expect(manager.custom).toBeDefined();
    });

    it("应该注册 medal:complete 事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      new MedalManager(mockPlayer._playerdata as any, mockTrigger as any);
      expect(onSpy).toHaveBeenCalledWith(
        "medal:complete",
        expect.any(Function)
      );
    });
  });

  describe("init", () => {
    it("应该初始化勋章进度实例", async () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );

      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_test_001",
          template: "PlayerLevel",
          unlockParam: ["100"],
          medalRewardGroup: [],
        },
        {
          medalId: "medal_test_002",
          template: "PlayerLevel",
          unlockParam: ["100"],
          medalRewardGroup: [],
        },
      ];

      await manager.init();

      expect(Object.keys(manager.medals).length).toBe(2);
      expect(manager.medals["medal_test_001"]).toBeDefined();
      expect(manager.medals["medal_test_002"]).toBeDefined();
    });
  });

  describe("setCustomData", () => {
    it("应该设置自定义展示数据", () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );

      const customData = { layout: "grid", positions: [0, 1, 2] };
      manager.setCustomData({ index: "1", data: customData as any });

      expect(manager.custom.currentIndex).toBe("1");
      expect(manager.custom.customs["1"]).toEqual(customData);
    });

    it("应该覆盖已存在的自定义数据", () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );

      manager.setCustomData({ index: "0", data: { layout: "list" } as any });
      expect(manager.custom.currentIndex).toBe("0");
      expect(manager.custom.customs["0"]).toEqual({ layout: "list" });
    });
  });

  describe("rewardMedal", () => {
    it("当勋章存在于 medals 中时应该设置 rts 并触发 items:get", () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );

      const medalItems = [{ type: "FURN", id: "furn_001", count: 1 }];
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_test_001",
          template: "PlayerLevel",
          unlockParam: ["100"],
          medalRewardGroup: [
            { groupId: "group_001", itemList: medalItems },
          ],
        },
      ];

      manager.medals["medal_test_001"] = new MedalProgress(
        {
          id: "medal_test_001",
          val: [[50, 100]],
          rts: 0,
          fts: 0,
          reward: "",
        } as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = manager.rewardMedal({
        medalId: "medal_test_001",
        group: "group_001",
      });

      expect(result).toEqual(medalItems);
      expect(emitSpy).toHaveBeenCalledWith("items:get", [medalItems]);
      expect(manager.medals["medal_test_001"].rts).toBeGreaterThan(0);
    });

    it("当勋章不在 medals 中时应该从 playerdata 设置 rts", () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );

      const medalItems = [{ type: "DIAMOND", id: "4002", count: 1 }];
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_test_002",
          template: "PlayerLevel",
          unlockParam: ["100"],
          medalRewardGroup: [
            { groupId: "group_002", itemList: medalItems },
          ],
        },
      ];

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = manager.rewardMedal({
        medalId: "medal_test_002",
        group: "group_002",
      });

      expect(result).toEqual(medalItems);
      expect(emitSpy).toHaveBeenCalledWith("items:get", [medalItems]);
      expect(
        mockPlayer._playerdata.medal!.medals["medal_test_002"].rts
      ).toBeGreaterThan(0);
    });
  });

  describe("onMedalComplete", () => {
    it("当勋章有奖励组时应该触发 rewardMedal", async () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );

      const rewardItems = [{ type: "FURN", id: "furn_test", count: 1 }];
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_test_001",
          template: "PlayerLevel",
          unlockParam: ["100"],
          medalRewardGroup: [
            { groupId: "default_group", itemList: rewardItems },
          ],
        },
      ];

      const rewardSpy = vi.spyOn(manager, "rewardMedal");
      await manager.onMedalComplete([{ medalId: "medal_test_001" }]);

      expect(rewardSpy).toHaveBeenCalledWith({
        medalId: "medal_test_001",
        group: "default_group",
      });
    });

    it("当勋章没有奖励组时不应该触发 rewardMedal", async () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );

      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_no_reward",
          template: "PlayerLevel",
          unlockParam: ["100"],
          medalRewardGroup: [],
        },
      ];

      const rewardSpy = vi.spyOn(manager, "rewardMedal");
      await manager.onMedalComplete([{ medalId: "medal_no_reward" }]);

      expect(rewardSpy).not.toHaveBeenCalled();
    });
  });

  describe("toJSON", () => {
    it("应该序列化勋章数据", () => {
      const manager = new MedalManager(
        mockPlayer._playerdata as any,
        mockTrigger as any
      );

      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "test_medal",
          template: "",
          unlockParam: ["100"],
          medalRewardGroup: [],
        },
      ];

      manager.medals["test_medal"] = new MedalProgress(
        {
          id: "test_medal",
          val: [[100, 100]],
          rts: 123,
          fts: 456,
          reward: "done",
        } as any,
        mockTrigger as any
      );

      const json = manager.toJSON();
      expect(json).toBeDefined();
      expect(json.medals).toBeDefined();
      expect(json.customs).toBeDefined();
    });
  });

  describe("MedalProgress", () => {
    it("应该正确构造 MedalProgress 实例", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "test_medal",
          template: "PlayerLevel",
          unlockParam: ["100"],
          medalRewardGroup: [],
        },
      ];

      const progress = new MedalProgress(
        {
          id: "test_medal",
          val: [[0, 100]],
          rts: 0,
          fts: 0,
          reward: "",
        } as any,
        mockTrigger as any
      );

      expect(progress.id).toBe("test_medal");
      expect(progress.rts).toBe(0);
      expect(progress.fts).toBe(0);
    });

    it("当 fts 为 0 时应该调用 init", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_init",
          template: "",
          unlockParam: ["100"],
          medalRewardGroup: [],
        },
      ];

      const onSpy = vi.spyOn(mockTrigger, "on");
      const progress = new MedalProgress(
        {
          id: "medal_init",
          val: [[0, 100]],
          rts: 0,
          fts: 0,
          reward: "",
        } as any,
        mockTrigger as any
      );

      expect(progress).toBeDefined();
    });

    it("PlayerLevel 模板应该正确初始化进度", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_level",
          template: "PlayerLevel",
          unlockParam: ["50"],
          medalRewardGroup: [],
        },
      ];

      const progress = new MedalProgress(
        {
          id: "medal_level",
          val: [[0, 50]],
          rts: 0,
          fts: 1,
          reward: "",
        } as any,
        mockTrigger as any
      );

      expect(progress.val[0]).toEqual([0, 50]);
    });

    it("PlayerLevel 模板 update 应该更新进度值", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_level",
          template: "PlayerLevel",
          unlockParam: ["50"],
          medalRewardGroup: [],
        },
      ];

      const progress = new MedalProgress(
        {
          id: "medal_level",
          val: [[0, 50]],
          rts: 0,
          fts: 1,
          reward: "",
        } as any,
        mockTrigger as any
      );

      progress.param = ["50"];
      progress.PlayerLevel({ level: 30 }, "update");
      expect(progress.val[0][0]).toBe(30);
    });

    it("toJSON 应该返回正确的序列化数据", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_json",
          template: "",
          unlockParam: ["100"],
          medalRewardGroup: [],
        },
      ];

      const progress = new MedalProgress(
        {
          id: "medal_json",
          val: [[75, 100]],
          rts: 1000,
          fts: 0,
          reward: "test",
        } as any,
        mockTrigger as any
      );

      const json = progress.toJSON();
      expect(json.id).toBe("medal_json");
      expect(json.val).toEqual([[75, 100]]);
    });
  });
});