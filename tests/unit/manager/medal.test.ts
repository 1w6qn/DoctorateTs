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
            rts: -1,
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
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager.medals).toEqual({});
      expect(manager._playerdata).toBe(mockPlayer._playerdata);
      expect(manager.custom).toBeDefined();
    });

    it("应该注册 medal:complete 事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      new MedalManager(mockPlayer as any, mockTrigger as any);
      expect(onSpy).toHaveBeenCalledWith(
        "medal:complete",
        expect.any(Function)
      );
    });
  });

  describe("init", () => {
    it("应该初始化勋章进度实例", async () => {
      const manager = new MedalManager(
        mockPlayer as any,
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
        mockPlayer as any,
        mockTrigger as any
      );

      const customData = { layout: "grid", positions: [0, 1, 2] };
      manager.setCustomData({ index: "1", data: customData as any });

      expect(manager.custom.currentIndex).toBe("1");
      expect(manager.custom.customs["1"]).toEqual(customData);
    });

    it("应该覆盖已存在的自定义数据", () => {
      const manager = new MedalManager(
        mockPlayer as any,
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
        mockPlayer as any,
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
          // 修复：奖励领取需勋章已完成（进度达标）——原测试 val [[50,100]] 未完成，
          // rewardMedal 修复后按完成态校验返回 []
          val: [[100, 100]],
          rts: -1,
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
        mockPlayer as any,
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

      // 该勋章未领取（rts=-1）才允许发放奖励
      mockPlayer._playerdata.medal!.medals["medal_test_002"].rts = -1;
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

    it("勋章进度更新应经共享引用写入持久态（_playerdata.medal.medals[id].val）", async () => {
      const manager = new MedalManager(
        mockPlayer as any,
        mockTrigger as any
      );
      await manager.init();
      // beforeEach 的 medal_test_001 带 val:[[50,100]]——MedalProgress.val 与该数组共享引用
      const progress = manager.medals["medal_test_001"] as any;
      progress.param = ["50"];
      progress.PlayerLevel({ level: 30 }, "update");
      expect(progress.val[0][0]).toBe(30);
      // 原地更新即写回持久态（服务端落盘/读取依赖此共享引用机制）
      expect(
        (manager as any)._playerdata.medal.medals["medal_test_001"].val[0][0]
      ).toBe(30);
    });

    it("进度事件更新应显式写回持久态并标记脏（A1——不依赖共享引用隐式落盘）", async () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_test_001",
          template: "PlayerLevel",
          unlockParam: ["50"],
          medalRewardGroup: [],
        },
      ];
      const markDirtySpy = vi.spyOn(mockPlayer, "markDirty");
      const manager = new MedalManager(
        mockPlayer as any,
        mockTrigger as any
      );
      await manager.init();
      // 真实 TypedEventEmitter（Emittery）：emit 会调用 init() 订阅的进度处理函数
      await (mockTrigger as any).emit("PlayerLevel", [{ level: 30 }]);
      // 显式写回：持久态 val 同步（即使引用断链也会重链接）
      expect(
        (manager as any)._playerdata.medal.medals["medal_test_001"].val[0][0]
      ).toBe(30);
      // 显式标记脏：条件落盘不会漏掉 medal 进度更新
      expect(markDirtySpy).toHaveBeenCalled();
    });
  });

  describe("onMedalComplete", () => {
    it("当勋章有奖励组时应该触发 rewardMedal", async () => {
      const manager = new MedalManager(
        mockPlayer as any,
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
        mockPlayer as any,
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
        mockPlayer as any,
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

    it("JoinGameDays 模板应计算注册天数", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_days",
          template: "JoinGameDays",
          unlockParam: ["30"],
          medalRewardGroup: [],
        },
      ];
      const progress = new MedalProgress(
        { id: "medal_days", val: [[0, 30]], fts: 0, rts: -1, reward: "" } as any,
        mockTrigger as any
      );
      expect(progress.val[0][1]).toBe(30);
      progress.JoinGameDays({ registerTs: 100 }, "update");
      expect(progress.val[0][0]).toBeGreaterThanOrEqual(0);
    });

    it("CharNum 模板应记录干员数量", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_chnum",
          template: "CharNum",
          unlockParam: ["10"],
          medalRewardGroup: [],
        },
      ];
      const progress = new MedalProgress(
        { id: "medal_chnum", val: [[0, 10]], fts: 0, rts: -1, reward: "" } as any,
        mockTrigger as any
      );
      progress.CharNum({ curCharInstId: 8 }, "update");
      // 修复：实际干员数 = curCharInstId - 1（instId 从 1 递增）——原实现多算 1
      expect(progress.val[0][0]).toBe(7);
    });

    it("RecruitCount 模板应累加招募次数", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_recruit",
          template: "RecruitCount",
          unlockParam: ["5"],
          medalRewardGroup: [],
        },
      ];
      const progress = new MedalProgress(
        { id: "medal_recruit", val: [[0, 5]], fts: 0, rts: -1, reward: "" } as any,
        mockTrigger as any
      );
      progress.RecruitCount({}, "update");
      progress.RecruitCount({}, "update");
      expect(progress.val[0][0]).toBe(2);
    });

    it("GotChars 模板应累加获得干员数", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_got",
          template: "GotChars",
          unlockParam: ["3"],
          medalRewardGroup: [],
        },
      ];
      mockExcelRef.CharacterTable = { char_001: { rarity: 5 } };
      const progress = new MedalProgress(
        { id: "medal_got", val: [[0, 3]], fts: 0, rts: -1, reward: "" } as any,
        mockTrigger as any
      );
      progress.GotChars({ char: { charId: "char_001" } }, "update");
      expect(progress.val[0][0]).toBe(1);
    });

    it("CharEvolveCount 模板应累加精一数量", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_evolve",
          template: "CharEvolveCount",
          unlockParam: ["1"],
          medalRewardGroup: [],
        },
      ];
      const progress = new MedalProgress(
        { id: "medal_evolve", val: [[0, 1]], fts: 0, rts: -1, reward: "" } as any,
        mockTrigger as any
      );
      progress.CharEvolveCount({ char: { evolvePhase: 2 } }, "update");
      expect(progress.val[0][0]).toBe(1);
    });

    it("PassTower 模板应累加通关次数", () => {
      mockExcelRef.MedalTable.medalList = [
        {
          medalId: "medal_tower",
          template: "PassTower",
          unlockParam: ["2"],
          medalRewardGroup: [],
        },
      ];
      const progress = new MedalProgress(
        { id: "medal_tower", val: [[0, 2]], fts: 0, rts: -1, reward: "" } as any,
        mockTrigger as any
      );
      progress.PassTower({ count: 1 }, "update");
      progress.PassTower({ count: 1 }, "update");
      expect(progress.val[0][0]).toBe(2);
    });
  });

describe("Medal 核心修复", () => {
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;
  let mockExcelRef: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockExcelRef = (vi.mocked(await import("@excel/excel")).default as any);
    mockExcelRef.MedalTable.medalList = [
      {
        medalId: "medal_lv_1",
        template: "PlayerLevel",
        unlockParam: ["50"],
        medalRewardGroup: [
          { groupId: "g1", itemList: [{ id: "furn_1", count: 1, type: "FURN" }] },
        ],
      },
      {
        medalId: "medal_lv_2",
        template: "PlayerLevel",
        unlockParam: ["100"],
        medalRewardGroup: [],
      },
      {
        medalId: "medal_broken",
        template: "PlayerLevel",
        unlockParam: ["1"],
        medalRewardGroup: [],
      },
    ];
  });

  it("fts 非 0 但进度未满的勋章应注册进度监听", () => {
    const onSpy = vi.spyOn(mockTrigger, "on");
    new MedalProgress(
      { id: "medal_lv_1", val: [[30, 50]], fts: 1000, rts: -1, reward: "" } as any,
      mockTrigger as any,
    );
    expect(onSpy).toHaveBeenCalledWith("PlayerLevel", expect.any(Function));
  });

  it("进度已满的勋章不应注册监听", () => {
    const onSpy = vi.spyOn(mockTrigger, "on");
    new MedalProgress(
      { id: "medal_lv_1", val: [[50, 50]], fts: 1000, rts: -1, reward: "" } as any,
      mockTrigger as any,
    );
    expect(onSpy).not.toHaveBeenCalled();
  });

  it("val 缺失的勋章（旧数据）构造不应崩溃且回填持久态（共享引用防断链）", () => {
    const onSpy = vi.spyOn(mockTrigger, "on");
    const item: any = { id: "medal_broken", fts: 0, rts: -1, reward: "" };
    const progress = new MedalProgress(item, mockTrigger as any);
    // init 在共享引用上构建进度结构 [0, unlockParam]（unlockParam ["1"]）并回填 item.val
    expect(progress.val[0][0]).toBe(0);
    expect(progress.val[0][1]).toBe(1);
    // 回填到持久态并共享同一引用——进度原地更新不再断链
    expect(item.val).toBe(progress.val);
    progress.PlayerLevel({ level: 5 }, "update");
    expect(item.val[0][0]).toBe(5);
    expect(onSpy).toHaveBeenCalled();
  });

  it("val 缺失但有模板：init 构建的结构回填持久态（进度可持久化）", () => {
    mockExcelRef.MedalTable.medalList = [
      { medalId: "medal_a", template: "PlayerLevel", unlockParam: ["10"], medalRewardGroup: [] },
    ];
    const item: any = { id: "medal_a", fts: 0, rts: -1, reward: "" };
    const progress = new MedalProgress(item, mockTrigger as any);
    // init 在共享引用上构建 [0, target] 并回填 item.val
    expect(item.val).toBe(progress.val);
    expect(progress.val[0][0]).toBe(0);
    expect(progress.val[0][1]).toBe(10);
    // 更新进度 → 原地写共享引用 → 直接落入持久态
    progress.PlayerLevel({ level: 5 }, "update");
    expect(item.val[0][0]).toBe(5);
  });

  it("rewardMedal 已领取（rts != -1）不应重复发放", async () => {
    const pd: any = mockPlayerData({
      medal: {
        medals: {
          medal_lv_1: {
            id: "medal_lv_1",
            val: [[50, 50]],
            rts: 1234567890,
            fts: 1000,
            reward: "",
          },
        },
        custom: { currentIndex: "0", customs: {} },
      },
    });
    pd._trigger = mockTrigger;
    const manager = new MedalManager(pd as any, mockTrigger as any);
    await manager.init();
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const items = await manager.rewardMedal({ medalId: "medal_lv_1", group: "g1" });
    expect(items).toEqual([]);
    expect(emitSpy).not.toHaveBeenCalledWith("items:get", expect.any(Array));
  });

  it("rewardMedal 领取后 rts 应持久化到 playerdata", async () => {
    const pd: any = mockPlayerData({
      medal: {
        medals: {
          medal_lv_1: {
            id: "medal_lv_1",
            val: [[50, 50]],
            rts: -1,
            fts: 1000,
            reward: "",
          },
        },
        custom: { currentIndex: "0", customs: {} },
      },
    });
    pd._trigger = mockTrigger;
    const manager = new MedalManager(pd as any, mockTrigger as any);
    await manager.init();
    await manager.rewardMedal({ medalId: "medal_lv_1", group: "g1" });
    expect(pd._playerdata.medal.medals["medal_lv_1"].rts).not.toBe(-1);
  });
});
});