import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock excel 数据表,提供 StatusManager 依赖的最小数据
vi.mock("@excel/excel", () => {
  return {
    default: {
      // 游戏常量:提供钻石碎片兑换比例
      GameDataConst: {
        diamondToShdRate: 10,
      },
      // 手册信息表:提供团队任务奖励物品
      HandbookInfoTable: {
        teamMissionList: {
          reward_001: {
            id: "reward_001",
            sort: 1,
            powerId: "power_001",
            powerName: "测试团队",
            item: { id: "team_item_001", count: 5, type: "MATERIAL" },
            favorPoint: 100,
          },
        },
      },
    },
  };
});

vi.mock("@game/service/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

// Mock 时间工具:now 返回固定值,checkNew 控制刷新逻辑
vi.mock("@utils/time", () => ({
  now: () => 1234567890,
  checkNew: () => true,
}));

// Mock moment,使 refreshTime 触发全部三类刷新事件
vi.mock("moment", () => ({
  default: () => ({
    day: () => 1,
    date: () => 1,
  }),
}));



import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { StatusManager } from "@game/service/player/status";

/**
 * StatusManager 单元测试
 * 覆盖秘书设置、头像/昵称/简历修改、故事完成、理智购买、钻石碎片兑换等
 */
describe("StatusManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();

    mockPlayer = mockPlayerData({
      status: {
        nickName: "TestUser",
        nickNumber: "0",
        level: 1,
        exp: 0,
        socialPoint: 0,
        gachaTicket: 0,
        tenGachaTicket: 0,
        instantFinishTicket: 0,
        hggShard: 0,
        lggShard: 0,
        recruitLicense: 0,
        progress: 0,
        buyApRemainTimes: 0,
        apLimitUpFlag: 0,
        uid: "10000",
        flags: {},
        ap: 100,
        maxAp: 100,
        androidDiamond: 0,
        iosDiamond: 0,
        diamondShard: 0,
        gold: 9999,
        practiceTicket: 0,
        lastRefreshTs: 0,
        lastApAddTime: 0,
        mainStageProgress: null,
        registerTs: 0,
        lastOnlineTs: 0,
        serverName: "TestServer",
        avatarId: "",
        resume: "",
        birthday: { month: 1, day: 1 },
        friendNumLimit: 50,
        monthlySubscriptionStartTime: 0,
        monthlySubscriptionEndTime: 0,
        secretary: "",
        secretarySkinId: "",
        tipMonthlyCardExpireTs: 0,
        avatar: { type: "ICON", id: "avatar_001" },
        globalVoiceLan: "CN_MANDARIN",
        classicShard: 0,
        classicGachaTicket: 0,
        classicTenGachaTicket: 0,
      } as any,
      troop: {
        curCharInstId: 1001,
        curSquadCount: 1,
        squads: {},
        chars: {
          1001: {
            instId: 1001,
            charId: "char_001",
            favorPoint: 0,
            potentialRank: 0,
            mainSkillLvl: 1,
            skin: "char_001#1",
            level: 1,
            exp: 0,
            evolvePhase: 0,
            defaultSkillIndex: -1,
            gainTime: 1234567890,
            skills: [],
            currentEquip: null,
            equip: {},
            voiceLan: "CN_MANDARIN",
          },
        },
        addon: {},
        charGroup: {},
        charMission: {},
      },
      collectionReward: {
        team: {},
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
    it("应该正确初始化并注册四个事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
      expect(onSpy).toHaveBeenCalledWith(
        "status:refresh:time",
        expect.any(Function)
      );
      expect(onSpy).toHaveBeenCalledWith(
        "refresh:daily",
        expect.any(Function)
      );
      expect(onSpy).toHaveBeenCalledWith(
        "refresh:weekly",
        expect.any(Function)
      );
      expect(onSpy).toHaveBeenCalledWith(
        "refresh:monthly",
        expect.any(Function)
      );
    });
  });

  describe("uid", () => {
    it("应该返回玩家 uid", () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager.uid).toBe("10000");
    });
  });

  describe("changeSecretary", () => {
    it("应该更新秘书干员与皮肤", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.changeSecretary({
        charInstId: 1001,
        skinId: "char_001#2",
      });

      expect(mockPlayer._playerdata.status!.secretary).toBe("char_001");
      expect(mockPlayer._playerdata.status!.secretarySkinId).toBe("char_001#2");
    });
  });

  describe("finishStory", () => {
    it("应该将指定故事标记为已完成", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.finishStory({ storyId: "story_001" });

      expect(mockPlayer._playerdata.status!.flags["story_001"]).toBe(1);
    });
  });

  describe("changeAvatar", () => {
    it("应该更新玩家头像信息", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const newAvatar = { type: "PORTAIT", id: "avatar_002" };
      await manager.changeAvatar({ avatar: newAvatar });

      expect(mockPlayer._playerdata.status!.avatar).toEqual(newAvatar);
    });
  });

  describe("changeResume", () => {
    it("应该更新玩家个人简历", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.changeResume({ resume: "这是新的简历内容" });

      expect(mockPlayer._playerdata.status!.resume).toBe("这是新的简历内容");
    });
  });

  describe("bindNickName", () => {
    it("应该更新玩家昵称", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.bindNickName({ nickname: "新昵称" });

      expect(mockPlayer._playerdata.status!.nickName).toBe("新昵称");
    });
  });

  describe("buyAp", () => {
    it("应扣减每日次数并触发 items:use 消耗钻石与 items:get 增加理智", async () => {
      mockPlayer._playerdata.status!.buyApRemainTimes = 10;
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.buyAp();

      expect(mockPlayer._playerdata.status!.buyApRemainTimes).toBe(9);
      expect(emitSpy).toHaveBeenCalledWith(
        "items:use",
        [[{ id: "", type: "DIAMOND", count: 1 }]]
      );
      expect(emitSpy).toHaveBeenCalledWith(
        "items:get",
        [[{ id: "", type: "AP_GAMEPLAY", count: 135 }]]
      );
    });

    it("每日次数耗尽后不应购买（修复：原无限制可无限 1 源石换理智）", async () => {
      mockPlayer._playerdata.status!.buyApRemainTimes = 0;
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.buyAp();

      expect(emitSpy).not.toHaveBeenCalled();
      expect(mockPlayer._playerdata.status!.buyApRemainTimes).toBe(0);
    });
  });

  describe("exchangeDiamondShard", () => {
    it("应该按 diamondToShdRate 比例兑换钻石碎片并触发事件", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      // count=10, diamondToShdRate=10 -> 获得 100 钻石碎片
      await manager.exchangeDiamondShard({ count: 10 });

      expect(emitSpy).toHaveBeenCalledWith(
        "items:get",
        [[{ id: "", type: "DIAMOND_SHD", count: 100 }]]
      );
      expect(emitSpy).toHaveBeenCalledWith(
        "items:use",
        [[{ id: "", type: "DIAMOND", count: 10 }]]
      );
    });
  });

  describe("receiveTeamCollectionReward", () => {
    it("应该领取团队收集奖励并触发 items:get", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.receiveTeamCollectionReward({ rewardId: "reward_001" });

      expect(mockPlayer._playerdata.collectionReward!.team["reward_001"]).toBe(
        1
      );
      expect(emitSpy).toHaveBeenCalledWith("items:get", [
        [{ id: "team_item_001", count: 5, type: "MATERIAL" }],
      ]);
    });
  });

  describe("refreshTime", () => {
    it("应该在跨日/周/月时触发对应刷新事件并更新时间戳", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.refreshTime();

      expect(emitSpy).toHaveBeenCalledWith("refresh:daily", [0]);
      expect(emitSpy).toHaveBeenCalledWith("refresh:weekly", []);
      expect(emitSpy).toHaveBeenCalledWith("refresh:monthly", []);
      expect(mockPlayer._playerdata.status!.lastRefreshTs).toBe(1234567890);
      expect(mockPlayer._playerdata.status!.lastOnlineTs).toBe(1234567890);
    });
  });

  describe("dailyRefresh", () => {
    it("应该恢复体力并重置每日购买次数", async () => {
      mockPlayer._playerdata.status!.ap = 50;
      mockPlayer._playerdata.status!.maxAp = 100;
      mockPlayer._playerdata.status!.lastApAddTime = 0;
      mockPlayer._playerdata.status!.buyApRemainTimes = 0;
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.dailyRefresh();

      expect(mockPlayer._playerdata.status!.ap).toBe(100);
      expect(mockPlayer._playerdata.status!.buyApRemainTimes).toBe(10);
      expect(mockPlayer._playerdata.status!.lastApAddTime).toBe(1234567890);
    });

    it("体力已满时不应超出上限", async () => {
      mockPlayer._playerdata.status!.ap = 100;
      mockPlayer._playerdata.status!.maxAp = 100;
      mockPlayer._playerdata.status!.lastApAddTime = 0;
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.dailyRefresh();

      expect(mockPlayer._playerdata.status!.ap).toBe(100);
    });
  });

  describe("weeklyRefresh / monthlyRefresh", () => {
    it("应委托 dailyRefresh 执行刷新（恢复体力+重置购买次数）", async () => {
      mockPlayer._playerdata.status!.ap = 30;
      mockPlayer._playerdata.status!.maxAp = 100;
      mockPlayer._playerdata.status!.lastApAddTime = 0;
      mockPlayer._playerdata.status!.buyApRemainTimes = 0;
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );
      const dailySpy = vi.spyOn(manager, "dailyRefresh");

      await manager.weeklyRefresh();
      await manager.monthlyRefresh();

      expect(dailySpy).toHaveBeenCalledTimes(2);
    });
  });
});
