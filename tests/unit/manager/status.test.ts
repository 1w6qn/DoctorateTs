import { describe, it, expect, vi, beforeEach } from "vitest";

// excel 数据端口替身:提供 StatusManager 依赖的最小数据
//
// 迁移说明(2026-09,excel 端口注入):管理者不再直连 `@excel/excel` 单例,
// 改经 `player.excel`(PlayerDataManager 注入的数据端口)取表——模块级
// vi.mock 因此失效,夹具改为显式注入到 mockPlayerData 的 excel 字段。
const excelMock: any = {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

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
};

vi.mock("@game/kernel/PlayerDataManager", () => ({
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
import { StatusManager } from "@game/modules/user/status";

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
    // excel 数据端口替身注入(见文件头说明)
    mockPlayer.excel = excelMock;

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
    it("buyAp 扣次数、经 gainItem 消耗 1 源石并回满体力，返回 true", async () => {
      mockPlayer._playerdata.status!.buyApRemainTimes = 10;
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const ok = await manager.buyAp();

      expect(ok).toBe(true);
      expect(mockPlayer._playerdata.status!.buyApRemainTimes).toBe(9);
      expect(mockPlayer.gainItem.setTarget).toHaveBeenCalledWith("", "DIAMOND", 1);
      expect(mockPlayer.gainItem.setTarget).toHaveBeenCalledWith("", "AP_GAMEPLAY", 135);
      expect(mockPlayer.gainItem.use).toHaveBeenCalled();
      expect(mockPlayer.gainItem.handle).toHaveBeenCalled();
    });

    it("buyAp 额度耗尽返回 false 且不扣次数", async () => {
      mockPlayer._playerdata.status!.buyApRemainTimes = 0;
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const ok = await manager.buyAp();

      expect(ok).toBe(false);
      expect(mockPlayer._playerdata.status!.buyApRemainTimes).toBe(0);
      expect(mockPlayer.gainItem.use).not.toHaveBeenCalled();
    });
  });

  describe("exchangeDiamondShard", () => {
    it("应该按 diamondToShdRate 比例经 gainItem 兑换钻石碎片", async () => {
      const manager = new StatusManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // count=10, diamondToShdRate=10 -> 获得 100 钻石碎片
      await manager.exchangeDiamondShard({ count: 10 });

      expect(mockPlayer.gainItem.setTarget).toHaveBeenCalledWith("", "DIAMOND_SHD", 100);
      expect(mockPlayer.gainItem.setTarget).toHaveBeenCalledWith("", "DIAMOND", 10);
      expect(mockPlayer.gainItem.use).toHaveBeenCalled();
      expect(mockPlayer.gainItem.handle).toHaveBeenCalled();
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

  // Round 46（审计 §5.4 系统性根因）：跨天/跨周/跨月的唯一驱动 refreshTime 此前只被
  // 管理端调用 → refresh:daily/weekly/monthly 在正常游戏流程中永不派发。现由认证后的
  // 每请求中间件调用 ensurePeriodicRefresh()（内部 60s 节流）。
  describe("ensurePeriodicRefresh（请求内周期性刷新补触发）", () => {
    it("lastOnlineTs 为 0（新号/迁移档）时应立即执行一次 refreshTime", async () => {
      const manager = new StatusManager(mockPlayer as any, mockTrigger as any);
      const spy = vi.spyOn(manager, "refreshTime");
      mockPlayer._playerdata.status!.lastOnlineTs = 0;
      await manager.ensurePeriodicRefresh();
      expect(spy).toHaveBeenCalledTimes(1);
      // refreshTime 会写回时间戳（now() mock = 1234567890）
      expect(mockPlayer._playerdata.status!.lastOnlineTs).toBe(1234567890);
    });

    it("节流窗口内（<60s）重复调用不再触发", async () => {
      const manager = new StatusManager(mockPlayer as any, mockTrigger as any);
      const spy = vi.spyOn(manager, "refreshTime");
      mockPlayer._playerdata.status!.lastOnlineTs = 1234567890 - 10; // 10s 前
      await manager.ensurePeriodicRefresh();
      expect(spy).not.toHaveBeenCalled();
    });

    it("超过节流窗口（>=60s）后再次触发", async () => {
      const manager = new StatusManager(mockPlayer as any, mockTrigger as any);
      const spy = vi.spyOn(manager, "refreshTime");
      mockPlayer._playerdata.status!.lastOnlineTs = 1234567890 - 61;
      await manager.ensurePeriodicRefresh();
      expect(spy).toHaveBeenCalledTimes(1);
    });
  });
});
