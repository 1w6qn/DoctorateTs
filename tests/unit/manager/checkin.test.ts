import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock excel 数据表,提供 CheckInManager 依赖的最小数据
vi.mock("@excel/excel", () => {
  return {
    default: {
      // 签到表:提供签到组、月卡订阅物品等
      CheckinTable: {
        groups: {
          group_001: {
            groupId: "group_001",
            title: "测试签到组",
            description: "测试用",
            signStartTime: 0,
            signEndTime: 9999999999,
            items: [
              { itemId: "item_001", itemType: "MATERIAL", count: 100 },
              { itemId: "item_002", itemType: "MATERIAL", count: 200 },
            ],
          },
          group_002: {
            groupId: "group_002",
            title: "二月签到组",
            description: "测试用",
            signStartTime: 0,
            signEndTime: 9999999999,
            items: [
              { itemId: "item_003", itemType: "MATERIAL", count: 300 },
            ],
          },
        },
        currentMonthlySubId: "sub_001",
        monthlySubItem: {
          sub_001: [
            {},
            {
              items: [
                { id: "sub_item_001", count: 1, type: "MATERIAL" },
              ],
            },
          ],
        },
      },
    },
  };
});

vi.mock("@game/service/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

// Mock 时间工具:now 固定时间戳,checkBetween 控制签到组与月卡判断
vi.mock("@utils/time", () => ({
  now: () => 1234567890,
  checkBetween: (ts: number, start: number, end: number) =>
    ts >= start && ts <= end,
}));

vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));


import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { CheckInManager } from "@game/service/manager/checkin";

/**
 * CheckInManager 单元测试
 * 覆盖签到、每日刷新、每月刷新、月卡奖励等场景
 */
describe("CheckInManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();

    mockPlayer = mockPlayerData({
      checkIn: {
        canCheckIn: 1,
        checkInGroupId: "group_001",
        checkInRewardIndex: 0,
        checkInHistory: [],
        newbiePackage: {
          open: false,
          groupId: "",
          finish: 0,
          stopSale: 0,
          checkInHistory: [],
        },
      },
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
    it("应该正确初始化并注册 refresh:monthly 与 refresh:daily 事件", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      const manager = new CheckInManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
      expect(onSpy).toHaveBeenCalledWith(
        "refresh:monthly",
        expect.any(Function)
      );
      expect(onSpy).toHaveBeenCalledWith(
        "refresh:daily",
        expect.any(Function)
      );
    });
  });

  describe("dailyRefresh", () => {
    it("应该重置 canCheckIn 并递增 checkInRewardIndex", async () => {
      const manager = new CheckInManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // 先设置为已签到状态,验证每日刷新会重置
      mockPlayer._playerdata.checkIn!.canCheckIn = 0;
      mockPlayer._playerdata.checkIn!.checkInRewardIndex = 5;

      await manager.dailyRefresh();

      expect(mockPlayer._playerdata.checkIn!.canCheckIn).toBe(1);
      expect(mockPlayer._playerdata.checkIn!.checkInRewardIndex).toBe(6);
    });
  });

  describe("monthlyRefresh", () => {
    it("应该重置签到历史与奖励索引,并匹配当前可用签到组", async () => {
      const manager = new CheckInManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockPlayer._playerdata.checkIn!.checkInHistory = [0, 0, 0];
      mockPlayer._playerdata.checkIn!.checkInRewardIndex = 15;

      await manager.monthlyRefresh();

      expect(mockPlayer._playerdata.checkIn!.checkInHistory).toEqual([]);
      expect(mockPlayer._playerdata.checkIn!.checkInRewardIndex).toBe(-1);
      // 当前时间在 group_001 的时间范围内
      expect(mockPlayer._playerdata.checkIn!.checkInGroupId).toBe("group_001");
    });

    it("groups 含 null 伪键时 monthlyRefresh 不应 500", async () => {
      // 数据表末尾字段名伪键（值 null）——修复前 Object.values 遍历到 null →
      // t.signStartTime 崩溃（2026-08-14 数据更新后所有生成表均带该伪键）
      const excel = await import("@excel/excel");
      const groups = (excel.default as any).CheckinTable.groups;
      groups["groupId"] = null;
      groups["signStartTime"] = null;
      const manager = new CheckInManager(
        mockPlayer as any,
        mockTrigger as any
      );
      await expect(manager.monthlyRefresh()).resolves.not.toThrow();
      // 仍能匹配到正常签到组
      expect(mockPlayer._playerdata.checkIn!.checkInGroupId).toBe("group_001");
    });
  });

  describe("checkIn", () => {
    it("当 canCheckIn 为 0 时应该返回 undefined 且不触发事件", async () => {
      const manager = new CheckInManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockPlayer._playerdata.checkIn!.canCheckIn = 0;
      const emitSpy = vi.spyOn(mockTrigger, "emit");

      const result = await manager.checkIn();

      expect(result).toBeUndefined();
      const itemsGetCalls = emitSpy.mock.calls.filter(
        (c) => c[0] === "items:get"
      );
      expect(itemsGetCalls.length).toBe(0);
    });

    it("当可签到且无月卡时应该返回签到奖励并将 canCheckIn 置 0", async () => {
      const manager = new CheckInManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = await manager.checkIn();

      expect(result).toBeDefined();
      expect(result!.signInRewards).toEqual([
        { id: "item_001", count: 100, type: "MATERIAL" },
      ]);
      expect(result!.subscriptionRewards).toEqual([]);
      expect(mockPlayer._playerdata.checkIn!.canCheckIn).toBe(0);
      expect(mockPlayer._playerdata.checkIn!.checkInHistory).toContain(0);
      expect(emitSpy).toHaveBeenCalledWith("items:get", [
        [{ id: "item_001", count: 100, type: "MATERIAL" }],
      ]);
    });

    it("当持有月卡时签到应额外返回订阅奖励", async () => {
      const manager = new CheckInManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // 设置月卡有效期内
      mockPlayer._playerdata.status!.monthlySubscriptionStartTime = 0;
      mockPlayer._playerdata.status!.monthlySubscriptionEndTime = 9999999999;

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = await manager.checkIn();

      expect(result).toBeDefined();
      expect(result!.signInRewards).toEqual([
        { id: "item_001", count: 100, type: "MATERIAL" },
      ]);
      expect(result!.subscriptionRewards).toEqual([
        { id: "sub_item_001", count: 1, type: "MATERIAL" },
      ]);
      // items:get 应携带签到奖励 + 订阅奖励
      expect(emitSpy).toHaveBeenCalledWith("items:get", [
        [
          { id: "sub_item_001", count: 1, type: "MATERIAL" },
          { id: "item_001", count: 100, type: "MATERIAL" },
        ],
      ]);
    });

    it("当 checkInRewardIndex 为 -1 时签到应重置为 0 后再发放奖励", async () => {
      const manager = new CheckInManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockPlayer._playerdata.checkIn!.checkInRewardIndex = -1;
      const result = await manager.checkIn();

      expect(result).toBeDefined();
      expect(mockPlayer._playerdata.checkIn!.checkInRewardIndex).toBe(0);
      // 应发放 index=0 的奖励
      expect(result!.signInRewards).toEqual([
        { id: "item_001", count: 100, type: "MATERIAL" },
      ]);
    });
  });
});
