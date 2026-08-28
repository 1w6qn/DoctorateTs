import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock excel 数据表,提供 RetroManager 依赖的最小数据
vi.mock("@excel/excel", () => {
  return {
    default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

      // 怀旧活动表:提供追踪奖励列表
      RetroTable: {
        zoneToRetro: {},
        stageValidInfo: {},
        stages: null,
        retroActList: {},
        retroTrailList: {
          retro_001: {
            retroID: "retro_001",
            trailStartTime: 0,
            trailRewardList: [
              {
                trailRewardId: "trail_reward_001",
                starCount: 1,
                rewardItem: { id: "retro_item_001", count: 5, type: "MATERIAL" },
              },
              {
                trailRewardId: "trail_reward_002",
                starCount: 3,
                rewardItem: { id: "retro_item_002", count: 10, type: "MATERIAL" },
              },
            ],
            stageList: [],
            relatedChar: "char_001",
            relatedFullPotentialItemID: null,
            themeColor: "#FFFFFF",
            fullPotentialItemID: null,
          },
        },
        stageList: {},
        ruleData: { title: [], desc: [] },
        customData: {
          typeAct17Side: {},
          typeAct25Side: {},
          typeAct20Side: {},
          typeAct21Side: {},
        },
        initRetroCoin: 0,
        retroCoinPerWeek: 0,
        retroCoinMax: 0,
        retroUnlockCost: 0,
        retroDetail: "",
        retroPreShowTime: 0,
      },
      // 活动表:提供通关奖励 retroData
      ActivityTable: {
        basicInfo: {},
        homeActConfig: {},
        zoneToActivity: {},
        actTimeTrackPoint: {},
        missionData: [],
        missionGroup: [],
        replicateMissions: {},
        activity: {
          MINISTORY: {
            act_001: {
              retroData: {
                rewards: [
                  {
                    id: "retro_001",
                    items: [
                      { id: "pass_item_001", count: 100, type: "MATERIAL" },
                      { id: "pass_item_002", count: 200, type: "MATERIAL" },
                    ],
                  },
                  {
                    id: "retro_002",
                    items: [
                      { id: "pass_item_003", count: 50, type: "MATERIAL" },
                    ],
                  },
                ],
              },
            },
            act_002: {},
          },
          DEFAULT: {},
          CHECKIN_ONLY: {},
        },
        extraData: { MAINLINE_BP: {} },
        activityItems: {},
        syncPoints: {},
        dynActs: {},
        stageRewardsData: {},
        actThemes: [],
        actFunData: {},
        carData: {},
        siracusaData: {},
        fireworkData: {},
        halfIdleData: {},
        kvSwitchData: {},
        dynEntrySwitchData: {},
        hiddenStageData: [],
        missionArchives: {},
        fifthAnnivExploreData: {},
        anniv7thData: {},
        autoChessData: {},
        stringRes: {},
        activityTraps: {},
        activityTrapMissions: {},
        trapRuneDataDict: {},
        activityTemplateMissionStyles: {},
        activityCrossDayTrackTypeDataDict: {},
        activityCrossDayTrackTypeMap: {},
        activityStoryReadTipsDatas: {},
      },
    },
  };
});

vi.mock("@game/kernel/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

vi.mock("@utils/time", () => ({
  now: () => 1234567890,
}));



import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { RetroManager } from "@game/modules/retro/RetroManager";

/**
 * RetroManager 单元测试
 * 覆盖怀旧关卡解锁、追踪奖励领取、通关奖励领取等核心功能
 */
describe("RetroManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();

    mockPlayer = mockPlayerData({
      retro: {
        coin: 10,
        supplement: 0,
        block: {
          retro_001: {
            locked: 1,
            open: 0,
          },
          retro_002: {
            locked: 1,
            open: 0,
          },
        },
        lst: 0,
        nst: 0,
        trail: {
          retro_001: {},
        },
        rewardPerm: [],
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
    it("应该正确初始化 RetroManager 实例", () => {
      const manager = new RetroManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
    });
  });

  describe("unlockRetroBlock", () => {
    it("应该消耗一个怀旧币并解锁指定怀旧关卡块", async () => {
      const manager = new RetroManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // 初始 coin=10,retro_001 处于锁定状态
      expect(mockPlayer._playerdata.retro!.coin).toBe(10);
      expect(mockPlayer._playerdata.retro!.block["retro_001"].locked).toBe(1);
      expect(mockPlayer._playerdata.retro!.block["retro_001"].open).toBe(0);

      await manager.unlockRetroBlock({ retroId: "retro_001" });

      // 应消耗 1 个怀旧币
      expect(mockPlayer._playerdata.retro!.coin).toBe(9);
      // 应解锁并打开 retro_001
      expect(mockPlayer._playerdata.retro!.block["retro_001"].locked).toBe(0);
      expect(mockPlayer._playerdata.retro!.block["retro_001"].open).toBe(1);
    });

    it("应该只解锁指定的怀旧关卡块,不影响其他块", async () => {
      const manager = new RetroManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.unlockRetroBlock({ retroId: "retro_001" });

      // retro_002 应仍处于锁定状态
      expect(mockPlayer._playerdata.retro!.block["retro_002"].locked).toBe(1);
      expect(mockPlayer._playerdata.retro!.block["retro_002"].open).toBe(0);
    });
  });

  describe("getRetroTrailReward", () => {
    it("应该返回追踪奖励物品并标记该奖励为已领取", async () => {
      const manager = new RetroManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = await manager.getRetroTrailReward({
        retroId: "retro_001",
        rewardId: "trail_reward_001",
      });

      // 应返回奖励物品
      expect(result).toEqual([
        { id: "retro_item_001", count: 5, type: "MATERIAL" },
      ]);
      // 应在 trail 中标记该奖励已领取
      expect(mockPlayer._playerdata.retro!.trail["retro_001"]).toEqual({
        trail_reward_001: 1,
      });
      // 应触发 items:get 事件
      expect(emitSpy).toHaveBeenCalledWith("items:get", [
        [{ id: "retro_item_001", count: 5, type: "MATERIAL" }],
      ]);
    });

    it("领取第二个追踪奖励时应保留已领取的第一个奖励标记", async () => {
      const manager = new RetroManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.getRetroTrailReward({
        retroId: "retro_001",
        rewardId: "trail_reward_001",
      });
      await manager.getRetroTrailReward({
        retroId: "retro_001",
        rewardId: "trail_reward_002",
      });

      expect(mockPlayer._playerdata.retro!.trail["retro_001"]).toEqual({
        trail_reward_001: 1,
        trail_reward_002: 1,
      });
    });

    it("trail 缺该 retro 条目/整体缺失时应惰性初始化而非 500", async () => {
      // 修复前：trail[retroId] 为 undefined 时直接写 trail[retroId][rewardId] → TypeError
      //（新 retro/旧存档——模板只预置已知 retro 条目）
      const manager = new RetroManager(
        mockPlayer as any,
        mockTrigger as any
      );
      // 场景一：trail 存在但缺 retro_001 条目
      mockPlayer._playerdata.retro!.trail = {};
      let result = await manager.getRetroTrailReward({
        retroId: "retro_001",
        rewardId: "trail_reward_001",
      });
      expect(result).toEqual([
        { id: "retro_item_001", count: 5, type: "MATERIAL" },
      ]);
      expect(mockPlayer._playerdata.retro!.trail["retro_001"]).toEqual({
        trail_reward_001: 1,
      });
      // 场景二：trail 整体缺失（更旧存档）
      delete (mockPlayer._playerdata.retro as any).trail;
      result = await manager.getRetroTrailReward({
        retroId: "retro_001",
        rewardId: "trail_reward_002",
      });
      expect(result).toEqual([
        { id: "retro_item_002", count: 10, type: "MATERIAL" },
      ]);
      expect(mockPlayer._playerdata.retro!.trail["retro_001"]).toEqual({
        trail_reward_002: 1,
      });
    });
  });

  describe("getRetroPassReward", () => {
    it("应该从匹配的活动 retroData 中找到对应 retroId 的通关奖励", async () => {
      const manager = new RetroManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = await manager.getRetroPassReward({
        retroId: "retro_001",
        activityId: "act_001",
      });

      // retro_001 对应的通关奖励应包含 pass_item_001 与 pass_item_002
      expect(result).toEqual([
        { id: "pass_item_001", count: 100, type: "MATERIAL" },
        { id: "pass_item_002", count: 200, type: "MATERIAL" },
      ]);
      // 应触发 items:get 事件
      expect(emitSpy).toHaveBeenCalledWith("items:get", [
        [
          { id: "pass_item_001", count: 100, type: "MATERIAL" },
          { id: "pass_item_002", count: 200, type: "MATERIAL" },
        ],
      ]);
    });

    it("当匹配的 retroId 不存在时应返回空奖励数组", async () => {
      const manager = new RetroManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // retro_999 在 retroData.rewards 中不存在
      const result = await manager.getRetroPassReward({
        retroId: "retro_999",
        activityId: "act_001",
      });

      expect(result).toEqual([]);
    });
  });
});
