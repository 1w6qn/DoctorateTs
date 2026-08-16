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
      GameDataConst: {
        playerExpMap: [100, 200, 300],
        playerApMap: [100, 110, 120],
      },
      CharacterTable: {},
      ItemTable: {
        items: {
          mat_001: { itemType: "MATERIAL", rarity: 1 },
          exp_mat: { itemType: "CARD_EXP", rarity: 0 },
          gold: { itemType: "GOLD", rarity: 0 },
          ap_item: { itemType: "AP_GAMEPLAY", rarity: 0 },
          char_skin: { itemType: "CHAR_SKIN", rarity: 0 },
        },
        expItems: {
          exp_mat: { gainExp: 50 },
        },
      },
      ShopClientTable: {},
      SkillDataBundle: {},
      ActivityTable: {
        basicInfo: {
          act53side: { id: "act53side", type: "TYPE_ACT53SIDE", name: "直到大地变成一颗酸橙" },
        },
        activity: {
          tYPE_ACT53SIDE: {
            act53side: {
              constData: { coinItemId: "act53side_token_photo" },
            },
          },
        },
      },
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


import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { InventoryManager } from "@game/manager/inventory";

describe("InventoryManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;
  let mockExcelRef: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockExcelRef = (vi.mocked(await import("@excel/excel")).default as any);

    mockPlayer = mockPlayerData({
      inventory: {},
      consumable: {},
      status: {
        gold: 9999,
        ap: 100,
        maxAp: 100,
        lastApAddTime: Math.floor(Date.now() / 1000),
        exp: 0,
        level: 1,
        practiceTicket: 5,
        recruitLicense: 3,
        instantFinishTicket: 0,
        gachaTicket: 10,
        androidDiamond: 0,
        diamondShard: 0,
        hggShard: 0,
        lggShard: 0,
        socialPoint: 0,
        tenGachaTicket: 0,
        classicShard: 0,
        classicGachaTicket: 0,
        classicTenGachaTicket: 0,
      },
      skin: {
        characterSkins: {},
        skinTs: {},
      },
      building: {
        furniture: {},
        solution: { furnitureTs: {} },
      },
      avatar: { avatar_icon: {} },
      nameCardStyle: {
        skin: {
          state: {},
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
    it("应该正确初始化 InventoryManager 实例", () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
    });

    it("应该注册 items:use 和 items:get 事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      new InventoryManager(mockPlayer as any, mockTrigger as any);
      expect(onSpy).toHaveBeenCalledWith(
        "items:use",
        expect.any(Function)
      );
      expect(onSpy).toHaveBeenCalledWith(
        "items:get",
        expect.any(Function)
      );
    });
  });

  describe("skinCnt", () => {
    it("应该返回角色皮肤数量", () => {
      mockPlayer._playerdata.skin!.characterSkins = {
        skin_001: 1,
        skin_002: 1,
        skin_003: 1,
      };

      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      expect(manager.skinCnt).toBe(3);
    });

    it("当没有皮肤时应该返回 0", () => {
      mockPlayer._playerdata.skin!.characterSkins = {};

      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      expect(manager.skinCnt).toBe(0);
    });
  });

  describe("gainItem", () => {
    it("MATERIAL 类型物品应该增加到库存", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.gainItem({
        type: "MATERIAL",
        id: "mat_001",
        count: 5,
      });

      expect(
        mockPlayer._playerdata.inventory!["mat_001"]
      ).toBe(5);
    });

    it("GOLD 类型物品应该增加金币", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.gainItem({
        type: "GOLD",
        id: "gold",
        count: 500,
      });

      expect(mockPlayer._playerdata.status!.gold).toBe(10499);
    });

    it("EXP_PLAYER 类型物品应该增加经验值", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.gainItem({
        type: "EXP_PLAYER",
        id: "",
        count: 50,
      });

      expect(mockPlayer._playerdata.status!.exp).toBe(50);
    });

    it("CHAR 类型物品应该触发 char:get 事件", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.gainItem({
        type: "CHAR",
        id: "char_001",
        count: 1,
      });

      expect(emitSpy).toHaveBeenCalledWith("char:get", ["char_001"]);
    });

    it("CHAR_SKIN 类型物品应该添加皮肤记录", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.gainItem({
        type: "CHAR_SKIN",
        id: "skin_test",
        count: 1,
      });

      expect(
        mockPlayer._playerdata.skin!.characterSkins["skin_test"]
      ).toBe(1);
    });

    it("AP_GAMEPLAY 类型物品应该增加理智值", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const oldAp = mockPlayer._playerdata.status!.ap;
      await manager.gainItem({
        type: "AP_GAMEPLAY",
        id: "",
        count: 20,
      });

      expect(mockPlayer._playerdata.status!.ap).toBeGreaterThan(oldAp);
    });

    it("TKT_GACHA 类型物品应该增加寻访凭证", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.gainItem({
        type: "TKT_GACHA",
        id: "",
        count: 3,
      });

      expect(mockPlayer._playerdata.status!.gachaTicket).toBe(13);
    });

    it("DIAMOND 类型物品应该增加合成玉", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.gainItem({
        type: "DIAMOND",
        id: "4002",
        count: 600,
      });

      expect(
        mockPlayer._playerdata.status!.androidDiamond
      ).toBe(600);
    });
  });

  describe("_useItem", () => {
    it("消耗类型物品应该减少数量", async () => {
      mockPlayer._playerdata.consumable = {
        "0": {
          1: { count: 5, ts: -1 },
        },
      };

      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager._useItem({
        type: "TKT_GACHA_PRSV",
        id: "0",
        count: 2,
        instId: 1,
      });

      expect(
        mockPlayer._playerdata.consumable["0"][1].count
      ).toBe(3);
    });

    it("非消耗类型物品应该触发反向 items:get", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager._useItem({
        type: "MATERIAL",
        id: "mat_001",
        count: 3,
      });

      const itemsGetCalls = emitSpy.mock.calls.filter(
        (c) => c[0] === "items:get"
      );
      expect(itemsGetCalls.length).toBeGreaterThan(0);
    });

    it("无 type 且 ItemTable 不存在的物品应跳过（不 500）", async () => {
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await expect(
        manager._useItem({ id: "DIAMOND_SHD", count: 600 })
      ).resolves.toBeUndefined();
      await expect(
        manager.gainItem({ id: "TKT_GACHA", count: 1 })
      ).resolves.toBeUndefined();
    });
  });

  describe("TYPE_ACT53SIDE 活动币跟踪（奇象巡展 actCoin）", () => {
    it("获得 coinItemId 物品时应累加 activity.TYPE_ACT53SIDE.actCoin", async () => {
      mockPlayer._playerdata.activity = {
        TYPE_ACT53SIDE: { act53side: { actCoin: 0, campaignCnt: 0, favorList: [] } },
      };
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await mockTrigger.emit("items:get", [[
        { id: "act53side_token_photo", type: "ACTIVITY_ITEM", count: 3 },
      ]]);

      expect(
        mockPlayer._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin
      ).toBe(3);
    });

    it("非活动币物品不触碰 actCoin", async () => {
      mockPlayer._playerdata.activity = {
        TYPE_ACT53SIDE: { act53side: { actCoin: 5, campaignCnt: 0, favorList: [] } },
      };
      const manager = new InventoryManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.gainItem({ id: "mat_001", type: "MATERIAL", count: 1 });

      expect(
        mockPlayer._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin
      ).toBe(5);
    });
  });
});