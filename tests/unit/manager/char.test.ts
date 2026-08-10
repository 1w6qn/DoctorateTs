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
        characterExpMap: [[0, 100, 200, 300]],
        characterUpgradeCostMap: [[0, 10, 20, 30]],
        maxLevel: [
          [50, 50, 50, 50, 50, 50],
          [50, 50, 50, 50, 50, 50],
          [50, 50, 50, 50, 50, 50],
          [50, 50, 50, 50, 50, 50],
          [50, 50, 50, 50, 50, 50],
          [50, 50, 50, 50, 50, 50],
        ],
        evolveGoldCost: [
          [0, 100, 200],
          [0, 200, 400],
          [0, 300, 600],
          [0, 400, 800],
          [0, 500, 1000],
          [0, 600, 1200],
        ],
      },
      CharacterTable: {
        char_001: {
          charId: "char_001",
          name: "测试干员",
          rarity: 5,
          potentialItemId: "pot_001",
          phases: [
            { evolveCost: [] },
            { evolveCost: [{ id: "mat_001", count: 5 }] },
            { evolveCost: [{ id: "mat_002", count: 10 }] },
          ],
          allSkillLvlup: [
            { lvlUpCost: [{ id: "skill_mat", count: 1 }] },
          ],
        },
      },
      ItemTable: {
        items: {
          mat_001: { itemType: "MATERIAL", rarity: 1 },
          exp_mat: { itemType: "CARD_EXP", rarity: 0 },
        },
        expItems: {
          exp_mat: { gainExp: 50 },
        },
      },
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

vi.mock("lodash", () => ({
  ceil: (n: number) => Math.ceil(n),
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { CharManager } from "@game/manager/char";

describe("CharManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;
  let mockExcelRef: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockExcelRef = (vi.mocked(await import("@excel/excel")).default as any);

    mockPlayer = mockPlayerData({
      troop: {
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
        curCharInstId: 1001,
      },
      dexNav: {
        character: {
          char_001: {
            charInstId: 1001,
            count: 1,
          },
        },
      },
      status: { gold: 9999 },
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
    it("应该正确初始化 CharManager 实例", () => {
      const manager = new CharManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
    });
  });

  describe("onCharGet", () => {
    it("当获取新干员时应该创建新的干员数据", async () => {
      const manager = new CharManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockPlayer._playerdata.dexNav!.character = {};
      mockPlayer._playerdata.troop!.curCharInstId = 0;

      const result = await manager.onCharGet([
        "char_001",
        { from: "NORMAL" },
      ]);

      expect(result).toBeDefined();
      expect(result.isNew).toBe(1);
      expect(result.charId).toBe("char_001");
    });

    it("当获取已有干员时应该返回 isNew 为 0", async () => {
      const manager = new CharManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.onCharGet([
        "char_001",
        { from: "NORMAL" },
      ]);

      expect(result).toBeDefined();
      expect(result.isNew).toBe(0);
    });

    it("当获取已有干员时应该触发 items:get 返还物品", async () => {
      const manager = new CharManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.onCharGet(["char_001", { from: "NORMAL" }]);

      const itemsGetCalls = emitSpy.mock.calls.filter(
        (c) => c[0] === "items:get"
      );
      expect(itemsGetCalls.length).toBeGreaterThan(0);
    });
  });

  describe("setDefaultSkill", () => {
    it("应该设置干员的默认技能索引", async () => {
      const manager = new CharManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.setDefaultSkill({
        charInstId: 1001,
        defaultSkillIndex: 1,
      });

      expect(
        mockPlayer._playerdata.troop!.chars[1001].defaultSkillIndex
      ).toBe(1);
    });
  });

  describe("boostPotential", () => {
    it("应该提升干员潜能并触发事件", async () => {
      const manager = new CharManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.boostPotential({
        charInstId: 1001,
        itemId: "pot_001",
        targetRank: 3,
      });

      expect(
        mockPlayer._playerdata.troop!.chars[1001].potentialRank
      ).toBe(3);
      expect(emitSpy).toHaveBeenCalledWith(
        "BoostPotential",
        expect.any(Array)
      );
    });
  });

  describe("upgradeSkill", () => {
    it("应该升级技能等级并触发事件", async () => {
      const manager = new CharManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockPlayer._playerdata.troop!.chars[1001].skills = [
        { specializeLevel: 0 },
      ];

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.upgradeSkill({
        charInstId: 1001,
        targetLevel: 2,
      });

      expect(
        mockPlayer._playerdata.troop!.chars[1001].mainSkillLvl
      ).toBe(2);
      expect(emitSpy).toHaveBeenCalledWith(
        "items:use",
        expect.any(Array)
      );
    });
  });

  describe("onCharGet 修复（2026-08-09）", () => {
    it("新干员创建后 curCharInstId 应递增（避免 instId 冲突）", async () => {
      const manager = new CharManager(mockPlayer as any, mockTrigger as any);
      mockPlayer._playerdata.dexNav!.character = {};
      mockPlayer._playerdata.troop!.curCharInstId = 0;
      await manager.onCharGet(["char_001", { from: "NORMAL" }]);
      // 新干员创建后 curCharInstId 0 → 1（此前从不递增导致后续新干员 instId 冲突）
      expect(mockPlayer._playerdata.troop!.curCharInstId).toBe(1);
      // 新干员的 instId 使用递增前的 curCharInstId（=0 时用 0 → dexNav 记录）
      const dexChar = mockPlayer._playerdata.dexNav!.character["char_001"];
      expect(dexChar.charInstId).toBe(0);
    });

    it("重复且未满潜干员应返回 potent {delta, now}", async () => {
      const manager = new CharManager(mockPlayer as any, mockTrigger as any);
      // char_001 已在 mock 中（potentialRank 0，maxPotentialLevel 5）
      const result = await manager.onCharGet(["char_001", { from: "NORMAL" }]);
      expect(result.isNew).toBe(0);
      expect(result.potent).toEqual({ delta: 1, now: 1 });
    });
  });
});
