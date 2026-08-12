import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock excel 数据表,提供 TroopManager 依赖的最小数据
vi.mock("@excel/excel", () => {
  return {
    default: {
      // 角色表:提供 rarity、potentialItemId、classicPotentialItemId、skills 字段
      CharacterTable: {
        char_001: {
          charId: "char_001",
          name: "测试干员",
          rarity: 5,
          potentialItemId: "pot_001",
          classicPotentialItemId: "pot_classic_001",
          skills: [
            {
              skillId: "sk1",
              unlockCond: { phase: 0, level: 1 },
            },
          ],
        },
        char_002: {
          charId: "char_002",
          name: "字符串稀有度干员（真实数据格式）",
          rarity: "TIER_5",
          potentialItemId: "pot_001",
          classicPotentialItemId: "pot_classic_001",
          skills: [
            {
              skillId: "sk1",
              unlockCond: { phase: 0, level: 1 },
            },
          ],
        },
        char_002_amiya: {
          charId: "char_002_amiya",
          name: "阿米娅",
          rarity: 5,
          potentialItemId: "pot_amiya",
          skills: [],
        },
      },
      // 抽卡表:提供潜能物品转换器
      GachaTable: {
        potentialMaterialConverter: {
          items: {
            5: { id: "shard_5", count: 10, type: "MATERIAL" },
            4: { id: "shard_4", count: 5, type: "MATERIAL" },
          },
        },
        classicPotentialMaterialConverter: {
          items: {
            5: { id: "classic_shard_5", count: 5, type: "MATERIAL" },
          },
        },
      },
      // 模组装备表
      UniequipTable: {
        equipDict: {
          equip_001: {
            uniEquipId: "equip_001",
            charId: "char_001",
          },
          // tmpl 变体专属模组（fix 应对 tmpl 各形态按各自 charId 回填）
          equip_tmpl_001: {
            uniEquipId: "equip_tmpl_001",
            charId: "char_001_alt",
          },
        },
      },
      // 勋章表:提供干员密录勋章（CharStoryUnlock 模板）配置
      MedalTable: {
        medalList: [
          {
            medalId: "medal_story_char_001",
            template: "CharStoryUnlock",
            unlockParam: ["char_001", "story_001"],
          },
        ],
        medalTypeData: {},
      },
    },
  };
});

vi.mock("@game/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

// Mock 时间工具,返回固定时间戳便于断言
vi.mock("@utils/time", () => ({
  now: () => 1234567890,
  checkBetween: (ts: number, start: number, end: number) =>
    ts >= start && ts <= end,
}));

vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));


import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { TroopManager } from "@game/manager/troop";

/**
 * TroopManager 单元测试
 * 覆盖编队管理、潜能分解、故事解锁、战斗事件触发等核心功能
 */
describe("TroopManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();

    mockPlayer = mockPlayerData({
      troop: {
        curCharInstId: 1001,
        curSquadCount: 1,
        squads: {
          1: {
            squadId: "1",
            name: "编队1",
            slots: [],
          },
        },
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
          1002: {
            instId: 1002,
            charId: "char_002",
            favorPoint: 0,
            potentialRank: 0,
            mainSkillLvl: 1,
            skin: "char_002#1",
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
        addon: {
          char_001: {
            story: {},
          },
        },
        charGroup: {},
        charMission: {},
      },
      inventory: {
        pot_001: 3,
        pot_classic_001: 2,
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
    it("应该正确初始化实例并注册 game:fix 事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
      expect(onSpy).toHaveBeenCalledWith("game:fix", expect.any(Function));
    });
  });

  describe("squadFormation", () => {
    it("应该更新编队槽位并触发 SquadFormation 事件", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const newSlots = [
        { charInstId: 1001, skillIndex: 0, currentEquip: null },
      ];
      await manager.squadFormation({ squadId: 1, slots: newSlots });

      expect(mockPlayer._playerdata.troop!.squads[1].slots).toEqual(newSlots);
      expect(emitSpy).toHaveBeenCalledWith("SquadFormation", []);
    });
  });

  describe("changeSquadName", () => {
    it("应该更新指定编队的名称", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.changeSquadName({ squadId: 1, name: "新编队名" });

      expect(mockPlayer._playerdata.troop!.squads[1].name).toBe("新编队名");
    });
  });

  describe("decomposePotentialItem", () => {
    it("应该按稀有度分解潜能物品并触发 items:use 与 items:get 事件", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      // rarity=5 -> 10 个 shard_5;inventory 中 pot_001 有 3 个 -> 共 30 个
      const result = await manager.decomposePotentialItem({
        charInstIdList: ["1001"],
      });

      expect(result).toEqual([{ id: "shard_5", count: 30 }]);
      expect(emitSpy).toHaveBeenCalledWith(
        "items:use",
        [[{ id: "pot_001", count: 3 }]]
      );
      expect(emitSpy).toHaveBeenCalledWith(
        "items:get",
        [[{ id: "shard_5", count: 30 }]]
      );
    });
  });

  describe("decomposeClassicPotentialItem", () => {
    it("应该分解经典潜能物品并触发事件", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      // rarity=5 -> 5 个 classic_shard_5;inventory 中 pot_classic_001 有 2 个 -> 共 10 个
      const result = await manager.decomposeClassicPotentialItem({
        charInstIdList: ["1001"],
      });

      expect(result).toEqual([{ id: "classic_shard_5", count: 10 }]);
      expect(emitSpy).toHaveBeenCalledWith(
        "items:use",
        [[{ id: "pot_classic_001", count: 2 }]]
      );
      expect(emitSpy).toHaveBeenCalledWith(
        "items:get",
        [[{ id: "classic_shard_5", count: 10 }]]
      );
    });
  });

  describe("addonStoryUnlock", () => {
    it("应该解锁指定干员的附加故事并记录时间戳", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.addonStoryUnlock({
        charId: "char_001",
        storyId: "story_001",
      });

      const story = mockPlayer._playerdata.troop!.addon!.char_001.story;
      expect(story).toBeDefined();
      expect(story!.story_001).toBeDefined();
      expect(story!.story_001.fts).toBe(1234567890);
      expect(story!.story_001.rts).toBe(1234567890);
    });

    it("应该同步发放密录对应勋章并返回勋章 ID（对照官服抓包）", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const medalId = await manager.addonStoryUnlock({
        charId: "char_001",
        storyId: "story_001",
      });

      expect(medalId).toBe("medal_story_char_001");
      const medal = mockPlayer._playerdata.medal!.medals.medal_story_char_001;
      expect(medal).toBeDefined();
      expect(medal.id).toBe("medal_story_char_001");
      expect(medal.val).toEqual([]);
      expect(medal.fts).toBe(1234567890);
      expect(medal.rts).toBe(-1);
    });

    it("无对应勋章配置时返回 null 且不写勋章", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const medalId = await manager.addonStoryUnlock({
        charId: "char_unknown",
        storyId: "story_unknown",
      });

      expect(medalId).toBeNull();
      expect(mockPlayer._playerdata.medal).toBeUndefined();
    });
  });

  describe("addonStageBattleStart", () => {
    it("应该触发 battle:start 事件并携带关卡与编队信息", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const squad = {
        squadId: "1",
        name: "test",
        slots: [],
      };
      await manager.addonStageBattleStart({
        charId: "char_001",
        stageId: "stage_001",
        squad,
        stageType: "STORY",
      });

      const battleStartCalls = emitSpy.mock.calls.filter(
        (c) => c[0] === "battle:start"
      );
      expect(battleStartCalls.length).toBe(1);
      expect(battleStartCalls[0][1][0].stageId).toBe("stage_001");
      expect(battleStartCalls[0][1][0].squad).toBe(squad);
    });
  });

  describe("addonStageBattleFinish", () => {
    it("应该触发 battle:finish 事件并原样传递参数与回调", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const args = {
        data: "test_data",
        battleData: { isCheat: "0", completeTime: 100 },
      };
      await manager.addonStageBattleFinish(args);

      expect(emitSpy).toHaveBeenCalledWith("battle:finish", [
        args,
        expect.any(Function),
      ]);
    });

    it("应通过回调回传战斗结算结果", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const mockResult = {
        rewards: [{ id: "mat_001", type: "MATERIAL", count: 1 }],
        firstRewards: [],
      };
      mockTrigger.on(
        "battle:finish",
        (([args, cb]: [any, any]) => {
          cb(mockResult);
        }) as any
      );

      const result = await manager.addonStageBattleFinish({
        data: "test_data",
        battleData: { isCheat: "0", completeTime: 100 },
      });

      expect(result).toEqual(mockResult);
    });
  });

  describe("fix", () => {
    it("应该为干员补充缺失的技能与装备信息", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.fix();

      const char = mockPlayer._playerdata.troop!.chars[1001];
      // skills 应被补充为 excel 中定义的技能
      expect(char.skills!.length).toBe(1);
      expect(char.skills![0].skillId).toBe("sk1");
      // defaultSkillIndex 原为 -1,存在 skills 时应被修正为 0
      expect(char.defaultSkillIndex).toBe(0);
      // equip 应根据 UniequipTable 初始化
      expect(char.equip!.equip_001).toBeDefined();
      expect(char.equip!.equip_001.hide).toBe(1);
      expect(char.equip!.equip_001.locked).toBe(1);
    });

    it("tmpl 变体按各自 charId 回填 equip", async () => {
      mockPlayer._playerdata.troop!.chars[1001].tmpl = {
        char_001_alt: {
          skinId: "char_001_alt#1",
          defaultSkillIndex: 0,
          skills: [],
          currentEquip: null,
          equip: {},
        },
      };
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.fix();

      const patch = mockPlayer._playerdata.troop!.chars[1001].tmpl!
        .char_001_alt as any;
      // 归属 char_001_alt 的模组被回填；归属 char_001 的 base 模组不进 tmpl
      expect(patch.equip.equip_tmpl_001).toBeDefined();
      expect(patch.equip.equip_tmpl_001.hide).toBe(1);
      expect(patch.equip.equip_tmpl_001.locked).toBe(1);
      expect(patch.equip.equip_001).toBeUndefined();
    });
  });

  describe("decomposePotentialItem 字符串 rarity（2026-08-09 修复）", () => {
    it('rarity 为 "TIER_5" 字符串时应转索引分解（原 items["TIER_5"] undefined 500）', async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );
      // char_002 的 rarity 为字符串 "TIER_5"，items 表按数值键 5 —— 修复后应正确命中
      const result = await manager.decomposePotentialItem({
        charInstIdList: ["1002"],
      });
      // TIER_5 → 索引 4 → items[4] shard_4 count 5 × 3（pot_001 库存）= 15
      expect(result).toEqual([{ id: "shard_4", count: 15 }]);
    });

    it("不存在的干员应跳过而非 500", async () => {
      const manager = new TroopManager(
        mockPlayer as any,
        mockTrigger as any
      );
      const result = await manager.decomposePotentialItem({
        charInstIdList: ["99999"],
      });
      expect(result).toEqual([]);
    });
  });
});
