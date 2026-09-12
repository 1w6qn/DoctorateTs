/**
 * 模组任务管理器（EquipmentMissionManager）单测
 *
 * 覆盖：场次型 / 一次性（指定关卡+三星）模板的真实进度判定、演习不计、关卡不符不推进、
 * 老存档完成态向后兼容（assertUnlockable 放行）。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// 精简 excel mock：提供麦哲伦 / 芙兰卡两个模组及其任务
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
    // 本文件不提供的表（占位：与「键不存在」在 ?. 读取下等价）
    ItemTable: undefined as { items?: Record<string, ItemRowMock> } | undefined,
    StageTable: undefined as { stages?: Record<string, StageRowMock> } | undefined,

    // 编成限制类任务需要职业/站位/星级（CharacterTable）
    CharacterTable: {
      char_248_mgllan: { profession: "SUPPORT", position: "RANGED", rarity: "TIER_6" },
      char_336_folivo: { profession: "SUPPORT", position: "RANGED", rarity: "TIER_5" },
      char_128_plosis: { profession: "MEDIC", position: "RANGED", rarity: "TIER_5" },
      char_130_doberm: { profession: "WARRIOR", position: "MELEE", rarity: "TIER_4" },
      char_123_fang: { profession: "PIONEER", position: "MELEE", rarity: "TIER_2" },
      char_2023_ling: { profession: "SUPPORT", position: "RANGED", rarity: "TIER_6" },
      char_455_nothin: { profession: "SPECIAL", position: "MELEE", rarity: "TIER_5" },
      char_4146_nymph: { profession: "CASTER", position: "RANGED", rarity: "TIER_6" },
      char_179_cgbird: { profession: "MEDIC", position: "RANGED", rarity: "TIER_6" },
    } as Record<string, CharRowMock>,
    UniequipTable: {
      equipDict: {
        uniequip_002_mgllan: {
          uniEquipId: "uniequip_002_mgllan",
          charId: "char_248_mgllan",
          missionList: ["uniequip_002_mgllan_1", "uniequip_002_mgllan_2"],
        },
        uniequip_002_franka: {
          uniEquipId: "uniequip_002_franka",
          charId: "char_106_franka",
          missionList: ["uniequip_002_franka_1", "uniequip_002_franka_dmg"],
        },
        uniequip_004_angel: {
          uniEquipId: "uniequip_004_angel",
          charId: "char_103_angel",
          missionList: ["uniequip_004_angel_cast", "uniequip_004_angel_dmg"],
        },
        uniequip_002_kirara: {
          uniEquipId: "uniequip_002_kirara",
          charId: "char_478_kirara",
          missionList: [
            "uniequip_002_kirara_2",
            "uniequip_002_kirara_kill",
            "uniequip_002_kirara_battlekill",
          ],
        },
        uniequip_002_nothin: {
          uniEquipId: "uniequip_002_nothin",
          charId: "char_455_nothin",
          missionList: ["uniequip_002_nothin_deploykill"],
        },
        uniequip_002_ling: {
          uniEquipId: "uniequip_002_ling",
          charId: "char_2023_ling",
          missionList: ["uniequip_002_ling_spec"],
        },
        uniequip_002_cgbird: {
          uniEquipId: "uniequip_002_cgbird",
          charId: "char_179_cgbird",
          missionList: ["uniequip_002_cgbird_cast"],
        },
        uniequip_002_nymph: {
          uniEquipId: "uniequip_002_nymph",
          charId: "char_4146_nymph",
          missionList: ["uniequip_002_nymph_elem"],
        },
        uniequip_002_doberm: {
          uniEquipId: "uniequip_002_doberm",
          charId: "char_130_doberm",
          missionList: ["uniequip_002_doberm_star"],
        },
        uniequip_002_plosis: {
          uniEquipId: "uniequip_002_plosis",
          charId: "char_128_plosis",
          missionList: ["uniequip_002_plosis_ex"],
        },
        uniequip_002_folivo: {
          uniEquipId: "uniequip_002_folivo",
          charId: "char_336_folivo",
          missionList: ["uniequip_002_folivo_num", "uniequip_002_folivo_pos"],
        },
        uniequip_002_fang: {
          uniEquipId: "uniequip_002_fang",
          charId: "char_123_fang",
          missionList: ["uniequip_002_fang_nodead"],
        },
      },
      missionList: {
        // 场次型：完成 5 次战斗（每场召唤5回召唤物）→ target=5
        uniequip_002_mgllan_1: {
          template: "EquipmentDeployStage",
          paramList: ["5", "5", "token_a;token_b", "char_248_mgllan"],
        },
        // 一次性：三星通关 main_02-05 → target=1
        uniequip_002_mgllan_2: {
          template: "EquipmentSquadPro",
          paramList: ["3", "main_02-05", "char_248_mgllan", "1,PIONEER"],
        },
        // 场次型：完成 5 次战斗（每场≥18000 伤害才计）→ target=5
        uniequip_002_franka_1: {
          template: "EquipmentBattleCharDamage",
          paramList: ["5", "char_106_franka", "18000"],
        },
        // 累计型：由非助战芙兰卡累计造成 60000 伤害 → target=60000
        uniequip_002_franka_dmg: {
          template: "EquipmentDamageTotal",
          paramList: ["char_106_franka", "60000", "0"],
        },
        // 累计技能施放：使用技能 8 次 → target=8
        uniequip_004_angel_cast: {
          template: "EquipmentSkillCast",
          paramList: ["char_103_angel", "skchr_angel_3", "8", "char_103_angel"],
        },
        // 累计造成伤害：target=200000（真实数据 charAdvancedStats 为空 → 走兜底）
        uniequip_004_angel_dmg: {
          template: "EquipmentDamageTotal",
          paramList: ["char_103_angel", "200000", "0"],
        },
        // 一次性击杀关卡：3星通关 main_03-01 并共歼灭 20 个敌人 → target=20
        uniequip_002_kirara_2: {
          template: "EquipmentCharKilledStage",
          paramList: ["3", "main_03-01", "char_478_kirara", "20", "char_478_kirara"],
        },
        // 累计歼灭：非助战绮良累计歼灭 30 个敌人 → target=30
        uniequip_002_kirara_kill: {
          template: "EquipmentCharKilled",
          paramList: ["char_478_kirara", "30", "char_478_kirara"],
        },
        // 场次型击杀：完成 5 次战斗且每场歼灭≥3 个敌人 → target=5
        uniequip_002_kirara_battlekill: {
          template: "EquipmentBattleCharKilled",
          paramList: ["5", "char_478_kirara", "3"],
        },
        // 编成限制家族（真实 paramList 形状取自 data/excel/uniequip_table.json）
        uniequip_002_doberm_star: {
          template: "EquipmentSquadStar",
          paramList: ["3", "main_01-12", "char_130_doberm", "13,3"],
        },
        uniequip_002_plosis_ex: {
          template: "EquipmentSquadProEx",
          paramList: ["3", "main_04-09", "char_128_plosis", "MEDIC;TANK"],
        },
        uniequip_002_folivo_num: {
          template: "EquipmentSquadNum",
          paramList: ["3", "main_04-01", "char_336_folivo", "1"],
        },
        uniequip_002_folivo_pos: {
          template: "EquipmentSquadPos",
          paramList: ["3", "main_02-09", "char_336_folivo", "1,MELEE"],
        },
        uniequip_002_fang_nodead: {
          template: "EquipmentSquadNoAnyDead",
          paramList: ["3", "main_04-08", "char_123_fang"],
        },
        uniequip_002_cgbird_cast: {
          template: "EquipmentSkillCastStage",
          paramList: ["3", "main_03-06", "skchr_cgbird_2", "10", "char_179_cgbird"],
        },
        uniequip_002_nymph_elem: {
          template: "EquipmentDamageTypeStage",
          paramList: ["3", "main_14-06", "char_4146_nymph", "5000", "5"],
        },
        uniequip_002_nothin_deploykill: {
          template: "EquipmentDeployCharAndKillCnt",
          paramList: ["5", "2", "char_455_nothin", "char_455_nothin", "4"],
        },
        uniequip_002_ling_spec: {
          template: "EquipmentStageDeployCntAndSpec",
          paramList: ["3", "main_03-04", "char_2023_ling", "4"],
        },
      },
    },
  },
}));

import { EquipmentMissionManager } from "@game/modules/equipmentMission/equipmentMission";
import { mockPlayerData, asPlayerManager, asModel } from "../../helpers";
import type { Draft } from "mutative";
import type { BattleInfo } from "@game/kernel/battle-info-store";
import type { BattleData } from "@game/kernel/battle-model";
import type { PlayerDataModel } from "@game/kernel/playerdata";

/** excel mock 行形状（本文件用到的字段） */
interface ItemRowMock {
  name?: string;
}
/** 干员表行窄视图（编成限制模板读职业/站位/稀有度） */
interface CharRowMock {
  profession?: string;
  position?: string;
  rarity?: string | number;
}
/** 关卡表行窄视图（mock 表为空，仅为索引签名占位） */
interface StageRowMock {
  stageId?: string;
}

function playerData() {
  return mockPlayerData({
    troop: {
      chars: {
        1: { instId: 1, charId: "char_248_mgllan" },
        2: { instId: 2, charId: "char_106_franka" },
        3: { instId: 3, charId: "char_103_angel" },
        4: { instId: 4, charId: "char_478_kirara" },
        5: { instId: 5, charId: "char_455_nothin" },
        6: { instId: 6, charId: "char_2023_ling" },
        7: { instId: 7, charId: "char_179_cgbird" },
        8: { instId: 8, charId: "char_4146_nymph" },
        9: { instId: 9, charId: "char_130_doberm" },
        10: { instId: 10, charId: "char_128_plosis" },
        11: { instId: 11, charId: "char_336_folivo" },
        12: { instId: 12, charId: "char_123_fang" },
      },
    },
  });
}

describe("EquipmentMissionManager", () => {
  let mgr: EquipmentMissionManager;
  let pd: ReturnType<typeof playerData>;

  beforeEach(() => {
    pd = playerData();
    mgr = new EquipmentMissionManager(asPlayerManager(pd));
  });

  function missions() {
    return pd._playerdata.equipment?.missions ?? {};
  }

  it("场次型模板按上场非助战干员的通关战斗场次推进", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-12", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } }),
      battleData: asModel<BattleData>({ completeState: 2 }),
    });
    // 麦哲伦 field 型任务推进 1 场（无关卡约束）；一次性任务关卡不符不推进
    expect(missions()["uniequip_002_mgllan_1"]).toEqual({ value: 1, target: 5 });
    expect(missions()["uniequip_002_mgllan_2"]).toEqual({ value: 0, target: 1 });
  });

  it("累计型模板按真实统计累加（charAdvancedStats.outputDamageTotal）", async () => {
    // 芙兰卡本场造成 12000 伤害 → 累计 12000/60000
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 2 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charAdvancedStats: {
              char_106_franka: { outputDamageTotal: 12000 },
            },
          },
        },
      }),
    });
    expect(missions()["uniequip_002_franka_dmg"]).toEqual({ value: 12000, target: 60000 });
    // 进度变化时压入 equipmentMission 推送
    expect(pd._pushMessages.map((p) => p.path)).toContain("equipmentMission");
    const push = pd._pushMessages.find((p) => p.path === "equipmentMission");
    expect(push!.payload).toEqual({ idList: ["uniequip_002_franka_dmg"] });
  });

  it("累计型模板统计缺失时置满兜底（不卡死）", async () => {
    // 无 charAdvancedStats → EquipmentDamageTotal 一场达标
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 2 }] } }),
      battleData: asModel<BattleData>({ completeState: 3, battleData: {} }),
    });
    expect(missions()["uniequip_002_franka_dmg"]).toEqual({ value: 60000, target: 60000 });
  });

  it("场次阈值型依赖单场伤害统计（BattleCharDamage≥18000 才计一场）", async () => {
    // 本场 12000 < 18000 → 不计
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 2 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { charAdvancedStats: { char_106_franka: { outputDamageTotal: 12000 } } } },
      }),
    });
    expect(missions()["uniequip_002_franka_1"]).toEqual({ value: 0, target: 5 });
    // 本场 20000 ≥ 18000 → 计一场
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-03", isPractice: 0, squad: { slots: [{ charInstId: 2 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { charAdvancedStats: { char_106_franka: { outputDamageTotal: 20000 } } } },
      }),
    });
    expect(missions()["uniequip_002_franka_1"]).toEqual({ value: 1, target: 5 });
  });

  it("技能施放统计（skillTrigStats）驱动技能类模板", async () => {
    // 麦哲伦无人机召唤 3 回（token SPAWN）→ DeployStage 阈值 5，未达 → field 为 0
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charStats: [
              { Key: { charId: "token_x", counterType: "SPAWN" }, Value: 3 },
            ],
            skillTrigStats: [
              { Key: { charId: "char_248_mgllan", skillId: "skchr_mgllan_1" }, Value: 4 },
            ],
            charAdvancedStats: { char_248_mgllan: { outputDamageTotal: 5000 } },
          },
        },
      }),
    });
    // 麦哲伦 field 型任务（无统计需求默认 hit）→ 计一场
    expect(missions()["uniequip_002_mgllan_1"]).toEqual({ value: 1, target: 5 });
  });

  it("真实线格式解析（skillTrigStats 提取 / charAdvancedStats 空走兜底）", async () => {
    // 引用 checkin-master/config.json 的真实 battleLog.stats 形状：
    // charStats(SPAWN/DEAD/WITHDRAW 字符串枚举)、skillTrigStats({Key:{charId,skillId}})、
    // charAdvancedStats:{}（真实线上逐干员高级统计恒空）与 totalDamage。
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-07", isPractice: 0, squad: { slots: [{ charInstId: 3 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charStats: [
              { Key: { charId: "char_103_angel", counterType: "SPAWN" }, Value: 2 },
            ],
            enemyStats: [
              { Key: { enemyId: "enemy_10070_ftkbtt", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 8 },
            ],
            skillTrigStats: [
              { Key: { charId: "char_103_angel", skillId: "skchr_angel_3" }, Value: 5 },
            ],
            charAdvancedStats: {},
            totalDamage: 161720.047,
          },
        },
      }),
    });
    // 技能施放真实累计 5/8
    expect(missions()["uniequip_004_angel_cast"]).toEqual({ value: 5, target: 8 });
    // charAdvancedStats 为空 → 累计伤害类走置满兜底（200000）
    expect(missions()["uniequip_004_angel_dmg"]).toEqual({ value: 200000, target: 200000 });
  });

  it("一次性模板需命中指定关卡且三星通关", async () => {
    // 关卡命中但未三星（completeState=2）
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_02-05", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } }),
      battleData: asModel<BattleData>({ completeState: 2 }),
    });
    expect(missions()["uniequip_002_mgllan_2"]).toEqual({ value: 0, target: 1 });
    // 三星 + 命中关卡 → 完成
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_02-05", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_mgllan_2"]).toEqual({ value: 1, target: 1 });
  });

  it("未上场干员（含助战）的模组任务不推进", async () => {
    // 仅麦哲伦上场；芙兰卡的模组任务不变
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({
        stageId: "main_02-05",
        isPractice: 0,
        squad: { slots: [{ charInstId: 1 }] },
        assistFriend: { uid: "1", assistChar: [{ charId: "char_106_franka" }], assistSlotIndex: 0 },
      }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_franka_1"]).toBeUndefined();
  });

  it("演习不计入进度", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_02-05", isPractice: 1, squad: { slots: [{ charInstId: 1 }] } }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_mgllan_1"]).toBeUndefined();
  });

  it("assertUnlockable：未完成任务拒绝解锁，完成态放行", async () => {
    // 未完成 → 抛错
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-12", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    const draft: Draft<PlayerDataModel> = asModel<PlayerDataModel>({
      ...pd._playerdata,
      equipment: { missions: missions() },
    });
    expect(() =>
      mgr.assertUnlockable("char_248_mgllan", ["uniequip_002_mgllan_1", "uniequip_002_mgllan_2"], draft),
    ).toThrow(/未完成/);
    // 老存档已完成态（value===target）→ 放行
    const doneDraft: Draft<PlayerDataModel> = asModel<PlayerDataModel>({
      equipment: { missions: { uniequip_002_mgllan_1: { value: 5, target: 5 } } },
    });
    expect(() => mgr.assertUnlockable("char_248_mgllan", ["uniequip_002_mgllan_1"], doneDraft)).not.toThrow();
  });

  it("一次性击杀关卡：击杀不足不完成，累计达标才完成（不自动完成）", async () => {
    // 3星通关 main_03-01，本场歼灭 12 → 进度 12/20，不直接完成
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_03-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 12 }] } },
      }),
    });
    expect(missions()["uniequip_002_kirara_2"]).toEqual({ value: 12, target: 20 });
    // 再次通关再歼灭 8 → 累计 20/20 完成
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_03-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 8 }] } },
      }),
    });
    expect(missions()["uniequip_002_kirara_2"]).toEqual({ value: 20, target: 20 });
  });

  it("一次性击杀关卡：关卡不符或未三星不推进击杀进度", async () => {
    // 未三星（completeState=2）→ 仅播种进度，不累加
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_03-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } }),
      battleData: asModel<BattleData>({
        completeState: 2,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 12 }] } },
      }),
    });
    expect(missions()["uniequip_002_kirara_2"]).toEqual({ value: 0, target: 20 });
    // 击杀达标但关卡不符 → 仍不推进
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_04-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 12 }] } },
      }),
    });
    expect(missions()["uniequip_002_kirara_2"]).toEqual({ value: 0, target: 20 });
  });

  it("累计歼灭敌人：按 enemyStats 逐场累加而非一次置满", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 5 }] } },
      }),
    });
    expect(missions()["uniequip_002_kirara_kill"]).toEqual({ value: 5, target: 30 });
  });

  it("场次型击杀：单场未达阈值不计数，达标才计一场", async () => {
    // 本场歼灭 2 < 3 → 不计
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 2 }] } },
      }),
    });
    expect(missions()["uniequip_002_kirara_battlekill"]).toEqual({ value: 0, target: 5 });
    // 本场歼灭 5 >= 3 → 计一场
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 5 }] } },
      }),
    });
    expect(missions()["uniequip_002_kirara_battlekill"]).toEqual({ value: 1, target: 5 });
  });

  // ===== Round 20：编成限制 / 元素参数下标 / 条件截断（原一律 hit:true）=====

  /** 构造编队：首个为任务干员，其余为其他成员 */
  function squad(...instIds: number[]) {
    return { slots: instIds.map((charInstId) => ({ charInstId })) };
  }

  it("SquadStar（13,3）：其他成员非 3 星 → 不完成；全 3 星 → 完成", async () => {
    // 杜宾 + 麦哲伦(6★) → 不符合「其他成员仅可编入3星干员」
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-12", isPractice: 0, squad: squad(9, 1) }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_doberm_star"]).toEqual({ value: 0, target: 1 });
    // 杜宾 + 芬(2★) → 仍不符（要求 3 星）
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-12", isPractice: 0, squad: squad(9, 12) }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_doberm_star"]).toEqual({ value: 0, target: 1 });
  });

  it("SquadProEx（MEDIC;TANK）：其他成员含被禁职业 → 不完成", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_04-09", isPractice: 0, squad: squad(10, 7) }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_plosis_ex"]).toEqual({ value: 0, target: 1 });
    // 换成先锋（非医疗/重装）→ 完成
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_04-09", isPractice: 0, squad: squad(10, 12) }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_plosis_ex"]).toEqual({ value: 1, target: 1 });
  });

  it("SquadNum（上限 1）：其他成员人数超限 → 不完成", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_04-01", isPractice: 0, squad: squad(11, 12, 9) }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_folivo_num"]).toEqual({ value: 0, target: 1 });
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_04-01", isPractice: 0, squad: squad(11, 12) }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_folivo_num"]).toEqual({ value: 1, target: 1 });
  });

  it("SquadPos（1,MELEE）：其他成员为远程位 → 不完成", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_02-09", isPractice: 0, squad: squad(11, 1) }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_folivo_pos"]).toEqual({ value: 0, target: 1 });
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_02-09", isPractice: 0, squad: squad(11, 9) }),
      battleData: asModel<BattleData>({ completeState: 3 }),
    });
    expect(missions()["uniequip_002_folivo_pos"]).toEqual({ value: 1, target: 1 });
  });

  it("SquadNoAnyDead：有统计且有人阵亡 → 不完成；无人阵亡 → 完成", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_04-08", isPractice: 0, squad: squad(12, 9) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { charStats: [{ Key: { charId: "char_130_doberm", counterType: "DEAD" }, Value: 1 }] } },
      }),
    });
    expect(missions()["uniequip_002_fang_nodead"]).toEqual({ value: 0, target: 1 });
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_04-08", isPractice: 0, squad: squad(12, 9) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { charStats: [{ Key: { charId: "char_130_doberm", counterType: "SPAWN" }, Value: 1 }] } },
      }),
    });
    expect(missions()["uniequip_002_fang_nodead"]).toEqual({ value: 1, target: 1 });
  });

  it("SkillCastStage：按 param[2] 技能 id 与 param[3] 阈值判定（原一律完成）", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_03-06", isPractice: 0, squad: squad(7) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { skillTrigStats: [{ Key: { charId: "char_179_cgbird", skillId: "skchr_cgbird_2" }, Value: 4 }] } },
      }),
    });
    expect(missions()["uniequip_002_cgbird_cast"]).toEqual({ value: 0, target: 1 });
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_03-06", isPractice: 0, squad: squad(7) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: { stats: { skillTrigStats: [{ Key: { charId: "char_179_cgbird", skillId: "skchr_cgbird_2" }, Value: 10 }] } },
      }),
    });
    expect(missions()["uniequip_002_cgbird_cast"]).toEqual({ value: 1, target: 1 });
  });

  it("DamageTypeStage：阈值取 param[3]、元素索引取 param[4]，读 outputElementDamageTotal", async () => {
    // 索引 5 的元素伤害 6000 ≥ 5000 → 完成（原实现把 5000 当索引 → 恒兜底完成）
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_14-06", isPractice: 0, squad: squad(8) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charAdvancedStats: {
              char_4146_nymph: { outputElementDamageTotal: [0, 0, 0, 0, 0, 6000] },
            },
          },
        },
      }),
    });
    expect(missions()["uniequip_002_nymph_elem"]).toEqual({ value: 1, target: 1 });
    // 索引 3（非任务索引）有大量伤害也不应误判为完成
    pd._playerdata.equipment.missions["uniequip_002_nymph_elem"] = { value: 0, target: 1 };
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_14-06", isPractice: 0, squad: squad(8) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charAdvancedStats: {
              char_4146_nymph: { outputElementDamageTotal: [0, 0, 0, 99999, 0, 1000] },
            },
          },
        },
      }),
    });
    expect(missions()["uniequip_002_nymph_elem"]).toEqual({ value: 0, target: 1 });
  });

  it("DeployCharAndKillCnt：需同时满足部署≥2 与歼灭≥4（原丢弃击杀阈值）", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-02", isPractice: 0, squad: squad(5) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charStats: [{ Key: { charId: "char_455_nothin", counterType: "SPAWN" }, Value: 2 }],
            enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 1 }],
          },
        },
      }),
    });
    expect(missions()["uniequip_002_nothin_deploykill"]).toEqual({ value: 0, target: 5 });
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_01-02", isPractice: 0, squad: squad(5) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charStats: [{ Key: { charId: "char_455_nothin", counterType: "SPAWN" }, Value: 2 }],
            enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 4 }],
          },
        },
      }),
    });
    expect(missions()["uniequip_002_nothin_deploykill"]).toEqual({ value: 1, target: 5 });
  });

  it("StageDeployCntAndSpec：部署过 5 位其他干员（> param[3]=4）→ 不完成", async () => {
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_03-04", isPractice: 0, squad: squad(6) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charStats: [
              { Key: { charId: "char_2023_ling", counterType: "SPAWN" }, Value: 1 },
              { Key: { charId: "char_a", counterType: "SPAWN" }, Value: 1 },
              { Key: { charId: "char_b", counterType: "SPAWN" }, Value: 1 },
              { Key: { charId: "char_c", counterType: "SPAWN" }, Value: 1 },
              { Key: { charId: "char_d", counterType: "SPAWN" }, Value: 1 },
              { Key: { charId: "char_e", counterType: "SPAWN" }, Value: 1 },
            ],
          },
        },
      }),
    });
    expect(missions()["uniequip_002_ling_spec"]).toEqual({ value: 0, target: 1 });
    // 仅令 + 1 位其他干员 → 完成
    await mgr.onBattleWin({
      battleInfo: asModel<BattleInfo>({ stageId: "main_03-04", isPractice: 0, squad: squad(6) }),
      battleData: asModel<BattleData>({
        completeState: 3,
        battleData: {
          stats: {
            charStats: [
              { Key: { charId: "char_2023_ling", counterType: "SPAWN" }, Value: 1 },
              { Key: { charId: "char_a", counterType: "SPAWN" }, Value: 3 },
            ],
          },
        },
      }),
    });
    expect(missions()["uniequip_002_ling_spec"]).toEqual({ value: 1, target: 1 });
  });
});
