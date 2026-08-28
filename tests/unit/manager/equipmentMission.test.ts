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
      },
    },
  },
}));

import { EquipmentMissionManager } from "@game/modules/equipmentMission/equipmentMission";
import { mockPlayerData } from "../../helpers";

function playerData() {
  return mockPlayerData({
    troop: {
      chars: {
        1: { instId: 1, charId: "char_248_mgllan" },
        2: { instId: 2, charId: "char_106_franka" },
        3: { instId: 3, charId: "char_103_angel" },
        4: { instId: 4, charId: "char_478_kirara" },
      },
    },
  } as any);
}

describe("EquipmentMissionManager", () => {
  let mgr: EquipmentMissionManager;
  let pd: ReturnType<typeof playerData>;

  beforeEach(() => {
    pd = playerData();
    mgr = new EquipmentMissionManager(pd as any);
  });

  function missions() {
    return (pd._playerdata as any).equipment?.missions ?? {};
  }

  it("场次型模板按上场非助战干员的通关战斗场次推进", async () => {
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-12", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } } as any,
      battleData: { completeState: 2 } as any,
    });
    // 麦哲伦 field 型任务推进 1 场（无关卡约束）；一次性任务关卡不符不推进
    expect(missions()["uniequip_002_mgllan_1"]).toEqual({ value: 1, target: 5 });
    expect(missions()["uniequip_002_mgllan_2"]).toEqual({ value: 0, target: 1 });
  });

  it("累计型模板按真实统计累加（charAdvancedStats.outputDamageTotal）", async () => {
    // 芙兰卡本场造成 12000 伤害 → 累计 12000/60000
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 2 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: {
          stats: {
            charAdvancedStats: {
              char_106_franka: { outputDamageTotal: 12000 },
            },
          },
        },
      } as any,
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
      battleInfo: { stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 2 }] } } as any,
      battleData: { completeState: 3, battleData: {} } as any,
    });
    expect(missions()["uniequip_002_franka_dmg"]).toEqual({ value: 60000, target: 60000 });
  });

  it("场次阈值型依赖单场伤害统计（BattleCharDamage≥18000 才计一场）", async () => {
    // 本场 12000 < 18000 → 不计
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 2 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: { stats: { charAdvancedStats: { char_106_franka: { outputDamageTotal: 12000 } } } },
      } as any,
    });
    expect(missions()["uniequip_002_franka_1"]).toEqual({ value: 0, target: 5 });
    // 本场 20000 ≥ 18000 → 计一场
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-03", isPractice: 0, squad: { slots: [{ charInstId: 2 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: { stats: { charAdvancedStats: { char_106_franka: { outputDamageTotal: 20000 } } } },
      } as any,
    });
    expect(missions()["uniequip_002_franka_1"]).toEqual({ value: 1, target: 5 });
  });

  it("技能施放统计（skillTrigStats）驱动技能类模板", async () => {
    // 麦哲伦无人机召唤 3 回（token SPAWN）→ DeployStage 阈值 5，未达 → field 为 0
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } } as any,
      battleData: {
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
      } as any,
    });
    // 麦哲伦 field 型任务（无统计需求默认 hit）→ 计一场
    expect(missions()["uniequip_002_mgllan_1"]).toEqual({ value: 1, target: 5 });
  });

  it("真实线格式解析（skillTrigStats 提取 / charAdvancedStats 空走兜底）", async () => {
    // 引用 checkin-master/config.json 的真实 battleLog.stats 形状：
    // charStats(SPAWN/DEAD/WITHDRAW 字符串枚举)、skillTrigStats({Key:{charId,skillId}})、
    // charAdvancedStats:{}（真实线上逐干员高级统计恒空）与 totalDamage。
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-07", isPractice: 0, squad: { slots: [{ charInstId: 3 }] } } as any,
      battleData: {
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
      } as any,
    });
    // 技能施放真实累计 5/8
    expect(missions()["uniequip_004_angel_cast"]).toEqual({ value: 5, target: 8 });
    // charAdvancedStats 为空 → 累计伤害类走置满兜底（200000）
    expect(missions()["uniequip_004_angel_dmg"]).toEqual({ value: 200000, target: 200000 });
  });

  it("一次性模板需命中指定关卡且三星通关", async () => {
    // 关卡命中但未三星（completeState=2）
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_02-05", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } } as any,
      battleData: { completeState: 2 } as any,
    });
    expect(missions()["uniequip_002_mgllan_2"]).toEqual({ value: 0, target: 1 });
    // 三星 + 命中关卡 → 完成
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_02-05", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } } as any,
      battleData: { completeState: 3 } as any,
    });
    expect(missions()["uniequip_002_mgllan_2"]).toEqual({ value: 1, target: 1 });
  });

  it("未上场干员（含助战）的模组任务不推进", async () => {
    // 仅麦哲伦上场；芙兰卡的模组任务不变
    await mgr.onBattleWin({
      battleInfo: {
        stageId: "main_02-05",
        isPractice: 0,
        squad: { slots: [{ charInstId: 1 }] },
        assistFriend: { uid: "1", assistChar: [{ charId: "char_106_franka" }], assistSlotIndex: 0 },
      } as any,
      battleData: { completeState: 3 } as any,
    });
    expect(missions()["uniequip_002_franka_1"]).toBeUndefined();
  });

  it("演习不计入进度", async () => {
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_02-05", isPractice: 1, squad: { slots: [{ charInstId: 1 }] } } as any,
      battleData: { completeState: 3 } as any,
    });
    expect(missions()["uniequip_002_mgllan_1"]).toBeUndefined();
  });

  it("assertUnlockable：未完成任务拒绝解锁，完成态放行", async () => {
    // 未完成 → 抛错
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-12", isPractice: 0, squad: { slots: [{ charInstId: 1 }] } } as any,
      battleData: { completeState: 3 } as any,
    });
    const draft: any = { ...pd._playerdata, equipment: { missions: missions() } };
    expect(() =>
      mgr.assertUnlockable("char_248_mgllan", ["uniequip_002_mgllan_1", "uniequip_002_mgllan_2"], draft),
    ).toThrow(/未完成/);
    // 老存档已完成态（value===target）→ 放行
    const doneDraft: any = {
      equipment: { missions: { uniequip_002_mgllan_1: { value: 5, target: 5 } } },
    };
    expect(() => mgr.assertUnlockable("char_248_mgllan", ["uniequip_002_mgllan_1"], doneDraft)).not.toThrow();
  });

  it("一次性击杀关卡：击杀不足不完成，累计达标才完成（不自动完成）", async () => {
    // 3星通关 main_03-01，本场歼灭 12 → 进度 12/20，不直接完成
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_03-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 12 }] } },
      } as any,
    });
    expect(missions()["uniequip_002_kirara_2"]).toEqual({ value: 12, target: 20 });
    // 再次通关再歼灭 8 → 累计 20/20 完成
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_03-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 8 }] } },
      } as any,
    });
    expect(missions()["uniequip_002_kirara_2"]).toEqual({ value: 20, target: 20 });
  });

  it("一次性击杀关卡：关卡不符或未三星不推进击杀进度", async () => {
    // 未三星（completeState=2）→ 仅播种进度，不累加
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_03-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } } as any,
      battleData: {
        completeState: 2,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 12 }] } },
      } as any,
    });
    expect(missions()["uniequip_002_kirara_2"]).toEqual({ value: 0, target: 20 });
    // 击杀达标但关卡不符 → 仍不推进
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_04-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 12 }] } },
      } as any,
    });
    expect(missions()["uniequip_002_kirara_2"]).toEqual({ value: 0, target: 20 });
  });

  it("累计歼灭敌人：按 enemyStats 逐场累加而非一次置满", async () => {
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 5 }] } },
      } as any,
    });
    expect(missions()["uniequip_002_kirara_kill"]).toEqual({ value: 5, target: 30 });
  });

  it("场次型击杀：单场未达阈值不计数，达标才计一场", async () => {
    // 本场歼灭 2 < 3 → 不计
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-01", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 2 }] } },
      } as any,
    });
    expect(missions()["uniequip_002_kirara_battlekill"]).toEqual({ value: 0, target: 5 });
    // 本场歼灭 5 >= 3 → 计一场
    await mgr.onBattleWin({
      battleInfo: { stageId: "main_01-02", isPractice: 0, squad: { slots: [{ charInstId: 4 }] } } as any,
      battleData: {
        completeState: 3,
        battleData: { stats: { enemyStats: [{ Key: { enemyId: "e", counterType: "HP_ZERO", isInvalidKilled: 0 }, Value: 5 }] } },
      } as any,
    });
    expect(missions()["uniequip_002_kirara_battlekill"]).toEqual({ value: 1, target: 5 });
  });
});