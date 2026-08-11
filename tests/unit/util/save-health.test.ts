import { describe, it, expect, vi, beforeEach } from "vitest";
import { checkAndRepairSave, hasRepairableIssues } from "../../../app/game/util/save-health";

vi.mock("@excel/excel", () => ({
  default: {
    CharacterTable: {
      char_001: {
        skills: [{ skillId: "skchr_test_1" }, { skillId: "skchr_test_2" }],
        allSkillLvlup: [
          { unlockCond: { phase: "PHASE_0", level: 1 } },
          { unlockCond: { phase: "PHASE_0", level: 2 } },
        ],
      },
      char_002: {
        skills: [{ skillId: "skchr_2_1" }],
        allSkillLvlup: [{ unlockCond: { phase: "PHASE_0", level: 1 } }],
      },
    },
  },
}));

describe("checkAndRepairSave（存档损坏自动检测与修复）", () => {
  it("PRIVATE.owners 含 null 条目应过滤（setPrivateDormOwner 字段名 bug 残留）", () => {
    const data = {
      status: { uid: "1", nickName: "博士" },
      troop: { chars: {} },
      building: {
        rooms: {
          PRIVATE: {
            slot_47: { owners: [null], comfort: 0 },
            slot_44: { owners: [340], comfort: 0 },
          },
        },
      },
    };
    const issues = checkAndRepairSave(data as any);
    expect(issues.some((i) => i.path.includes("slot_47") && i.fixed)).toBe(true);
    expect(data.building.rooms.PRIVATE.slot_47.owners).toEqual([]);
    // 合规房间不受影响
    expect(data.building.rooms.PRIVATE.slot_44.owners).toEqual([340]);
  });

  it("缺失必填顶层结构应重建", () => {
    const data = { status: { uid: "1" } };
    const issues = checkAndRepairSave(data as any);
    for (const key of ["troop", "dungeon", "activity", "building"]) {
      expect(data[key]).toBeDefined();
    }
    expect(issues.filter((i) => i.fixed).length).toBeGreaterThanOrEqual(3);
  });

  it("troop.chars 内非法干员（缺 charId）应移除", () => {
    const data = {
      status: { uid: "1" },
      troop: { chars: { "1": { instId: 1, charId: "char_001" }, "2": { instId: 2 } } },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    expect(data.troop.chars["2"]).toBeUndefined();
    expect(data.troop.chars["1"]).toBeDefined();
    expect(issues.some((i) => i.path === "troop.chars[2]" && i.fixed)).toBe(true);
  });

  it("status.uid 非字符串应转字符串", () => {
    const data = {
      status: { uid: 2222 },
      troop: {},
      dungeon: {},
      activity: {},
      building: {},
    };
    checkAndRepairSave(data as any);
    expect(data.status.uid).toBe("2222");
  });

  it("合规存档应零修复（幂等）", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "1": {
            instId: 1,
            charId: "char_001",
            level: 1,
            evolvePhase: 0,
            defaultSkillIndex: 0,
            skills: [{ skillId: "skchr_test_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 }],
          },
        },
      },
      dungeon: {},
      activity: {},
      building: { rooms: { PRIVATE: { slot_1: { owners: [1] } } } },
    };
    const issues = checkAndRepairSave(data as any);
    expect(issues.filter((i) => i.fixed)).toHaveLength(0);
    expect(hasRepairableIssues(data)).toBe(false);
  });

  it("非对象根节点应标记不可修复", () => {
    const issues = checkAndRepairSave(null as any);
    expect(issues.some((i) => !i.fixed)).toBe(true);
  });

  it("dexNav.charInstId 悬空应重指向 roster 中正确干员（干员发放重建后残留）", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "2": { instId: 2, charId: "char_002" },
          "101": { instId: 101, charId: "char_101_sora" },
        },
      },
      dexNav: {
        character: {
          // 悬空：指向不存在的 instId
          char_002: { charInstId: 999, count: 3 },
          // 错指：指向其他干员（roster[2] 是 char_002）
          char_101_sora: { charInstId: 2, count: 5 },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    expect(data.dexNav.character.char_002.charInstId).toBe(2);
    expect(data.dexNav.character.char_101_sora.charInstId).toBe(101);
    expect(issues.filter((i) => i.fixed && i.path.startsWith("dexNav"))).toHaveLength(2);
  });

  it("dexNav 孤儿条目（干员不在 roster）应移除", () => {
    const data = {
      status: { uid: "1" },
      troop: { chars: { "2": { instId: 2, charId: "char_002" } } },
      dexNav: { character: { char_002: { charInstId: 2, count: 1 }, char_ghost: { charInstId: 5, count: 9 } } },
      dungeon: {},
      activity: {},
      building: {},
    };
    checkAndRepairSave(data as any);
    expect(data.dexNav.character.char_ghost).toBeUndefined();
    expect(data.dexNav.character.char_002).toBeDefined();
  });

  it("currentTmpl 自引用且 tmpl 为空（onCharGet 旧发放结构）应移除模板字段", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "380": { instId: 380, charId: "char_4178_alanna", currentTmpl: "char_4178_alanna", tmpl: {} },
          "381": { instId: 381, charId: "char_4026_vulpis" },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    expect(data.troop.chars["380"].currentTmpl).toBeUndefined();
    expect(data.troop.chars["380"].tmpl).toBeUndefined();
    // 合规干员（无模板字段）不受影响
    expect(data.troop.chars["381"].currentTmpl).toBeUndefined();
    expect(issues.some((i) => i.path === "troop.chars[380]" && i.fixed)).toBe(true);
  });

  it("currentTmpl 为 null（旧生成器结构）应移除", () => {
    const data = {
      status: { uid: "1" },
      troop: { chars: { "1": { instId: 1, charId: "char_001", currentTmpl: null } } },
      dungeon: {},
      activity: {},
      building: {},
    };
    checkAndRepairSave(data as any);
    expect(data.troop.chars["1"].currentTmpl).toBeUndefined();
  });

  it("currentTmpl 指向 tmpl 中不存在的形态应移除 currentTmpl（保留 tmpl）", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "7": {
            instId: 7,
            charId: "char_007",
            currentTmpl: "char_007_x",
            tmpl: { char_007: { skinId: null, skills: [] } },
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    checkAndRepairSave(data as any);
    expect(data.troop.chars["7"].currentTmpl).toBeUndefined();
    expect(data.troop.chars["7"].tmpl.char_007).toBeDefined();
  });

  it("阿米娅合法多形态模板（currentTmpl 指向 tmpl 内形态）应保留", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "1": {
            instId: 1,
            charId: "char_002_amiya",
            currentTmpl: "char_1037_amiya3",
            tmpl: { char_002_amiya: { skinId: null }, char_1001_amiya2: {}, char_1037_amiya3: {} },
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    expect(data.troop.chars["1"].currentTmpl).toBe("char_1037_amiya3");
    expect(Object.keys(data.troop.chars["1"].tmpl)).toHaveLength(3);
    expect(issues.filter((i) => i.fixed && i.path.includes("troop.chars"))).toHaveLength(0);
  });

  it("空 skills 干员应按精英化回填技能（精1→技能2、精2→技能3）", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "380": {
            instId: 380,
            charId: "char_001",
            level: 2,
            evolvePhase: 0,
            defaultSkillIndex: -1,
            skills: [],
          },
          "381": {
            instId: 381,
            charId: "char_001",
            level: 1,
            evolvePhase: 1, // 精1 → 技能1+2
            defaultSkillIndex: -1,
            skills: [],
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    // E0：仅技能1（标准规则：技能2 需精1）
    expect(data.troop.chars["380"].skills.map((s: any) => s.skillId)).toEqual([
      "skchr_test_1",
    ]);
    expect(data.troop.chars["380"].defaultSkillIndex).toBe(0);
    // E1：技能1+2
    expect(data.troop.chars["381"].skills.map((s: any) => s.skillId)).toEqual([
      "skchr_test_1",
      "skchr_test_2",
    ]);
    expect(issues.some((i) => i.path === "troop.chars[380].skills" && i.fixed)).toBe(true);
  });

  it("技能回填幂等：已合规干员不再修复", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "2": {
            instId: 2,
            charId: "char_002",
            level: 1,
            evolvePhase: 0,
            defaultSkillIndex: 0,
            skills: [{ skillId: "skchr_2_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 }],
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    expect(issues.filter((i) => i.path.includes("troop.chars[2].skills"))).toHaveLength(0);
  });

  it("E0 干员带技能2/3（旧规则多发放）应移除（无投入）", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "380": {
            instId: 380,
            charId: "char_001",
            level: 1,
            evolvePhase: 0,
            defaultSkillIndex: 0,
            skills: [
              { skillId: "skchr_test_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 },
              { skillId: "skchr_test_2", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 },
            ],
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(data as any);
    // E0 仅技能1（技能2 需精1）；无投入 → 移除
    expect(data.troop.chars["380"].skills.map((s: any) => s.skillId)).toEqual([
      "skchr_test_1",
    ]);
    expect(issues.some((i) => i.path.includes("troop.chars[380].skills") && i.fixed)).toBe(true);
  });

  it("有专精投入的技能即使当前阶段未解锁也应保留（不破坏数据）", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "380": {
            instId: 380,
            charId: "char_001",
            level: 1,
            evolvePhase: 0,
            defaultSkillIndex: 1,
            skills: [
              { skillId: "skchr_test_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 },
              { skillId: "skchr_test_2", unlock: 1, state: 0, specializeLevel: 2, completeUpgradeTime: -1 },
            ],
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    checkAndRepairSave(data as any);
    // 技能2 有专精 2 → 保留
    expect(data.troop.chars["380"].skills.map((s: any) => s.skillId)).toEqual([
      "skchr_test_1",
      "skchr_test_2",
    ]);
  });

  it("训练室 trainee 为 null（旧结算残留）应修复为空对象", () => {
    const data = {
      status: { uid: "1" },
      troop: { chars: {} },
      dungeon: {},
      activity: {},
      building: {
        rooms: {
          TRAINING: {
            slot_13: {
              buff: {},
              state: 0,
              lastUpdateTime: 0,
              trainee: null,
              trainer: { charInstId: 210, state: 3 },
            },
          },
        },
      },
    };
    const issues = checkAndRepairSave(data as any);
    const trainee = data.building.rooms.TRAINING.slot_13.trainee;
    expect(trainee).not.toBeNull();
    expect(trainee.charInstId).toBe(-1);
    expect(trainee.state).toBe(0); // EMPTY 官方空态
    expect(trainee.targetSkill).toBe(-1);
    expect(issues.some((i) => i.path.includes("trainee") && i.fixed)).toBe(true);
    // 合规 trainer 不受影响
    expect(data.building.rooms.TRAINING.slot_13.trainer.charInstId).toBe(210);
  });
});
