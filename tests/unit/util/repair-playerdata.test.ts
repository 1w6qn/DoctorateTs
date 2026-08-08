import { describe, it, expect, vi } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    CharacterTable: {
      char_001_test1: {
        skills: [{ skillId: "skchr_test1_1", overridePrefabKey: null, overrideTokenKey: null }],
      },
      char_002_amiya: {
        skills: [{ skillId: "skchr_amiya_1", overridePrefabKey: null, overrideTokenKey: null }],
      },
      char_1001_amiya2: {
        skills: [{ skillId: "skchr_amiya2_1", overridePrefabKey: null, overrideTokenKey: null }],
      },
      char_1037_amiya3: {
        skills: [{ skillId: "skchr_amiya3_1", overridePrefabKey: null, overrideTokenKey: null }],
      },
    },
    UniequipTable: {
      charEquip: {
        char_001_test1: ["uniequip_001_test1"],
        char_002_amiya: ["uniequip_001_amiya"],
        char_1001_amiya2: [],
        char_1037_amiya3: [],
      },
    },
  },
}));

import { repairCharStructure } from "../../../app/game/util/repair-playerdata";

describe("repairCharStructure 干员结构修复", () => {
  it("旧生成器结构（currentTmpl:null + 缺字段）应修复为 player_data.json 合规结构", () => {
    const chars: Record<string, any> = {
      "1": {
        instId: 1,
        charId: "char_001_test1",
        favorPoint: 25570,
        potentialRank: 5,
        mainSkillLvl: 7,
        skin: null,
        level: 90,
        exp: 0,
        evolvePhase: 2,
        defaultSkillIndex: -1,
        gainTime: 1700000000,
        skills: [],
        currentTmpl: null,
        tmpl: {},
      },
    };
    repairCharStructure(chars);
    const c = chars["1"];
    // 非阿米娅：删除 currentTmpl/tmpl（卡死根因）
    expect(c.currentTmpl).toBeUndefined();
    expect(c.tmpl).toBeUndefined();
    // 补齐字段
    expect(c.voiceLan).toBe("CN_MANDARIN");
    expect(c.starMark).toBe(0);
    expect(c.equip).toEqual({ uniequip_001_test1: { hide: 0, locked: 0, level: 3 } });
    expect(c.currentEquip).toBe("uniequip_001_test1");
    // skills 空 → 从 excel 补齐满专精
    expect(c.skills).toEqual([
      { skillId: "skchr_test1_1", unlock: 1, state: 0, specializeLevel: 3, completeUpgradeTime: -1 },
    ]);
  });

  it("阿米娅 tmpl 为空应重建三形态（对齐 player_data.json）", () => {
    const chars: Record<string, any> = {
      "1": {
        instId: 1,
        charId: "char_002_amiya",
        favorPoint: 25570,
        potentialRank: 5,
        mainSkillLvl: 7,
        skin: null,
        level: 80,
        exp: 0,
        evolvePhase: 2,
        defaultSkillIndex: -1,
        gainTime: 1700000000,
        skills: [],
        currentTmpl: null,
        tmpl: {},
      },
    };
    repairCharStructure(chars);
    const c = chars["1"];
    expect(c.currentTmpl).toBe("char_002_amiya");
    expect(Object.keys(c.tmpl)).toEqual(["char_002_amiya", "char_1001_amiya2", "char_1037_amiya3"]);
    expect(c.tmpl["char_002_amiya"].skills[0].skillId).toBe("skchr_amiya_1");
    expect(c.tmpl["char_002_amiya"].currentEquip).toBe("uniequip_001_amiya");
  });

  it("合规结构（无 currentTmpl + 字段齐全）应保持幂等（非空 skills/equip 不被覆盖）", () => {
    const chars: Record<string, any> = {
      "1": {
        instId: 1,
        charId: "char_001_test1",
        favorPoint: 25570,
        potentialRank: 5,
        mainSkillLvl: 7,
        skin: null,
        level: 90,
        exp: 0,
        evolvePhase: 2,
        defaultSkillIndex: -1,
        gainTime: 1700000000,
        skills: [{ skillId: "skchr_test1_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 }],
        currentEquip: "uniequip_001_test1",
        equip: { uniequip_001_test1: { hide: 0, locked: 0, level: 1 } },
        voiceLan: "CN_MANDARIN",
        starMark: 0,
      },
    };
    repairCharStructure(chars);
    const c = chars["1"];
    expect(c.currentTmpl).toBeUndefined();
    expect(c.skills).toEqual([{ skillId: "skchr_test1_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 }]); // 有技能不覆盖
    expect(c.equip).toEqual({ uniequip_001_test1: { hide: 0, locked: 0, level: 1 } }); // 非空装备不覆盖
    expect(c.voiceLan).toBe("CN_MANDARIN");
    expect(c.starMark).toBe(0);
  });
});
