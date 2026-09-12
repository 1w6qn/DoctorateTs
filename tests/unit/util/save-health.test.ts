import { describe, it, expect, vi, beforeEach } from "vitest";
import { checkAndRepairSave, hasRepairableIssues, type SaveDataShape } from "@game/kernel/save-health";

/** excel 行夹具视图（门面方法只读取 `name`） */
interface ExcelRowMock {
  name?: string;
}

/** 干员表行夹具视图（本文件提供的字段） */
interface ExcelCharRowMock {
  skills?: { skillId: string; unlockCond?: { phase: number | string; level: number } }[];
  allSkillLvlup?: { unlockCond?: { phase: string | number; level: number } }[];
}

/** 模组表行夹具视图（本文件提供的字段） */
interface UniequipRowMock {
  uniEquipId: string;
  charId: string;
  showEvolvePhase: string;
  unlockEvolvePhase: number;
  unlockLevel: number;
  missionList: string[];
  itemCost: Record<string, number[]>;
}

/**
 * excel 替身夹具视图
 *
 * 门面方法按 excel.ts 实现索引替身表，故各表按可索引形状声明；
 * 本文件未提供的表声明为可选（`this.X?.` 读取，与「键不存在」运行期等价）。
 */
interface ExcelMockFixture {
  getItem(id: string): ExcelRowMock | undefined;
  itemName(id: string): string;
  makeItem(id: string, count: number, type?: string): { id: string; count: number; type?: string };
  charData(charId: string): ExcelCharRowMock | undefined;
  stageData(stageId: string): ExcelRowMock | undefined;
  CharacterTable: Record<string, ExcelCharRowMock>;
  UniequipTable: {
    charEquip: Record<string, string[]>;
    equipDict: Record<string, UniequipRowMock>;
  };
  ItemTable?: { items?: Record<string, ExcelRowMock> };
  StageTable?: { stages?: Record<string, ExcelRowMock> };
}

/** 干员技能条目夹具（与 char-skills 的 CharSkillEntry 同形） */
interface SaveFixtureSkill {
  skillId: string;
  unlock: number;
  state: number;
  specializeLevel: number;
  completeUpgradeTime: number;
}

/** 升变模板子对象夹具（本文件只读有无/键数） */
interface SaveFixturePatch {
  skinId?: string | null;
  skills?: SaveFixtureSkill[];
}

/** 干员条目夹具 */
interface SaveFixtureChar {
  instId?: number;
  charId?: string;
  level?: number;
  evolvePhase?: number;
  defaultSkillIndex?: number;
  skills?: SaveFixtureSkill[] | null;
  equip?: Record<string, { hide: number; locked: number; level: number }> | null;
  currentEquip?: string | null;
  tmpl?: Record<string, SaveFixturePatch> | null;
  currentTmpl?: string | null;
}

/** 训练室受训干员夹具（历史残留 null） */
interface SaveFixtureTrainee {
  state?: number;
  charInstId?: number;
  targetSkill?: number;
}

/**
 * 存档夹具视图（本文件用例的不可信 JSON 输入）
 *
 * 与 `SaveDataShape` 同形但更宽，以容纳夹具的历史形状（全部字段可选、
 * 干员条目可带生成模型未声明的 `instId`/`tmpl` 子对象等）。真实 `SaveDataShape`
 * 可赋给本视图，故 {@link asSaveData} 的单向断言成立；运行期对象不变。
 */
interface SaveFixtureView {
  status?: {
    uid?: string | number;
    nickName?: string;
    nickNumber?: string;
    level?: number;
    exp?: number;
    gold?: number;
  };
  troop?: { chars?: Record<string, SaveFixtureChar | null | undefined> };
  dungeon?: SaveDataShape["dungeon"];
  activity?: SaveDataShape["activity"];
  building?: {
    rooms?: {
      PRIVATE?: Record<
        string,
        { owners?: (number | null)[] | null; comfort?: number } | null | undefined
      >;
      TRAINING?: Record<
        string,
        {
          trainee?: SaveFixtureTrainee | null;
          trainer?: { charInstId?: number; state?: number } | null;
        } | null | undefined
      >;
    };
  };
  dexNav?: {
    character?: Record<string, { charInstId?: number; count?: number } | null | undefined>;
  };
  arkodc?: {
    topics?: Record<
      string,
      | {
          varSeqs?: { [key: string]: number };
          rewards?: { [key: string]: number };
          position?: { x: number; y: number; z: number } | null;
        }
      | null
      | undefined
    >;
  };
}

/** 夹具视图 → 被测入参（单向断言，见 {@link SaveFixtureView}） */
function asSaveData(fixture: SaveFixtureView): SaveDataShape {
  return fixture as SaveDataShape;
}

vi.mock("@excel/excel", (): { default: ExcelMockFixture } => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    CharacterTable: {
      char_001: {
        skills: [
          { skillId: "skchr_test_1", unlockCond: { phase: 0, level: 1 } },
          { skillId: "skchr_test_2", unlockCond: { phase: "PHASE_1", level: 1 } },
        ],
        allSkillLvlup: [
          { unlockCond: { phase: "PHASE_0", level: 1 } },
          { unlockCond: { phase: "PHASE_0", level: 2 } },
        ],
      },
      char_002: {
        skills: [{ skillId: "skchr_2_1", unlockCond: { phase: "PHASE_0", level: 1 } }],
        allSkillLvlup: [{ unlockCond: { phase: "PHASE_0", level: 1 } }],
      },
    },
    UniequipTable: {
      charEquip: { char_999_mod: ["mod_001"] },
      equipDict: {
        mod_001: {
          uniEquipId: "mod_001",
          charId: "char_999_mod",
          showEvolvePhase: "PHASE_2",
          unlockEvolvePhase: 0,
          unlockLevel: 0,
          missionList: [],
          itemCost: { 1: [] },
        },
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
    const issues = checkAndRepairSave(asSaveData(data));
    expect(issues.some((i) => i.path.includes("slot_47") && i.fixed)).toBe(true);
    expect(data.building.rooms.PRIVATE.slot_47.owners).toEqual([]);
    // 合规房间不受影响
    expect(data.building.rooms.PRIVATE.slot_44.owners).toEqual([340]);
  });

  it("缺失必填顶层结构应重建", () => {
    const data = { status: { uid: "1" } };
    // 同一对象引用：类型按存档视图读取（运行期仍是上面的夹具，被 checkAndRepairSave 原地重建）
    const store = asSaveData(data);
    const issues = checkAndRepairSave(store);
    for (const key of ["troop", "dungeon", "activity", "building"] as const) {
      expect(store[key]).toBeDefined();
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
    const issues = checkAndRepairSave(asSaveData(data));
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
    checkAndRepairSave(asSaveData(data));
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
            skills: [
              { skillId: "skchr_test_1", unlock: 1, state: 0, specializeLevel: 0, completeUpgradeTime: -1 },
              { skillId: "skchr_test_2", unlock: 0, state: 0, specializeLevel: 0, completeUpgradeTime: -1 },
            ],
          },
        },
      },
      dungeon: {},
      activity: {},
      building: { rooms: { PRIVATE: { slot_1: { owners: [1] } } } },
    };
    const issues = checkAndRepairSave(asSaveData(data));
    expect(issues.filter((i) => i.fixed)).toHaveLength(0);
    expect(hasRepairableIssues(asSaveData(data))).toBe(false);
  });

  it("非对象根节点应标记不可修复", () => {
    // 非对象根节点：原始 JSON 读取产物为 null（走「不可自动修复」分支）
    const nonObjectRoot: SaveDataShape = JSON.parse("null");
    const issues = checkAndRepairSave(nonObjectRoot);
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
    const issues = checkAndRepairSave(asSaveData(data));
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
    checkAndRepairSave(asSaveData(data));
    expect(data.dexNav.character.char_ghost).toBeUndefined();
    expect(data.dexNav.character.char_002).toBeDefined();
  });

  it("currentTmpl 自引用且 tmpl 为空（onCharGet 旧发放结构）应移除模板字段", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "380": { instId: 380, charId: "char_4178_alanna", currentTmpl: "char_4178_alanna", tmpl: {} },
          "381": { instId: 381, charId: "char_4026_vulpis" } as SaveFixtureChar,
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(asSaveData(data));
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
    checkAndRepairSave(asSaveData(data));
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
    checkAndRepairSave(asSaveData(data));
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
    const issues = checkAndRepairSave(asSaveData(data));
    expect(data.troop.chars["1"].currentTmpl).toBe("char_1037_amiya3");
    expect(Object.keys(data.troop.chars["1"].tmpl)).toHaveLength(3);
    expect(issues.filter((i) => i.fixed && i.path.includes("troop.chars"))).toHaveLength(0);
  });

  it("空 skills 干员应按官服线格式回填全部技能（含 unlock:0 锁定占位）", () => {
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
            skills: [] as SaveFixtureSkill[],
          },
          "381": {
            instId: 381,
            charId: "char_001",
            level: 1,
            evolvePhase: 1, // 精1 → 技能1+2 均解锁
            defaultSkillIndex: -1,
            skills: [] as SaveFixtureSkill[],
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(asSaveData(data));
    // E0：官方线格式仍列出全部技能，技能2 为 unlock:0 锁定占位
    expect(data.troop.chars["380"].skills.map((s) => s.skillId)).toEqual([
      "skchr_test_1",
      "skchr_test_2",
    ]);
    expect(data.troop.chars["380"].skills[0].unlock).toBe(1);
    expect(data.troop.chars["380"].skills[1].unlock).toBe(0);
    expect(data.troop.chars["380"].defaultSkillIndex).toBe(0);
    // E1：技能2 解锁，unlock 置 1
    expect(data.troop.chars["381"].skills.map((s) => s.skillId)).toEqual([
      "skchr_test_1",
      "skchr_test_2",
    ]);
    expect(data.troop.chars["381"].skills[1].unlock).toBe(1);
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
    const issues = checkAndRepairSave(asSaveData(data));
    expect(issues.filter((i) => i.path.includes("troop.chars[2].skills"))).toHaveLength(0);
  });

  it("E0 干员带技能2（旧规则多发放 unlock:1）应按官服策略改为锁定占位 unlock:0", () => {
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
    const issues = checkAndRepairSave(asSaveData(data));
    // 完全采用官服线格式：技能2 保留为 unlock:0 锁定占位，而不是删除
    expect(data.troop.chars["380"].skills.map((s) => s.skillId)).toEqual([
      "skchr_test_1",
      "skchr_test_2",
    ]);
    expect(data.troop.chars["380"].skills[1].unlock).toBe(0);
    expect(issues.some((i) => i.path.includes("troop.chars[380].skills") && i.fixed)).toBe(true);
  });

  it("官服存档带 unlock:0 锁定技能占位应保留（不触发技能修复）", () => {
    const data = {
      status: { uid: "2222" },
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
              { skillId: "skchr_test_2", unlock: 0, state: 0, specializeLevel: 0, completeUpgradeTime: -1 },
            ],
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(asSaveData(data));
    // 官方线格式：未解锁技能以 unlock:0 占位，不应被健康检查移除
    expect(data.troop.chars["380"].skills.map((s) => s.skillId)).toEqual([
      "skchr_test_1",
      "skchr_test_2",
    ]);
    expect(data.troop.chars["380"].skills[1].unlock).toBe(0);
    expect(issues.some((i) => i.path.includes("skills") && i.fixed)).toBe(false);
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
    checkAndRepairSave(asSaveData(data));
    // 技能2 有专精 2 → 保留；按官服策略未精一时 unlock 校正为 0 占位
    expect(data.troop.chars["380"].skills.map((s) => s.skillId)).toEqual([
      "skchr_test_1",
      "skchr_test_2",
    ]);
    expect(data.troop.chars["380"].skills[1].unlock).toBe(0);
    expect(data.troop.chars["380"].skills[1].specializeLevel).toBe(2);
    // 默认技能不能指向锁定占位，应校正到第一个已解锁技能
    expect(data.troop.chars["380"].defaultSkillIndex).toBe(0);
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
              trainee: null as SaveFixtureTrainee | null,
              trainer: { charInstId: 210, state: 3 },
            },
          },
        },
      },
    };
    const issues = checkAndRepairSave(asSaveData(data));
    const trainee = data.building.rooms.TRAINING.slot_13.trainee;
    expect(trainee).not.toBeNull();
    expect(trainee!.charInstId).toBe(-1);
    expect(trainee!.state).toBe(0); // EMPTY 官方空态
    expect(trainee!.targetSkill).toBe(-1);
    expect(issues.some((i) => i.path.includes("trainee") && i.fixed)).toBe(true);
    // 合规 trainer 不受影响
    expect(data.building.rooms.TRAINING.slot_13.trainer.charInstId).toBe(210);
  });

  it("arkodc.topics 含 undefined 键（旧 restart 缺 topicId 残留）应移除", () => {
    const data = {
      status: { uid: "1" },
      troop: { chars: {} },
      dungeon: {},
      activity: {},
      building: {},
      arkodc: {
        topics: {
          "undefined": { varSeqs: {}, rewards: {}, position: null },
          ark_odc_act53side: { varSeqs: {}, rewards: {}, position: null },
        },
      },
    };
    const issues = checkAndRepairSave(asSaveData(data));
    expect(data.arkodc.topics["undefined"]).toBeUndefined();
    // 合规主题保留，且 position null 重置为原点
    expect(data.arkodc.topics["ark_odc_act53side"]).toBeDefined();
    expect(data.arkodc.topics["ark_odc_act53side"].position).toEqual({ x: 0, y: 0, z: 0 });
    expect(issues.some((i) => i.path.includes("undefined") && i.fixed)).toBe(true);
  });

  it("精二干员有模组却 hide=1（历史精二未处理模组）应自动显示并设 currentEquip", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          // 精二 + 已有模组条目但 hide=1（错误隐藏）
          "10": {
            instId: 10,
            charId: "char_999_mod",
            level: 50,
            evolvePhase: 2,
            defaultSkillIndex: 0,
            currentEquip: null,
            equip: { mod_001: { hide: 1, locked: 0, level: 1 } },
          },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(asSaveData(data));
    const mod = data.troop.chars["10"].equip.mod_001;
    expect(mod.hide).toBe(0); // 精二后显示
    expect(mod.locked).toBe(0); // 已解锁的保持
    expect(data.troop.chars["10"].currentEquip).toBe("mod_001"); // currentEquip 补上
    expect(issues.some((i) => i.path === "troop.chars[10].equip" && i.fixed)).toBe(true);
  });

  it("无模组干员/阿米娅不应被模组健康检查改动", () => {
    const data = {
      status: { uid: "1" },
      troop: {
        chars: {
          "2": { instId: 2, charId: "char_002", level: 1, evolvePhase: 0, defaultSkillIndex: 0, equip: {} },
          "3": { instId: 3, charId: "char_002_amiya", level: 90, evolvePhase: 2, defaultSkillIndex: 0, equip: {} },
        },
      },
      dungeon: {},
      activity: {},
      building: {},
    };
    const issues = checkAndRepairSave(asSaveData(data));
    expect(issues.some((i) => i.path.includes("equip") && i.fixed)).toBe(false);
  });
});
