/**
 * 干员技能解锁工具（等级/精英化驱动）
 *
 * 官方规则（test.json 全量 378/378 验证）：技能 i 的解锁条件 =
 * CharacterTable[charId].allSkillLvlup[i].unlockCond（{phase, level}）——
 * 干员 evolvePhase > cond.phase 或（== 且 level >= cond.level）时解锁该技能。
 *
 * ⚠️ 注意：CharacterData_MainSkill 顶层 unlockCond 是另一组数据（主技能等级解锁），
 * 与技能解锁条件不同（两者 1504 处差异，误用会 187/378 不匹配——troop.fix() 历史地雷）。
 */
import excel from "@excel/excel";

const PHASE_NUM: Record<string, number> = {
  PHASE_0: 0,
  PHASE_1: 1,
  PHASE_2: 2,
};

/** 干员技能条目（存档线格式） */
export interface CharSkillEntry {
  skillId: string;
  unlock: number;
  state: number;
  specializeLevel: number;
  completeUpgradeTime: number;
}

/** 干员技能相关字段（兼容 PlayerCharacter 与 save-health 的 any 数据） */
export interface CharSkillsLike {
  charId: string;
  evolvePhase: number;
  level: number;
  skills?: CharSkillEntry[] | null;
  defaultSkillIndex?: number;
}

/**
 * 计算干员当前应解锁的技能 ID 列表（按官方 allSkillLvlup 规则）
 * @param charId - 干员ID（char_002_amiya 技能在 tmpl，返回空）
 * @param evolvePhase - 精英化阶段（0/1/2）
 * @param level - 等级
 * @returns 应解锁的技能 ID 数组（无技能干员/阿米娅返回空）
 */
export function unlockedSkillIds(
  charId: string,
  evolvePhase: number,
  level: number,
): string[] {
  // 阿米娅：技能在升变 tmpl 三形态中，char.skills 恒为空（官方同）
  if (charId === "char_002_amiya") return [];
  const info = (excel.CharacterTable as Record<string, any>)?.[charId];
  const skills = info?.skills;
  if (!skills || !skills.length) return [];
  const out: string[] = [];
  for (let i = 0; i < skills.length; i++) {
    const cond = info.allSkillLvlup?.[i]?.unlockCond;
    if (!cond) {
      out.push(skills[i].skillId);
      continue;
    }
    const condPhase = PHASE_NUM[cond.phase] ?? 0;
    if (
      evolvePhase > condPhase ||
      (evolvePhase === condPhase && level >= (cond.level ?? 1))
    ) {
      out.push(skills[i].skillId);
    }
  }
  return out;
}

/**
 * 按当前等级/精英化重组干员 skills：追加新解锁技能（保留已有条目的
 * state/specializeLevel/completeUpgradeTime，unlock 置 1），校正
 * defaultSkillIndex（有技能且 -1/越界/缺失 → 0；无技能且 dsi 异常 → -1）。
 *
 * 幂等：对已合规干员无副作用。只追加不回收（等级/精英化只会更易解锁）。
 * @param char - 干员对象（原地修改）
 * @returns 是否发生变更
 */
export function reconcileCharSkills(char: CharSkillsLike): boolean {
  let changed = false;
  const skills: CharSkillEntry[] = char.skills ?? (char.skills = []);
  for (const skillId of unlockedSkillIds(
    char.charId,
    char.evolvePhase,
    char.level,
  )) {
    const existing = skills.find((s) => s && s.skillId === skillId);
    if (!existing) {
      skills.push({
        skillId,
        unlock: 1,
        state: 0,
        specializeLevel: 0,
        completeUpgradeTime: -1,
      });
      changed = true;
    } else if (existing.unlock !== 1) {
      existing.unlock = 1;
      changed = true;
    }
  }
  // defaultSkillIndex 校正：有技能时 dsi 必须为合法索引（-1/越界/缺失 → 0）；
  // 无技能时仅当 dsi 已定义且非 -1 才校正为 -1（旧数据 -1 已合规，缺失不动）
  if (skills.length > 0) {
    if (
      char.defaultSkillIndex === undefined ||
      char.defaultSkillIndex < 0 ||
      char.defaultSkillIndex >= skills.length
    ) {
      char.defaultSkillIndex = 0;
      changed = true;
    }
  } else if (
    char.defaultSkillIndex !== undefined &&
    char.defaultSkillIndex !== -1
  ) {
    char.defaultSkillIndex = -1;
    changed = true;
  }
  return changed;
}
