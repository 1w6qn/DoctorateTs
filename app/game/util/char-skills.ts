/**
 * 干员技能解锁工具（等级/精英化驱动）
 *
 * 官方标准规则：技能1 默认解锁；技能2 精1（evolvePhase>=1）解锁；
 * 技能3 精2（evolvePhase>=2）解锁（如有）。
 * ⚠️ 勿用 allSkillLvlup[i].unlockCond / skills[i].unlockCond 作为技能解锁条件——
 * 前者是主技能等级升级条件（所有技能恒为 PHASE_0/l1），后者是专精解锁条件；
 * 两者都与技能解锁无关（test.json 为官服导入快照，技能状态不一致，不可作基准）。
 */
import excel from "@excel/excel";

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
 * 计算干员当前应解锁的技能 ID 列表（标准规则：精1→技能2、精2→技能3）
 * @param charId - 干员ID（char_002_amiya 技能在 tmpl，返回空）
 * @param evolvePhase - 精英化阶段（0/1/2）
 * @param level - 等级（标准规则不依赖等级，保留参数以兼容调用方）
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
    if (i === 0) {
      out.push(skills[i].skillId); // 技能1 默认
    } else if (i === 1 && evolvePhase >= 1) {
      out.push(skills[i].skillId); // 技能2 精1解锁
    } else if (i >= 2 && evolvePhase >= 2) {
      out.push(skills[i].skillId); // 技能3 精2解锁（如有）
    }
  }
  return out;
}

/**
 * 按当前精英化重组干员 skills：追加新解锁技能（保留已有条目的
 * state/specializeLevel/completeUpgradeTime，unlock 置 1），移除当前阶段未解锁
 * 且无投入的技能（标准规则：精1→技能2、精2→技能3——旧规则曾多发放技能2/3），
 * 校正 defaultSkillIndex（有技能且 -1/越界/缺失 → 0；无技能且 dsi 异常 → -1）。
 *
 * 幂等：对已合规干员无副作用。移除仅在技能无专精/训练投入时进行（有投入保留，
 * 不破坏数据）。
 * @param char - 干员对象（原地修改）
 * @returns 是否发生变更
 */
export function reconcileCharSkills(char: CharSkillsLike): boolean {
  let changed = false;
  const skills: CharSkillEntry[] = char.skills ?? (char.skills = []);
  const unlocked = unlockedSkillIds(char.charId, char.evolvePhase, char.level);
  // 移除当前阶段未解锁且无投入的技能（倒序遍历避免索引错位）
  for (let i = skills.length - 1; i >= 0; i--) {
    const s = skills[i];
    if (!s || !s.skillId) continue;
    if (
      !unlocked.includes(s.skillId) &&
      (s.specializeLevel ?? 0) === 0 &&
      s.state !== 1
    ) {
      skills.splice(i, 1);
      changed = true;
    }
  }
  for (const skillId of unlocked) {
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
