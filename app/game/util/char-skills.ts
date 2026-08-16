/**
 * 干员技能解锁工具（等级/精英化驱动）
 *
 * 完全采用官服线格式：
 * - 干员 skills 数组列出该干员 excel 中的全部技能（阿米娅除外，其技能在 tmpl 中）。
 * - 每个技能用 unlock 表示当前是否解锁：1 = 已解锁，0 = 未解锁的官方锁定占位。
 * - 解锁条件以 excel CharacterTable[charId].skills[i].unlockCond.phase 为准，
 *   即当前 evolvePhase >= 所需 phase 时 unlock = 1，否则 unlock = 0。
 * - 官服存档在未精一/未精二时仍会列出未来技能占位（unlock:0），修复/回填时不得删除。
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

/** 单个技能在 excel 中的解锁信息 */
interface ExcelSkillInfo {
  skillId: string;
  /** 解锁所需精英化阶段（0/1/2） */
  phase: number;
}

/**
 * 将 excel 的 phase 字段（数字 0/1/2 或 "PHASE_0"/"PHASE_1"/"PHASE_2"）归一化为数字
 */
function normalizePhase(phase: unknown): number {
  if (typeof phase === "number") return phase;
  if (typeof phase === "string") {
    const n = Number(phase.replace(/^PHASE_/, ""));
    return Number.isFinite(n) ? n : 0;
  }
  return 0;
}

/**
 * 获取干员在 excel 中的全部技能及解锁阶段（阿米娅/无技能干员返回空）
 */
function excelSkillInfos(charId: string): ExcelSkillInfo[] {
  // 阿米娅：技能在升变 tmpl 三形态中，char.skills 恒为空（官方同）
  if (charId === "char_002_amiya") return [];
  const info = (excel.CharacterTable as Record<string, any>)?.[charId];
  const skills = info?.skills;
  if (!Array.isArray(skills) || skills.length === 0) return [];
  return skills
    .filter((s: any) => s?.skillId)
    .map((s: any) => ({
      skillId: s.skillId,
      phase: normalizePhase(s?.unlockCond?.phase),
    }));
}

/**
 * 计算干员当前应解锁的技能 ID 列表（完全按 excel skills[i].unlockCond.phase）
 * @param charId - 干员ID（char_002_amiya 技能在 tmpl，返回空）
 * @param evolvePhase - 精英化阶段（0/1/2）
 * @param level - 等级（官方解锁条件不依赖等级，保留参数以兼容调用方）
 * @returns 应解锁的技能 ID 数组（无技能干员/阿米娅返回空）
 */
export function unlockedSkillIds(
  charId: string,
  evolvePhase: number,
  level: number,
): string[] {
  const phase = Number(evolvePhase) || 0;
  return excelSkillInfos(charId)
    .filter((s) => s.phase <= phase)
    .map((s) => s.skillId);
}

/**
 * 按官方线格式重组干员 skills：
 * - 保留已有条目的 state/specializeLevel/completeUpgradeTime；
 * - 按 excel skills[i].unlockCond.phase 校正 unlock（1=已解锁，0=锁定占位）；
 * - 补齐缺失的全部官方技能（含未解锁占位），移除不在 excel 中且无投入的技能；
 * - 校正 defaultSkillIndex（有技能时须指向已解锁技能；无技能且 dsi 异常 → -1）。
 *
 * 幂等：对已合规官服存档无副作用。移除仅在技能不在 excel 且无专精/训练投入时进行
 * （有投入保留，不破坏数据）。
 * @param char - 干员对象（原地修改）
 * @returns 是否发生变更
 */
export function reconcileCharSkills(char: CharSkillsLike): boolean {
  let changed = false;
  const skills: CharSkillEntry[] = char.skills ?? (char.skills = []);
  const officialSkills = excelSkillInfos(char.charId);
  const officialIds = new Set(officialSkills.map((s) => s.skillId));
  const evolvePhase = Number(char.evolvePhase) || 0;

  // 1. 移除不在 excel 中且无投入的技能（倒序遍历避免索引错位）
  for (let i = skills.length - 1; i >= 0; i--) {
    const s = skills[i];
    if (!s || !s.skillId) continue;
    if (
      !officialIds.has(s.skillId) &&
      (s.specializeLevel ?? 0) === 0 &&
      s.state !== 1
    ) {
      skills.splice(i, 1);
      changed = true;
    }
  }

  // 2. 按 excel 官方技能列表补齐/校正 unlock
  const byId = new Map<string, CharSkillEntry>();
  for (const s of skills) {
    if (s && s.skillId && !byId.has(s.skillId)) byId.set(s.skillId, s);
  }
  for (const info of officialSkills) {
    const expectedUnlock = info.phase <= evolvePhase ? 1 : 0;
    let entry = byId.get(info.skillId);
    if (!entry) {
      entry = {
        skillId: info.skillId,
        unlock: expectedUnlock,
        state: 0,
        specializeLevel: 0,
        completeUpgradeTime: -1,
      };
      byId.set(info.skillId, entry);
      changed = true;
    } else if (entry.unlock !== expectedUnlock) {
      entry.unlock = expectedUnlock;
      changed = true;
    }
  }

  // 3. 按官方顺序重建数组；不在 excel 中但有投入的非官方技能保留在末尾
  const ordered: CharSkillEntry[] = [];
  for (const info of officialSkills) {
    const entry = byId.get(info.skillId);
    if (entry) ordered.push(entry);
  }
  for (const s of skills) {
    if (s && s.skillId && !officialIds.has(s.skillId)) ordered.push(s);
  }
  if (
    ordered.length !== skills.length ||
    ordered.some((s, i) => s !== skills[i])
  ) {
    skills.length = 0;
    skills.push(...ordered);
    changed = true;
  }

  // 4. defaultSkillIndex 校正：有技能时必须指向已解锁技能（unlock === 1）；
  //    无技能时仅当 dsi 已定义且非 -1 才校正为 -1（旧数据 -1 已合规，缺失不动）
  if (skills.length > 0) {
    const firstUnlocked = skills.findIndex((s) => s && s.unlock === 1);
    const validDefault = firstUnlocked >= 0 ? firstUnlocked : 0;
    const current = char.defaultSkillIndex;
    const pointsToUnlocked =
      current !== undefined &&
      current >= 0 &&
      current < skills.length &&
      skills[current]?.unlock === 1;
    if (!pointsToUnlocked) {
      char.defaultSkillIndex = validDefault;
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
