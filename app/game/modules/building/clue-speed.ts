/**
 * 会客室线索搜集速度引擎（纯函数，无 IO）
 *
 * 官方机制（prts.wiki 会客室页，2026-08-25 全量对齐）：
 * - 每份线索基础生成时间 20 小时（100% 速度基准）
 * - 总速度 = 设施等级基础效率（Lv 107/109/111%）+ 宿舍总氛围档
 *   （≥2000 +5%、≥3000 +10%、≥4000 +15%）+ Σ进驻干员（稀有度 4★+2%/5★+4%/6★+5%、
 *   精英阶段 精1+8%/精2+16%、非涣散 +5%/人）+ 后勤技能（meet_*）
 * - 自有线索库上限 10；对干员搜集，满库仍可搜集，但完成第 11 份后停工并「滞留线索」
 *   （会客室页），腾出空位后滞留线索入库
 */

/** 线索基准生成时长（秒）：20 小时 @100% 速度（会客室页） */
export const CLUE_BASE_SECONDS = 72000;

/** 会客室等级基础效率（107/109/111%，会客室页） */
export const MEETING_PHASE_EFFICIENCY = [1.07, 1.09, 1.11];

/** 自有线索库上限（满库停工，会客室页） */
export const OWN_CLUE_LIMIT = 10;

/** 进驻干员线索加成所需信息 */
export interface ClueCharInfo {
  /** 稀有度索引（0 基：3=4★、4=5★、5=6★） */
  rarityIndex: number;
  /** 精英阶段（0/1/2） */
  evolvePhase: number;
  /** 是否注意力涣散（心情耗尽） */
  dispersed: boolean;
}

/**
 * 宿舍总氛围 → 线索速度加成档（≥2000 +5%、≥3000 +10%、≥4000 +15%）。
 * @param totalComfort - 全宿舍氛围（comfort）总和
 */
export function comfortClueBonus(totalComfort: number): number {
  if ((totalComfort ?? 0) >= 4000) return 0.15;
  if ((totalComfort ?? 0) >= 3000) return 0.1;
  if ((totalComfort ?? 0) >= 2000) return 0.05;
  return 0;
}

/**
 * 单个进驻干员的线索速度加成：稀有度（4★+2%/5★+4%/6★+5%）+
 * 精英阶段（精1+8%/精2+16%）+ 非涣散 +5%。
 */
export function charClueBonus(c: ClueCharInfo): number {
  let bonus = 0;
  const r = c?.rarityIndex ?? 0;
  if (r >= 5) bonus += 0.05;
  else if (r === 4) bonus += 0.04;
  else if (r === 3) bonus += 0.02;
  const phase = c?.evolvePhase ?? 0;
  if (phase >= 2) bonus += 0.16;
  else if (phase === 1) bonus += 0.08;
  if (!c?.dispersed) bonus += 0.05;
  return bonus;
}

/**
 * 会客室线索搜集总速度倍率（各项加算）：
 * 等级基础效率 + 氛围档 + Σ干员加成 + meet_* 技能。
 */
export function meetingSpeedMultiplier(opts: {
  roomLevel: number;
  totalComfort: number;
  chars: ClueCharInfo[];
  meetBonus: number;
}): number {
  const lv = Math.min(Math.max(opts.roomLevel ?? 1, 1), 3);
  let mult = MEETING_PHASE_EFFICIENCY[lv - 1];
  mult += comfortClueBonus(opts.totalComfort);
  for (const c of opts.chars ?? []) mult += charClueBonus(c);
  mult += opts.meetBonus ?? 0;
  return mult;
}
