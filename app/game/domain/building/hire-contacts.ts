/**
 * 人力办公室联络（人脉资源）引擎（纯函数，无 IO）
 *
 * 官方机制（prts.wiki 办公室页，2026-08-25 全量对齐）：
 * - 进驻干员按联络速度累积，基础 12 小时获得 1 次联络（标签刷新次数）
 * - 进驻即有基础联络效率 +5%（无论是否有技能），与 hire_* 技能加算
 * - 人脉资源上限 = 办公室相位 refreshTimes（excel = 3），达上限干员暂停工作
 */

/** 联络基础时长（秒）：12 小时 / 次（办公室页） */
export const CONTACT_BASE_SECONDS = 43200;

/** 进驻基础联络效率 +5%（办公室页：无论是否有技能） */
export const CONTACT_BASE_BONUS = 0.05;

/**
 * 联络速度系数（每秒推进的"基准进度秒"）：
 * (resSpeed/100) × (1 + 进驻基础 5% + hire_* 技能加成)。
 * @param resSpeed - 办公室相位联络速度（百分制，如 100）
 * @param hireBonus - 进驻干员 hire_* 技能加成（小数，如 0.2）
 */
export function contactSpeedFactor(resSpeed: number, hireBonus: number): number {
  return ((resSpeed ?? 100) / 100) * (1 + CONTACT_BASE_BONUS + (hireBonus ?? 0));
}

/**
 * 联络进度结算：每满 12h 基准进度获得 1 次人脉库存。
 * @param progressSec - 累积的基准进度秒
 * @returns gained 新增库存次数；remainder 结算后剩余进度秒
 */
export function settleContactProgress(progressSec: number): {
  gained: number;
  remainder: number;
} {
  const p = Math.max(progressSec ?? 0, 0);
  const gained = Math.floor(p / CONTACT_BASE_SECONDS);
  return { gained, remainder: p - gained * CONTACT_BASE_SECONDS };
}
