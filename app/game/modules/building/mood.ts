/**
 * 基建干员心情通用机制引擎（纯函数，无 IO）
 *
 * 机制来源（prts.wiki「罗德岛基建」，2026-08-25 全量对齐审计）：
 * - 注意力涣散：心情（ap）耗尽（=0）的干员，后勤技能与基础效率大部分失效
 *   （宿舍休息恢复不受影响）
 * - 头数心情减免：制造站/贸易站进驻 2 人 -0.05 点/时、3 人 -0.1 点/时
 * - 暖机工时：干员在岗累积工作时间（贸易站订单概率改写 α/β 阈值、发电站充能
 *   暖机等消费），离岗/换工位清零
 *
 * 单位约定（与 11.4/11.7 校准一致）：
 * - 心情 1 点 = 360000 raw AP（manpowerDisplayFactor）；上限 24 点 = 8640000
 * - 心情档位换算：1 点/小时 = 100 raw AP/秒（360000 ÷ 3600）
 */

/** 心情上限（raw AP）：24 点 × 360000（真实存档校准：新干员 ap=8640000） */
export const MAX_AP = 8640000;

/**
 * 注意力涣散判定：心情耗尽（ap ≤ 0）→ 技能/基础效率失效。
 * ap 缺失视为满心情（未进驻干员/旧存档惰性初始化）。
 * @param ap - 干员当前心情（raw AP）
 */
export function isDispersedAp(ap: number | null | undefined): boolean {
  return (ap ?? MAX_AP) <= 0;
}

/**
 * 头数心情减免（点/小时）：制造站/贸易站按在岗人数阶梯减免
 * （官方：2 人 -0.05、3 人 -0.1）。仅这两类房间适用，调用方按房间过滤。
 * @param headcount - 该房间当前在岗干员数
 * @returns 减免量（点/小时，正数）
 */
export function headcountMoodRelief(headcount: number): number {
  if (headcount >= 3) return 0.1;
  if (headcount >= 2) return 0.05;
  return 0;
}

/**
 * 暖机工时（小时）：在岗累积秒数换算。负数/缺失按 0（离岗清零后的初始态）。
 * @param warmupSec - 存档扩展字段 building.chars[].warmupSec（秒）
 */
export function warmupHoursOf(warmupSec?: number | null): number {
  return Math.max(warmupSec ?? 0, 0) / 3600;
}
