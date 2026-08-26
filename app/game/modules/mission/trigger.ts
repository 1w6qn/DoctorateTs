/**
 * 任务模块事件订阅（Trigger）
 *
 * 集中登记 MissionManager 的领域事件订阅，由构造函数末尾调用
 * （保持构造期订阅时机不变）。仅 type-only 引用 logic，避免运行时循环依赖。
 */
import type { MissionManager } from "./logic";

/**
 * 登记任务模块事件订阅
 *
 * - refresh:weekly  每周一刷新周任务
 * - refresh:daily   每日刷新日常任务
 * @param m - MissionManager 实例
 */
export function registerMissionTriggers(m: MissionManager): void {
  m._trigger.on("refresh:weekly", m.weeklyRefresh.bind(m));
  m._trigger.on("refresh:daily", m.dailyRefresh.bind(m));
}
