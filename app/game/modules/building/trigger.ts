/**
 * 基建模块事件订阅登记
 *
 * 注册顺序即事件派发顺序：refresh:daily 先于 char:init（与迁移前
 * BuildingManager 构造器内联订阅一致，不得调换）。
 *
 * @param trigger - 类型化事件触发器
 * @param mgr - BuildingManager 实例（绑定订阅回调）
 */
import type { TypedEventEmitter } from "../../kernel/events/runtime";
import type { BuildingManager } from "./logic";
import type { PlayerCharacter } from "../../kernel/model";

export function registerBuildingTriggers(
  trigger: TypedEventEmitter,
  mgr: BuildingManager,
): void {
  // 每日刷新：会客室每日免费线索重置（dailyReward=null——"今日未领"合法值）
  trigger.on("refresh:daily", mgr.dailyRefresh.bind(mgr));
  // 修复（2026-09-09，审计 §6.3-27）：原订阅 "building:char:init" —— 该事件**全仓无 emit 方**
  // （建仓以来从未派发），而干员模块获取新干员时 emit 的是 "char:init"（payload 同为
  // [PlayerCharacter]，见 character/char.ts onCharGet 尾部）。命名错位导致 `_onCharInit`
  // 永不执行：新获得干员在 building.chars 无建档 → 心情 AP / 私人宿舍 privateRooms /
  // 进驻状态 charId 全缺（官方存档每个在编干员都有该条目）。现改订阅真正派发的 "char:init"。
  trigger.on("char:init", ([char]: [PlayerCharacter]) => mgr._onCharInit(char));
}
