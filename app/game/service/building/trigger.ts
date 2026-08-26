/**
 * 基建模块事件订阅登记
 *
 * 注册顺序即事件派发顺序：refresh:daily 先于 building:char:init（与迁移前
 * BuildingManager 构造器内联订阅一致，不得调换）。
 *
 * @param trigger - 类型化事件触发器
 * @param mgr - BuildingManager 实例（绑定订阅回调）
 */
import type { TypedEventEmitter } from "@game/service/events";
import type { BuildingManager } from "./logic";
import type { PlayerCharacter } from "@game/domain/character";

export function registerBuildingTriggers(
  trigger: TypedEventEmitter,
  mgr: BuildingManager,
): void {
  // 每日刷新：会客室每日免费线索重置（dailyReward=null——"今日未领"合法值）
  trigger.on("refresh:daily", mgr.dailyRefresh.bind(mgr));
  trigger.on("building:char:init", ([char]: [PlayerCharacter]) =>
    mgr._onCharInit(char),
  );
}
