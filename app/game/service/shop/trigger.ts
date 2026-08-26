/**
 * 商店模块事件订阅登记
 *
 * 注册顺序即事件派发顺序：refresh:daily 先于 refresh:monthly（与迁移前
 * ShopManager 构造器内联订阅一致，不得调换）。
 *
 * @param trigger - 类型化事件触发器
 * @param mgr - ShopManager 实例（绑定订阅回调）
 */
import type { TypedEventEmitter } from "@game/service/events";
import type { ShopManager } from "./logic";

export function registerShopTriggers(
  trigger: TypedEventEmitter,
  mgr: ShopManager,
): void {
  trigger.on("refresh:daily", mgr.dailyRefresh.bind(mgr));
  trigger.on("refresh:monthly", mgr.monthlyRefresh.bind(mgr));
}
