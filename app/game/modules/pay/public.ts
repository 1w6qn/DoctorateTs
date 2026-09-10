/**
 * pay 模块对外出口（public.ts）
 *
 * 跨模块引用约定（AGENTS.md「落位规则」）：模块间只允许 import 对方 public.ts 或走事件总线。
 * 本文件为 `pay/purchase-record` 的门面——activities/milestone 等需要记录「活动礼包购买」时
 * 经此引用，避免直接触达模块内部文件（守卫 R3，见 tests/unit/architecture/module-boundary.test.ts）。
 */
export { recordPurchase } from "./purchase-record";
