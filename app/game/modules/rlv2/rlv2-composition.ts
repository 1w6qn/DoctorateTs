/**
 * rlv2 控制器子模块组合（Rlv2 Composition Factory）
 *
 * 将 RoguelikeV2Controller 构造器中「硬编码 new 8 个子管理器」抽取为可覆写的组合工厂，
 * 与 PlayerDataManager/player-composition 采用同款依赖注入（DI）模式：
 * - `composeRlv2ChildModules` 按原顺序构造全部子管理器；
 * - `RoguelikeV2Controller` 支持 `deps.modules` 部分覆写（测试可替换个别子模块，缩小构造面）。
 *
 * 构造顺序即事件订阅顺序，必须与迁移前完全一致，以保持事件派发顺序不变。
 * 说明：子管理器需在控制器构造期持有 `this` 引用，故组合仍在控制器内执行，
 * 「构造哪些、顺序如何」已从业务类剥离为可覆写策略。
 */
import type { RoguelikeV2Controller } from "./rlv2";
import type { TypedEventEmitter } from "@game/model/events";
import { RoguelikeTroopManager } from "./rlv2/troop";
import { RoguelikePlayerStatusManager } from "./rlv2/status";
import { RoguelikeInventoryManager } from "./rlv2/inventory";
import { RoguelikeBuffManager } from "./rlv2/buff";
import { RoguelikeMapManager } from "./rlv2/map";
import { RoguelikeModuleManager } from "./rlv2/module";
import { RoguelikeBattleManager } from "./rlv2/battle";
import { RoguelikePoolManager } from "./rlv2/pool";

/**
 * rlv2 子模块集合（组合工厂返回值）
 *
 * 覆盖 RoguelikeV2Controller 创建的全部子管理器（不含 controller 自身）。
 */
export interface Rlv2ChildModules {
  troop: RoguelikeTroopManager;
  status: RoguelikePlayerStatusManager;
  inventory: RoguelikeInventoryManager;
  buff: RoguelikeBuffManager;
  map: RoguelikeMapManager;
  module: RoguelikeModuleManager;
  battle: RoguelikeBattleManager;
  pool: RoguelikePoolManager;
}

/**
 * 组合 rlv2 子模块（默认工厂）
 *
 * 按迁移前原始构造顺序依次 new 每个子管理器，并**在构造后立即写回控制器**——
 * 因为部分子管理器（如 RoguelikeBuffManager）在自身构造期会读取控制器上已就位的
 * 兄弟管理器（`controller._status`），若等到全部构造完再统一赋值，兄弟字段尚未挂在
 * 控制器上会读到 undefined。逐项写回与迁移前「构造一个即赋值一个」语义完全一致。
 *
 * @param controller - rlv2 控制器（父）
 * @param trigger - 类型化事件触发器
 * @returns 全部子模块集合
 */
export function composeRlv2ChildModules(
  controller: RoguelikeV2Controller,
  trigger: TypedEventEmitter,
): Rlv2ChildModules {
  return {
    troop: (controller.troop = new RoguelikeTroopManager(controller, trigger)),
    status: (controller._status = new RoguelikePlayerStatusManager(controller, trigger)),
    inventory: (controller.inventory = new RoguelikeInventoryManager(controller, trigger)),
    buff: (controller._buff = new RoguelikeBuffManager(controller, trigger)),
    map: (controller._map = new RoguelikeMapManager(controller, trigger)),
    module: (controller._module = new RoguelikeModuleManager(controller, trigger)),
    battle: (controller._battle = new RoguelikeBattleManager(controller, trigger)),
    pool: (controller._pool = new RoguelikePoolManager(controller, trigger)),
  };
}