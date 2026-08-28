/**
 * rlv2 主题模块注册工厂（Rlv2 Theme Module Composition）
 *
 * 把 RoguelikeModuleManager（module.ts）中的主题模块分发表独立出来：
 * - 按 moduleType 键（FRAGMENT/DISASTER/…/WRATH/SKY）集中注册 14 个主题模块管理器；
 * - 模块新增/删除只需改动本文件一处，module.ts 只消费这张表。
 *
 * 每个工厂函数接收父控制器与事件触发器，构造对应主题模块管理器
 * （构造期即挂在控制器/事件上，与迁移前行为一致）。
 */
import type { RoguelikeV2Manager } from "./logic";
import type { TypedEventEmitter } from "../../kernel/events/runtime";
import { RoguelikeFragmentManager } from "./modules/fragment";
import { RoguelikeDisasterManager } from "./modules/disaster";
import { RoguelikeNodeUpgradeManager } from "./modules/node_upgrade";
import { RoguelikeTotemManager } from "./modules/totem";
import { RoguelikeGridZoneManager } from "./modules/grid_zone";
import { RoguelikeWeatherManager } from "./modules/weather";
import { RoguelikeScrapManager } from "./modules/scrap";
import { RoguelikeDiceManager, RoguelikeSanManager } from "./modules/dice";
import { RoguelikeCopperManager } from "./modules/copper";
import { RoguelikeChaosManager, RoguelikeVisionManager } from "./modules/chaos";
import { RoguelikeSkyManager, RoguelikeWrathManager } from "./modules/wrath_sky";

/**
 * 主题模块工厂表：moduleType 键 → 构造该模块管理器的工厂函数
 */
export type Rlv2ModuleFactoryMap = {
  [moduleType: string]: (() => unknown) | undefined;
};

/**
 * 构建主题模块分发表
 * @param controller - rlv2 控制器（父）
 * @param trigger - 类型化事件触发器
 * @returns moduleType 键 → 模块构造工厂 的映射
 */
export function composeRlv2ThemeModules(
  controller: RoguelikeV2Manager,
  trigger: TypedEventEmitter,
): Rlv2ModuleFactoryMap {
  return {
    FRAGMENT: () => new RoguelikeFragmentManager(controller, trigger),
    DISASTER: () => new RoguelikeDisasterManager(controller, trigger),
    NODE_UPGRADE: () => new RoguelikeNodeUpgradeManager(controller, trigger),
    TOTEM: () => new RoguelikeTotemManager(controller, trigger),
    GRID_ZONE: () => new RoguelikeGridZoneManager(controller, trigger),
    WEATHER: () => new RoguelikeWeatherManager(controller, trigger),
    SCRAP: () => new RoguelikeScrapManager(controller, trigger),
    SANCHECK: () => new RoguelikeSanManager(controller, trigger),
    DICE: () => new RoguelikeDiceManager(controller, trigger),
    COPPER: () => new RoguelikeCopperManager(controller, trigger),
    CHAOS: () => new RoguelikeChaosManager(controller, trigger),
    VISION: () => new RoguelikeVisionManager(controller, trigger),
    WRATH: () => new RoguelikeWrathManager(controller, trigger),
    SKY: () => new RoguelikeSkyManager(controller, trigger),
  };
}