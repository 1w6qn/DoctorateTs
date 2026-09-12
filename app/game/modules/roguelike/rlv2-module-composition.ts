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
 * 模块管理器类型再导出
 *
 * module.ts 的访问器按具体管理器类型收敛，而 architecture/decoupling 守卫要求
 * module.ts 不直连 `./modules/*`（只能经本分发表），故类型统一从这里出口。
 */
export type { RoguelikeFragmentManager } from "./modules/fragment";
export type { RoguelikeTotemManager } from "./modules/totem";
export type { RoguelikeGridZoneManager } from "./modules/grid_zone";
export type { RoguelikeScrapManager } from "./modules/scrap";
export type { RoguelikeWeatherManager } from "./modules/weather";
export type { RoguelikeDiceManager, RoguelikeSanManager } from "./modules/dice";
export type { RoguelikeCopperManager } from "./modules/copper";
export type {
  RoguelikeChaosManager,
  RoguelikeVisionManager,
} from "./modules/chaos";
export type {
  RoguelikeSkyManager,
  RoguelikeWrathManager,
} from "./modules/wrath_sky";

/**
 * 主题模块管理器联合类型（分发表全部 14 个模块管理器）
 */
export type Rlv2ThemeModule =
  | RoguelikeFragmentManager
  | RoguelikeDisasterManager
  | RoguelikeNodeUpgradeManager
  | RoguelikeTotemManager
  | RoguelikeGridZoneManager
  | RoguelikeWeatherManager
  | RoguelikeScrapManager
  | RoguelikeSanManager
  | RoguelikeDiceManager
  | RoguelikeCopperManager
  | RoguelikeChaosManager
  | RoguelikeVisionManager
  | RoguelikeWrathManager
  | RoguelikeSkyManager;

/**
 * 主题模块工厂表：moduleType 键 → 构造该模块管理器的工厂函数
 */
export type Rlv2ModuleFactoryMap = {
  [moduleType: string]: () => Rlv2ThemeModule;
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