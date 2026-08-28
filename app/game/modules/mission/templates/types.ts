/**
 * 任务模板公共类型
 *
 * 由 logic.ts 拆分而来：MissionInfo 描述任务进度实例的模板视角
 * （value/progress/param），MissionTemplateGroup 为按事件名分组的
 * 模板注册表类型（键可缺省，各组文件只声明自身覆盖的事件）。
 */
import { MissionCalcState } from "../../../kernel/playerdata";
import type { EventMap } from "../../../kernel/events";

/**
 * 任务模板接口
 * 定义了任务进度数据结构
 */
export interface MissionInfo {
  value: number;
  progress: MissionCalcState[];
  param: string[];
}

/**
 * 任务模板注册表类型
 *
 * 参照明日方舟任务系统，定义了各种任务类型的进度追踪逻辑：
 *
 * 任务模板分类：
 * - 关卡相关：CompleteStageAnyType, StageWithEnemyKill, EnemyKillInAnyStage,
 *             CompleteStage, CompleteAnyStage, CompleteCampaign, CompleteMainStage,
 *             StageWithReplay, TakeOverReplay, PassStageWithSimpleCountMore等
 * - 干员相关：UpgradeChar, EvolveChar, HasChar, HasEquipment, BoostPotential,
 *             CharIntimacy, UpgradeSpecialization等
 * - 社交相关：ReceiveSocialPoint, VisitBuilding, SetAssistCharList, SendClue等
 * - 商店相关：BuyShopItem, NormalGacha等
 * - 基建相关：ManufactureItem, DeliveryOrder, DiyComfort, HasRoom, WorkshopSynthesis等
 * - 其他：GainIntimacy, UpgradeSkill, SquadFormation, EditBusinessCard等
 */
export type MissionTemplateGroup = {
  [T in keyof Partial<EventMap>]: {
    [p: string]: {
      init: (mission: MissionInfo) => void;
      update: (mission: MissionInfo, ...args: EventMap[T]) => void;
    };
  };
};
