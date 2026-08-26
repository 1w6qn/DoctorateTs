/**
 * 任务系统事件映射（Mission）
 *
 * 从 service/mission/models.ts 拆分迁出:EventMapMission 是领域事件契约(纯类型),
 * 与任务协议 DTO 分离,归入 domain 事件层。
 */
import type { ItemBundle } from "@excel/character_table";
import type { BattleData } from "@game/domain/battle";

export type EventMapMission = {
  /** 任务完成事件 */
  "mission:complete": [{ missionId: string }];
  /** 任务进度更新事件 */
  "mission:update": [{ missionId: string; progress: number }];
  /** 任务奖励领取事件 */
  "mission:reward": [{ missionId: string; items: ItemBundle[] }];

  // ============ 任务模板事件 ============
  /** 通关活动关卡累计（act53side 任务 CompleteStageAct：param[1]=关卡列表，目标=累计通关次数） */
  CompleteStageAct: [BattleData & { stageId: string }];
  /** 指定关卡累计杀敌 / 用技能 / 部署（StageWithCondition：type0=杀敌，1=技能，2=部署） */
  StageWithCondition: [BattleData & { stageId: string }];
  /** 活动关卡累计击杀敌人（EnemyKill：param[1]=关卡列表，目标=累计击杀数） */
  EnemyKill: [BattleData & { stageId: string }];
  /** 通关任意关卡（CompleteStageOrCampaign：目标=累计通关次数） */
  CompleteStageOrCampaign: [BattleData & { stageId: string }];
  /** 通关物资筹备关卡（CompleteDailyStage：目标=累计通关次数，param[1]=物资类型） */
  CompleteDailyStage: [BattleData & { stageId: string }];
  /** 通关多维合作（CompleteAnyMulStage：param[1]=关卡，param[2]=星级门槛） */
  CompleteAnyMulStage: [BattleData & { stageId: string }];
  /** 驻守关卡通关（CompleteInterlockStage：param[1]=reference，param[2]=驻守关卡链） */
  CompleteInterlockStage: [BattleData & { stageId: string }];
  /** 通关且满足战斗条件（CompleteStageCondition：细分型读 enemyStats/extraBattleInfo/skillTrigStats） */
  CompleteStageCondition: [BattleData & { stageId: string }];
  /** 通关且达成击杀/装置计数（CompleteStageSimpleAtLeastId / CompleteStageSimpleAtMostId） */
  CompleteStageSimpleAtLeastId: [BattleData & { stageId: string }];
  CompleteStageSimpleAtMostId: [BattleData & { stageId: string }];
  /** 携带遗物/科技树通关（CompleteStageWithRelic / CompleteStageWithTechTree） */
  CompleteStageWithRelic: [BattleData & { stageId: string }];
  CompleteStageWithTechTree: [BattleData & { stageId: string }];
  /** 携带标志物通关（CompleteStageWithCharm） */
  CompleteStageWithCharm: [BattleData & { stageId: string }];
  /** arkodc 奖励组收集（act53side 任务 ArkodcRewardGroupAtLeast：统计 topic.rewards 命中 param[2] 列表的数量） */
  ArkodcRewardGroupAtLeast: [{ activityId: string; rewards: Record<string, number> }];
};
