/**
 * 任务模块领域模型（协议类型 + 事件映射）
 *
 * 协议类型对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * ConfirmMission/ConfirmMissionGroup/AutoConfirmMissions/ExchangeMissionRewards 系列类。
 */
import { ItemBundle } from "@excel/character_table";
import { PlayerDeltaResponse } from "../../model/protocol/common";
import type { BattleData } from "@game/model/battle";

/** 确认单个任务请求（CS: ConfirmMissionRequest） */
export interface ConfirmMissionRequest {
  missionId: string;
}

/** 确认单个任务响应（CS: ConfirmMissionResponse；服务端额外返回 items） */
export interface ConfirmMissionResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 确认任务组请求（CS: ConfirmMissionGroupRequest） */
export interface ConfirmMissionGroupRequest {
  missionGroupId: string;
}

/** 任务组奖励（CS: MissionGroupRewards） */
export interface MissionGroupRewards {
  id: string;
  items: ItemBundle[];
}

/** 确认任务组响应（CS: ConfirmMissionGroupResponse；服务端不返回 items） */
export interface ConfirmMissionGroupResponse extends PlayerDeltaResponse {
  items?: MissionGroupRewards[];
}

/** 自动确认任务请求（CS: AutoConfirmMissionsRequest；服务端读取 type） */
export interface AutoConfirmMissionsRequest {
  type: string;
}

/** 自动确认任务响应（CS: AutoConfirmMissionsResponse） */
export interface AutoConfirmMissionsResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 兑换任务奖励请求（CS: ExchangeMissionRewardsRequest） */
export interface ExchangeMissionRewardsRequest {
  targetRewardsId: string;
}

/** 兑换任务奖励响应（CS: ExchangeMissionRewardsResponse） */
export type ExchangeMissionRewardsResponse = PlayerDeltaResponse;

/** 批量确认任务请求（CS: ConfirmMissionListRequest { missionIds }） */
export interface ConfirmMissionListRequest {
  missionIds: string[];
}

/** 批量确认任务响应（服务端自定义，同 confirmMission 聚合 items） */
export interface ConfirmMissionListResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 批量确认多任务组请求（CS 无直接对应类；官服抓包客户端传 missionIds，兼容 missionGroupIds） */
export interface ConfirmMultiGroupMissionListRequest {
  missionIds?: string[];
  missionGroupIds?: string[];
}

/** 批量确认多任务组响应（服务端自定义，同 confirmMissionList 聚合 items） */
export interface ConfirmMultiGroupMissionListResponse extends PlayerDeltaResponse {
  items?: ItemBundle[];
}

// ============ 任务领域事件映射（原 model/eventmaps/mission.ts） ============

/**
 * 任务领域事件映射
 *
 * 集中定义任务系统的领域事件：
 * - 任务生命周期：完成 / 进度更新 / 奖励领取
 * - 任务模板事件（template 语义的事件名），由各玩法动作 emit，
 *   MissionManager 的 MissionTemplates 按 template 名订阅
 */
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
