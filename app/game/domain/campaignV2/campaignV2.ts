/**
 * 主线战役V2协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * CampaignStartBattleRequest / CampaignFinishBattleRequest / CampaignSweepRequest 等
 * Request/Response 类；字段以 CS 类为准，服务端未返回的协议字段标为可选。
 */
import { ItemBundle } from "@excel/excel";
import { CommonStartBattleRequest } from "../shared/battle-model";
import { PlayerDeltaResponse } from "../contracts/common";

/**
 * 主线战役V2战斗开始请求（CS: CampaignStartBattleRequest : CommonStartBattleRequest）
 * CS 无额外字段，复用 CommonStartBattleRequest
 */
export type CampaignStartBattleRequest = CommonStartBattleRequest;

/**
 * 主线战役V2战斗开始响应（CS: CampaignStartBattleResponse : CommonStartBattleResponse）
 * CS 基类仅含 result/battleId，服务端额外返回 DefaultStartBattleResponse 风格的 AP 保护字段
 */
export interface CampaignStartBattleResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  apFailReturn: number;
  isApProtect: number;
  inApProtectPeriod: boolean;
  notifyPowerScoreNotEnoughIfFailed: boolean;
}

/**
 * 主线战役V2战斗结束请求（CS: CampaignFinishBattleRequest : CommonFinishBattleRequest）
 * CS 的 battleData 为 BattleDataInRequest（含 stats），服务端契约仅读 isCheat/completeTime
 */
export interface CampaignFinishBattleRequest {
  data: string;
  battleData: { isCheat: string; completeTime: number };
}

/**
 * 主线战役V2战斗结束响应（CS: CampaignFinishBattleResponse : CommonFinishBattleResponse）
 * 练习模式（isPractice）下服务端仅返回增量，其余结算字段可缺失故全部可选；
 * CS 的 result 字段服务端未返回
 */
export interface CampaignFinishBattleResponse extends PlayerDeltaResponse {
  result?: number;
  apFailReturn?: number;
  expScale?: number;
  goldScale?: number;
  rewards?: ItemBundle[];
  firstRewards?: ItemBundle[];
  unlockStages?: string[];
  unusualRewards?: ItemBundle[];
  additionalRewards?: ItemBundle[];
  furnitureRewards?: ItemBundle[];
  alert?: unknown[];
  suggestFriend?: boolean;
  pryResult?: unknown[];
  /** CS: CampaignFinishBattleResponse 新增字段，服务端省略 */
  currentFeeBefore?: number;
  /** CS: CampaignFinishBattleResponse 新增字段，服务端省略 */
  currentFeeAfter?: number;
}

/**
 * 主线战役V2扫荡请求（CS: CampaignSweepRequest）
 * CS 无对应 CampaignSweepResponse 类（扫荡响应复用结算响应结构）
 */
export interface CampaignSweepRequest {
  stageId: string;
  itemId: string;
  instId: number;
}

/** 主线战役V2扫荡响应（服务端固定结构，类 DefaultFinishBattleResponse） */
export interface CampaignSweepResponse extends PlayerDeltaResponse {
  result: number;
  apFailReturn: number;
  rewards: ItemBundle[];
  unlockStages: string[];
  unusualRewards: ItemBundle[];
  additionalRewards: ItemBundle[];
  furnitureRewards: ItemBundle[];
  diamondMaterialRewards: ItemBundle[];
  currentFeeBefore: number;
  currentFeeAfter: number;
}

/** 获取主线战役V2突破奖励请求（CS: CampaignConfirmBreakRewardRequest） */
export interface CampaignConfirmBreakRewardRequest {
  stageId: string;
  indexList: number[];
}

/** 获取主线战役V2突破奖励响应（CS: CampaignConfirmBreakRewardResponse；服务端返回 202 不响应体） */
export interface CampaignConfirmBreakRewardResponse extends PlayerDeltaResponse {
  feeAdd?: number;
  items?: unknown[];
}

/** 获取主线战役V2额外任务奖励请求（CS: CampaignGetCommonMissionRewardRequest） */
export interface CampaignGetCommonMissionRewardRequest {
  id: string;
}

/** 获取主线战役V2额外任务奖励响应（CS: CampaignGetCommonMissionRewardResponse；服务端返回 202 不响应体） */
export type CampaignGetCommonMissionRewardResponse = PlayerDeltaResponse;
