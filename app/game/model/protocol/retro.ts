/**
 * 复刻/插曲（Retro）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * RetroUnlockRetroBlockRequest / RetroTrailRewardRequest / RetroGetPassRewardRequest 等
 * Request/Response 类，以及 Torappu.Activity.Act20side.RetroCarCompetitionStart/Finish
 * Request/Response 类；字段以 CS 类为准，服务端未返回的协议字段（如 result）标为可选。
 */
import { ItemBundle } from "@excel/character_table";
import { PlayerDeltaResponse } from "./common";

/** 解锁复刻区块请求（CS: RetroUnlockRetroBlockRequest） */
export interface RetroUnlockRetroBlockRequest {
  retroId: string;
}

/** 解锁复刻区块响应（CS: RetroUnlockRetroBlockResponse；服务端省略 result） */
export interface RetroUnlockRetroBlockResponse extends PlayerDeltaResponse {
  result?: number;
}

/** 获取复刻轨迹奖励请求（CS: RetroTrailRewardRequest） */
export interface RetroTrailRewardRequest {
  retroId: string;
  rewardId: string;
}

/** 获取复刻轨迹奖励响应（CS: RetroTrailRewardResponse；CS items 为 List<ItemGet>，服务端返回 ItemBundle[]） */
export interface RetroTrailRewardResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 获取复刻通行证奖励请求（CS: RetroGetPassRewardRequest） */
export interface RetroGetPassRewardRequest {
  retroId: string;
  activityId: string;
}

/** 获取复刻通行证奖励响应（CS: RetroGetPassRewardResponse） */
export interface RetroGetPassRewardResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 复刻战车竞速开始请求（CS: Activity.Act20side.RetroCarCompetitionStartRequest { retroId/stageId/car }；服务端不读取 body） */
export interface RetroCarCompetitionStartRequest {}

/**
 * 复刻战车竞速开始响应
 * CS: Activity.Act20side.RetroCarCompetitionStartResponse : DefaultStartBattleResponse
 * （含 isApProtect/apFailReturn/notifyPowerScoreNotEnoughIfFailed/inApProtectPeriod），
 * 服务端仅返回 result/battleId，其余字段省略标为可选
 */
export interface RetroCarCompetitionStartResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  isApProtect?: boolean;
  apFailReturn?: number;
  notifyPowerScoreNotEnoughIfFailed?: boolean;
  inApProtectPeriod?: boolean;
}

/** 复刻战车竞速结算请求（CS: Activity.Act20side.RetroCarCompetitionFinishRequest : CommonFinishBattleRequest；服务端不读取 body） */
export interface RetroCarCompetitionFinishRequest {}

/**
 * 复刻战车竞速结算响应
 * CS: Activity.Act20side.RetroCarCompetitionFinishResponse : CarCompetitionFinishResponse
 * （performance/expression/operation/total/level:CartCompetitionRank/isNew）；
 * 服务端返回固定 stub 结构，level 为字符串形式（"SS"），isNew 输出布尔
 */
export interface RetroCarCompetitionFinishResponse extends PlayerDeltaResponse {
  performance: number;
  expression: number;
  operation: number;
  total: number;
  level: string;
  isNew: boolean;
}
