/**
 * 老版集成战略（roguelike v1）协议类型
 *
 * 这些路由对应老版集成战略玩法（刻俄柏的灰蕈秘境等），CS 2.7.61 中
 * Torappu.Roguelike 命名空间已改为主题制（RoguelikeTopic*，见 protocol/rlv2.ts），
 * 本文件所列 Request/Response 类在 CS 2.7.61 中无同名类，均以服务端实现为准。
 */
import { PlayerDeltaResponse } from "../contracts/common";

/* ===== 请求类型 ===== */

/** 创建游戏请求（服务端自定义，CS 2.7.61 无对应类；handler 不读取 body） */
export interface RoguelikeCreateGameRequest {}

/** 结束游戏请求（服务端自定义，CS 2.7.61 无对应类；handler 不读取 body） */
export interface RoguelikeFinishGameRequest {}

/** 放弃游戏请求（服务端自定义，CS 2.7.61 无对应类；handler 不读取 body） */
export interface RoguelikeGiveUpGameRequest {}

/** 里程碑奖励请求（服务端自定义，CS 2.7.61 无对应类；handler 不读取 body） */
export interface RoguelikeMilestoneRewardRequest {}

/** 尝试最佳里程碑奖励请求（服务端自定义，CS 2.7.61 无对应类；handler 不读取 body） */
export interface RoguelikeMilestoneRewardTryBestRequest {}

/**
 * 升级局外增益请求（服务端自定义，CS 2.7.61 无对应类）
 * 兼容 id / buffId 两种字段名，二者取一；服务端经 rlv2.unlockBuff 处理
 */
export interface RoguelikeUpgradeOutBuffRequest {
  theme: string;
  id: string;
  buffId?: string;
}

/* ===== 响应类型 ===== */

/** 创建游戏响应（服务端自定义，仅返回 result 与增量） */
export interface RoguelikeCreateGameResponse extends PlayerDeltaResponse {
  result: number;
}

/** 结束游戏响应（服务端自定义，仅返回 result 与增量） */
export interface RoguelikeFinishGameResponse extends PlayerDeltaResponse {
  result: number;
}

/** 放弃游戏响应（服务端自定义，仅返回 result 与增量） */
export interface RoguelikeGiveUpGameResponse extends PlayerDeltaResponse {
  result: number;
}

/** 里程碑奖励响应（服务端自定义，返回固定空 items 与 result） */
export interface RoguelikeMilestoneRewardResponse extends PlayerDeltaResponse {
  items: unknown[];
  result: number;
}

/** 尝试最佳里程碑奖励响应（服务端自定义，返回固定空 items 与 result） */
export interface RoguelikeMilestoneRewardTryBestResponse extends PlayerDeltaResponse {
  items: unknown[];
  result: number;
}

/**
 * 升级局外增益响应（服务端自定义）
 * errorMsg 仅在解锁失败时由 rlv2.unlockBuff 返回，标为可选
 */
export interface RoguelikeUpgradeOutBuffResponse extends PlayerDeltaResponse {
  result: number;
  errorMsg?: string;
}
