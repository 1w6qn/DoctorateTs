/**
 * 自走棋（AutoChess）赛季协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.UI.AutoChess /
 * Torappu.Activity.AutoChess 命名空间的 Request/Response 类；字段以 CS 类为准。
 * 本服务端 handler 均为占位实现（不读取 body，仅返回增量或固定字段），
 * 请求类型统一定义为空接口，响应仅标注服务端实际输出的字段。
 */
import { PlayerDeltaResponse } from "../../kernel/http/common";

/* ===== 请求类型 ===== */

/** 同步赛季信息请求（CS: ActAutoChessSyncInfoRequest，含 actId；服务端不读取） */
export interface ActAutoChessSyncInfoRequest {}

/** 设置棋子池部署请求（CS: AutoChessSetChessPoolDeployRequest，含 actId / chessPool；服务端不读取） */
export interface AutoChessSetChessPoolDeployRequest {}

/** 完成引导战斗请求（CS: AutoChessTrainingBattleFinishRequest : CommonFinishBattleRequest；服务端不读取） */
export interface AutoChessTrainingBattleFinishRequest {}

/** 获取好友助战列表请求（CS: AutoChessGetFriendAssistListRequest，含 actId / charId；服务端不读取） */
export interface AutoChessGetFriendAssistListRequest {}

/** 加入队伍请求（CS: AutoChessJoinTeamRequest，含 activityId / teamId；服务端不读取） */
export interface AutoChessJoinTeamRequest {}

/** 多人战斗结束请求（CS: AutoChessMultiBattleFinishRequest : CommonFinishBattleRequest；服务端不读取） */
export interface AutoChessMultiBattleFinishRequest {}

/** 多人战斗开始请求（CS: AutoChessMultiBattleStartRequest，含 activityId / sceneId；服务端不读取） */
export interface AutoChessMultiBattleStartRequest {}

/** 查询匹配请求（CS: AutoChessQueryMatchRequest，含 activityId / needLeave；服务端不读取） */
export interface AutoChessQueryMatchRequest {}

/** 退出单机游戏请求（CS: AutoChessQuitSingleGameRequest，含 activityId / sceneId；服务端不读取） */
export interface AutoChessQuitSingleGameRequest {}

/** 移除棋子池角色请求（CS: AutoChessRemoveChessPoolCharRequest，含 actId / chessId；服务端不读取） */
export interface AutoChessRemoveChessPoolCharRequest {}

/** 上报战斗结果请求（服务端自定义，无 CS 对应类；服务端不读取 body） */
export interface AutoChessReportRequest {}

/** 设置棋子池助战请求（CS: AutoChessSetFriendAssistRequest，含 actId / assistChessId / assistUid；服务端不读取） */
export interface AutoChessSetFriendAssistRequest {}

/** 设置棋子池自定角色请求（CS: AutoChessSetChessPoolDiyCharRequest，含 actId / diyChessPool；服务端不读取） */
export interface AutoChessSetChessPoolDiyCharRequest {}

/** 结算游戏请求（CS: AutoChessSettleGameRequest，含 activityId / quitBattle；服务端不读取） */
export interface AutoChessSettleGameRequest {}

/** 点赞结算请求（CS: AutoChessSettleLikeRequest，含 activityId / uid；服务端不读取） */
export interface AutoChessSettleLikeRequest {}

/** 开始匹配请求（CS: AutoChessStartMatchRequest，含 activityId / option；服务端不读取） */
export interface AutoChessStartMatchRequest {}

/** 创建队伍请求（CS: AutoChessCreateTeamRequest，含 activityId / modeId / matchOpt / matchFlag；服务端不读取） */
export interface AutoChessCreateTeamRequest {}

/** 开始引导战斗请求（CS: AutoChessTrainingBattleStartRequest，含 activityId / stageId；服务端不读取） */
export interface AutoChessTrainingBattleStartRequest {}

/* ===== 响应类型 ===== */

/**
 * 同步赛季信息响应（CS: ActAutoChessSyncInfoResponse 含 changed/battleInfo；
 * 服务端返回自定义空 info 对象，与 CS 字段不一致）
 */
export interface ActAutoChessSyncInfoResponse extends PlayerDeltaResponse {
  info: { [key: string]: unknown };
}

/** 设置棋子池部署响应（CS: AutoChessSetChessPoolDeployResponse） */
export type AutoChessSetChessPoolDeployResponse = PlayerDeltaResponse;

/** 完成引导战斗响应（CS: AutoChessTrainingBattleFinishResponse : CommonFinishBattleResponse；服务端仅返回增量） */
export type AutoChessTrainingBattleFinishResponse = PlayerDeltaResponse;

/**
 * 获取好友助战列表响应（CS: AutoChessGetFriendAssistListResponse 含 assistList；
 * 服务端返回固定空 charList，与 CS 字段名不一致）
 */
export interface AutoChessGetFriendAssistListResponse extends PlayerDeltaResponse {
  charList: unknown[];
}

/** 加入队伍响应（CS: AutoChessJoinTeamResponse；服务端省略 result/team） */
export type AutoChessJoinTeamResponse = PlayerDeltaResponse;

/** 多人战斗结束响应（CS: AutoChessMultiBattleFinishResponse : CommonFinishBattleResponse；服务端仅返回增量） */
export type AutoChessMultiBattleFinishResponse = PlayerDeltaResponse;

/** 多人战斗开始响应（CS: AutoChessMultiBattleStartResponse : CommonStartBattleResponse；服务端仅返回 battleId/result） */
export interface AutoChessMultiBattleStartResponse extends PlayerDeltaResponse {
  battleId: string;
  result: number;
}

/**
 * 查询匹配响应（CS: AutoChessQueryMatchResponse 含 result/team；
 * 服务端返回固定 matchInfo:null 与 result:1，与 CS 字段名不一致）
 */
export interface AutoChessQueryMatchResponse extends PlayerDeltaResponse {
  matchInfo: null;
  result: number;
}

/** 退出单机游戏响应（CS: AutoChessQuitSingleGameResponse；服务端省略 result/battleInfo） */
export type AutoChessQuitSingleGameResponse = PlayerDeltaResponse;

/** 移除棋子池角色响应（CS: AutoChessRemoveChessPoolCharResponse） */
export type AutoChessRemoveChessPoolCharResponse = PlayerDeltaResponse;

/** 上报战斗结果响应（服务端自定义，仅返回增量） */
export type AutoChessReportResponse = PlayerDeltaResponse;

/** 设置棋子池助战响应（CS: AutoChessSetFriendAssistResponse） */
export type AutoChessSetFriendAssistResponse = PlayerDeltaResponse;

/** 设置棋子池自定角色响应（CS: AutoChessSetChessPoolDiyCharResponse） */
export type AutoChessSetChessPoolDiyCharResponse = PlayerDeltaResponse;

/** 结算游戏响应（CS: AutoChessSettleGameResponse 含 result/gameSettleData；服务端仅返回 result） */
export interface AutoChessSettleGameResponse extends PlayerDeltaResponse {
  result: number;
}

/** 点赞结算响应（CS: AutoChessSettleLikeResponse） */
export type AutoChessSettleLikeResponse = PlayerDeltaResponse;

/** 开始匹配响应（CS: AutoChessStartMatchResponse；服务端省略 result） */
export type AutoChessStartMatchResponse = PlayerDeltaResponse;

/**
 * 创建队伍响应（CS: AutoChessCreateTeamResponse 含 result/team；
 * 服务端返回随机 teamId 字符串，与 CS 结构不一致）
 */
export interface AutoChessCreateTeamResponse extends PlayerDeltaResponse {
  teamId: string;
}

/** 开始引导战斗响应（CS: AutoChessTrainingBattleStartResponse : CommonStartBattleResponse；服务端仅返回 battleId/result） */
export interface AutoChessTrainingBattleStartResponse extends PlayerDeltaResponse {
  battleId: string;
  result: number;
}
