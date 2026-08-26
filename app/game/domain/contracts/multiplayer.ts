/**
 * 联机V3（多人合作）与邀请协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.Activity.ActMultiV3 /
 * Torappu.UI.CommonInviteDialog 命名空间的 Request/Response 类；字段以 CS 类为准。
 * 本服务端 handler 均为占位实现（不读取 body，仅返回增量或固定字段），
 * 请求类型统一定义为空接口，响应仅标注服务端实际输出的字段。
 */
import { PlayerDeltaResponse } from "./common";

/* ===== 请求类型 ===== */

/** 获取联机信息请求（CS: ActMultiV3QueryGetInfoRequest，含 activityId；服务端不读取） */
export interface ActMultiV3QueryGetInfoRequest {}

/** 修改称号请求（CS: ActMultiV3ChangeTitleRequest，含 activityId / select；服务端不读取） */
export interface ActMultiV3ChangeTitleRequest {}

/** 设置战斗增益请求（CS: ActMultiV3SetSquadEffectRequest，含 activityId / modeType / buffId；服务端不读取） */
export interface ActMultiV3SetSquadEffectRequest {}

/** 设置出战编队请求（CS: ActMultiV3SetSquadRequest，含 activityId / modeType / prefer / backup；服务端不读取） */
export interface ActMultiV3SetSquadRequest {}

/** 引导战斗开始请求（CS: ActMultiV3GuideBattleStartRequest，含 activityId / stageId；服务端不读取） */
export interface ActMultiV3GuideBattleStartRequest {}

/** 引导战斗结束请求（CS: ActMultiV3GuideBattleFinishRequest : CommonFinishBattleRequest；服务端不读取） */
export interface ActMultiV3GuideBattleFinishRequest {}

/** 联机战斗开始请求（CS: ActMultiV3BattleStartRequest，含 activityId / sceneId；服务端不读取） */
export interface ActMultiV3BattleStartRequest {}

/** 联机战斗结束请求（CS: ActMultiV3BattleFinishRequest，含 activityId；服务端不读取） */
export interface ActMultiV3BattleFinishRequest {}

/** 更换照片请求（CS: ActMultiV3ChangePhotoRequest，含 activityId / weekRewardId / templateId / photoInstId；服务端不读取） */
export interface ActMultiV3ChangePhotoRequest {}

/** 提交相册请求（CS: ActMultiV3CommitAlbumRequest，含 activityId / weekRewardId；服务端不读取） */
export interface ActMultiV3CommitAlbumRequest {}

/** 创建队伍请求（CS: ActMultiV3CreateTeamRequest，含 activityId；服务端不读取） */
export interface ActMultiV3CreateTeamRequest {}

/** 加入队伍请求（CS: ActMultiV3JoinTeamRequest，含 activityId / teamId；服务端不读取） */
export interface ActMultiV3JoinTeamRequest {}

/** 查询匹配请求（CS: ActMultiV3QueryMatchRequest，含 activityId / needLeave；服务端不读取） */
export interface ActMultiV3QueryMatchRequest {}

/** 举报队友请求（CS: ActMultiV3ReportPartnerRequest，含 activityId / reasons；服务端不读取） */
export interface ActMultiV3ReportPartnerRequest {}

/** 点赞队友请求（CS: ActMultiV3LikePartnerRequest，含 activityId；服务端不读取） */
export interface ActMultiV3LikePartnerRequest {}

/** 开始匹配请求（CS: ActMultiV3StartMatchRequest，含 activityId / option；服务端不读取） */
export interface ActMultiV3StartMatchRequest {}

/** 解锁战斗增益请求（CS: ActMultiV3UnlockSquadEffectRequest，含 activityId / buffId；服务端不读取） */
export interface ActMultiV3UnlockSquadEffectRequest {}

/** 刷新邀请列表请求（CS: InvitedRefreshRequest，含 inviteId / inviteType；服务端不读取） */
export interface InvitedRefreshRequest {}

/** 切换邀请接受状态请求（CS: InvitedSettingRequest，含 inviteId / inviteType / operate；服务端不读取） */
export interface InvitedSettingRequest {}

/** 发送邀请请求（CS: InviteRequest，含 inviteId / inviteType / toUid；服务端不读取） */
export interface InviteRequest {}

/** 处理邀请请求（CS: ProcessInviteRequest，含 inviteId / inviteType / fromUid / fromIdx / operate；服务端不读取） */
export interface ProcessInviteRequest {}

/* ===== 响应类型 ===== */

/** 联机队伍信息（服务端 getInfo 返回的自定义结构，无 CS 对应类） */
export interface ActMultiV3TeamInfo {
  teamId: string;
  teamName: string;
  captainUid: string;
  members: unknown[];
  buffList: unknown[];
  squadList: unknown[];
  album: { [key: string]: unknown };
  title: string;
  photo: string;
}

/** 获取联机信息响应（CS: ActMultiV3QueryGetInfoResponse 无额外字段；服务端返回自定义 info 结构） */
export interface ActMultiV3QueryGetInfoResponse extends PlayerDeltaResponse {
  info: ActMultiV3TeamInfo;
}

/** 修改称号响应（CS: ActMultiV3ChangeTitleResponse） */
export type ActMultiV3ChangeTitleResponse = PlayerDeltaResponse;

/** 设置战斗增益响应（CS: ActMultiV3SetSquadEffectResponse） */
export type ActMultiV3SetSquadEffectResponse = PlayerDeltaResponse;

/** 设置出战编队响应（CS: ActMultiV3SetSquadResponse） */
export type ActMultiV3SetSquadResponse = PlayerDeltaResponse;

/** 引导战斗开始响应（CS: ActMultiV3GuideBattleStartResponse : CommonStartBattleResponse；服务端仅返回 battleId/result） */
export interface ActMultiV3GuideBattleStartResponse extends PlayerDeltaResponse {
  battleId: string;
  result: number;
}

/** 引导战斗结束响应（CS: ActMultiV3GuideBattleFinishResponse : CommonFinishBattleResponse；服务端省略 data） */
export type ActMultiV3GuideBattleFinishResponse = PlayerDeltaResponse;

/** 联机战斗开始响应（CS: ActMultiV3BattleStartResponse : CommonStartBattleResponse；服务端仅返回 battleId/result） */
export interface ActMultiV3BattleStartResponse extends PlayerDeltaResponse {
  battleId: string;
  result: number;
}

/** 联机战斗结束响应（CS: ActMultiV3BattleFinishResponse 含 data；服务端省略 data） */
export type ActMultiV3BattleFinishResponse = PlayerDeltaResponse;

/** 更换照片响应（CS: ActMultiV3ChangePhotoResponse） */
export type ActMultiV3ChangePhotoResponse = PlayerDeltaResponse;

/** 提交相册响应（CS: ActMultiV3CommitAlbumResponse；服务端省略 items） */
export type ActMultiV3CommitAlbumResponse = PlayerDeltaResponse;

/**
 * 创建队伍响应（CS: ActMultiV3CreateTeamResponse 含 result/team；
 * 服务端返回随机 teamId 字符串，与 CS 结构不一致）
 */
export interface ActMultiV3CreateTeamResponse extends PlayerDeltaResponse {
  teamId: string;
}

/** 加入队伍响应（CS: ActMultiV3JoinTeamResponse；服务端省略 result/team） */
export type ActMultiV3JoinTeamResponse = PlayerDeltaResponse;

/**
 * 查询匹配响应（CS: ActMultiV3QueryMatchResponse 含 result/team；
 * 服务端返回固定 matchInfo:null 与 result:1，与 CS 字段名不一致）
 */
export interface ActMultiV3QueryMatchResponse extends PlayerDeltaResponse {
  matchInfo: null;
  result: number;
}

/** 举报队友响应（CS: ActMultiV3ReportPartnerResponse） */
export type ActMultiV3ReportPartnerResponse = PlayerDeltaResponse;

/** 点赞队友响应（CS: ActMultiV3LikePartnerResponse） */
export type ActMultiV3LikePartnerResponse = PlayerDeltaResponse;

/** 开始匹配响应（CS: ActMultiV3StartMatchResponse；服务端省略 result） */
export type ActMultiV3StartMatchResponse = PlayerDeltaResponse;

/** 解锁战斗增益响应（CS: ActMultiV3UnlockSquadEffectResponse） */
export type ActMultiV3UnlockSquadEffectResponse = PlayerDeltaResponse;

/** 刷新邀请列表响应（服务端自定义，返回固定空 inviteList） */
export interface InvitedRefreshResponse extends PlayerDeltaResponse {
  inviteList: unknown[];
}

/** 切换邀请接受状态响应（CS: InvitedSettingResponse；服务端省略 result） */
export type InvitedSettingResponse = PlayerDeltaResponse;

/** 发送邀请响应（CS: InviteResponse；服务端省略 result） */
export type InviteResponse = PlayerDeltaResponse;

/** 处理邀请响应（CS: ProcessInviteResponse；服务端省略 result） */
export type ProcessInviteResponse = PlayerDeltaResponse;
