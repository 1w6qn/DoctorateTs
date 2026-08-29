/**
 * 自走棋（AutoChess，卫戍协议）赛季协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.UI.AutoChess /
 * Torappu.Activity.AutoChess 命名空间的 Request/Response 类；字段以 CS 类为准。
 * 路由前缀 /activity/autochessSeason/*（见 reference/client-routes.txt 90-107 行）。
 */
import { PlayerDeltaResponse } from "../../kernel/http/common";

/* ===== 赛季信息同步 ===== */

/** 同步赛季信息请求（CS: ActAutoChessSyncInfoRequest { actId }） */
export interface ActAutoChessSyncInfoRequest {
  actId: string;
}

/** 进行中/待结算的战场信息（CS: ActAutoChessSyncInfoBattleInfo） */
export interface ActAutoChessSyncInfoBattleInfo {
  sceneId: string;
  address: string;
  token: string;
  modeId: string;
  endTime: number;
  curRound: number;
}

/** 同步赛季信息响应（CS: ActAutoChessSyncInfoResponse { changed, battleInfo }） */
export interface ActAutoChessSyncInfoResponse extends PlayerDeltaResponse {
  /** 棋池变更列表（客户端用于“棋池变更提示”；无变更时为空数组） */
  changed: string[];
  /** 进行中/待重连战场；无则 null */
  battleInfo: ActAutoChessSyncInfoBattleInfo | null;
}

/* ===== 棋池配置 ===== */

/** 部署项（CS: Torappu.UI.AutoChess.Deploy { skillIndex, currentEquip }） */
export interface AutoChessDeploy {
  skillIndex: number;
  currentEquip?: string | null;
}

/** 自定义干员部署项（CS: DiyCharDeploy，额外 diyChar/origChessId） */
export interface AutoChessDiyCharDeploy extends AutoChessDeploy {
  diyChar?: string | null;
  origChessId?: string | null;
}

/** 设置棋池部署请求（CS: AutoChessSetChessPoolDeployRequest { actId, chessPool }） */
export interface AutoChessSetChessPoolDeployRequest {
  actId: string;
  chessPool: { [key: string]: AutoChessDeploy };
}

export type AutoChessSetChessPoolDeployResponse = PlayerDeltaResponse;

/** 设置棋池自定干员请求（CS: AutoChessSetChessPoolDiyCharRequest { actId, diyChessPool }） */
export interface AutoChessSetChessPoolDiyCharRequest {
  actId: string;
  diyChessPool: { [key: string]: AutoChessDiyCharDeploy };
}

export type AutoChessSetChessPoolDiyCharResponse = PlayerDeltaResponse;

/** 移除棋池角色请求（CS: AutoChessRemoveChessPoolCharRequest { actId, chessId }） */
export interface AutoChessRemoveChessPoolCharRequest {
  actId: string;
  chessId: string;
}

export type AutoChessRemoveChessPoolCharResponse = PlayerDeltaResponse;

/** 设置棋池助战请求（CS: AutoChessSetFriendAssistRequest { actId, assistChessId, assistUid }） */
export interface AutoChessSetFriendAssistRequest {
  actId: string;
  assistChessId: string;
  assistUid: string;
}

export type AutoChessSetFriendAssistResponse = PlayerDeltaResponse;

/** 获取好友助战列表请求（CS: AutoChessGetFriendAssistListRequest { actId, charId }） */
export interface AutoChessGetFriendAssistListRequest {
  actId: string;
  charId: string;
}

/** 获取好友助战列表响应（CS: AutoChessGetFriendAssistListResponse { assistList }） */
export interface AutoChessGetFriendAssistListResponse extends PlayerDeltaResponse {
  assistList: unknown[];
}

/* ===== 组队 / 匹配 ===== */

/** 队伍信息（CS: AutoChessTeamInfo { teamId, serverAddress, serverToken }） */
export interface AutoChessTeamInfo {
  teamId: string;
  serverAddress: string;
  serverToken: string;
}

/** 创建队伍请求（CS: AutoChessCreateTeamRequest { activityId, modeId, matchOpt, matchFlag }） */
export interface AutoChessCreateTeamRequest {
  activityId: string;
  modeId: string;
  matchOpt?: number;
  matchFlag?: boolean;
}

/** 创建队伍响应（CS: AutoChessCreateTeamResponse { result, team }） */
export interface AutoChessCreateTeamResponse extends PlayerDeltaResponse {
  result: number;
  team: AutoChessTeamInfo;
}

/** 加入队伍请求（CS: AutoChessJoinTeamRequest { activityId, teamId }） */
export interface AutoChessJoinTeamRequest {
  activityId: string;
  teamId: string;
}

/** 加入队伍响应（CS: AutoChessJoinTeamResponse { result, team }） */
export interface AutoChessJoinTeamResponse extends PlayerDeltaResponse {
  result: number;
  team: AutoChessTeamInfo;
}

/** 开始匹配请求（CS: AutoChessStartMatchRequest { activityId, option { mode, matchType } }） */
export interface AutoChessStartMatchRequest {
  activityId: string;
  option?: { mode: string; matchType?: number } | null;
}

/** 开始匹配响应（CS: AutoChessStartMatchResponse { result }） */
export interface AutoChessStartMatchResponse extends PlayerDeltaResponse {
  result: number;
}

/** 查询匹配请求（CS: AutoChessQueryMatchRequest { activityId, needLeave }） */
export interface AutoChessQueryMatchRequest {
  activityId: string;
  needLeave?: number;
}

/** 查询匹配响应（CS: AutoChessQueryMatchResponse { result, team }；result 0=OK 1=CANCEL 2=TIME_OUT） */
export interface AutoChessQueryMatchResponse extends PlayerDeltaResponse {
  result: number;
  team: AutoChessTeamInfo | null;
}

/* ===== 战斗 ===== */

/** 多人战斗开始请求（CS: AutoChessMultiBattleStartRequest { activityId, sceneId }） */
export interface AutoChessMultiBattleStartRequest {
  activityId: string;
  sceneId: string;
}

/** 引导战斗开始请求（CS: AutoChessTrainingBattleStartRequest { activityId, stageId }） */
export interface AutoChessTrainingBattleStartRequest {
  activityId: string;
  stageId: string;
}

/** 战斗开始响应（CS: CommonStartBattleResponse 子类：training/multi 均只扩展该基类） */
export interface AutoChessStartBattleResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  apFailReturn: number;
  isApProtect: number;
  inApProtectPeriod: boolean;
  notifyPowerScoreNotEnoughIfFailed: boolean;
}

export type AutoChessTrainingBattleStartResponse = AutoChessStartBattleResponse;

/** 引导战斗结束请求（CS: AutoChessTrainingBattleFinishRequest : CommonFinishBattleRequest + activityId） */
export interface AutoChessTrainingBattleFinishRequest {
  activityId: string;
  data?: string;
  battleData?: unknown;
}

/** 多人战斗结束请求（CS: AutoChessMultiBattleFinishRequest : CommonFinishBattleRequest + activityId/sceneId） */
export interface AutoChessMultiBattleFinishRequest {
  activityId: string;
  sceneId: string;
  data?: string;
  battleData?: unknown;
}

/** 战斗结束响应（CS: CommonFinishBattleResponse 子类；与 bossRush/enemyDuel 结算字段对齐） */
export interface AutoChessFinishBattleResponse extends PlayerDeltaResponse {
  result: number;
  apFailReturn: number;
  expScale: number;
  goldScale: number;
  rewards: unknown[];
  firstRewards: unknown[];
  unlockStages: string[] | null;
  unusualRewards: unknown[];
  additionalRewards: unknown[];
  furnitureRewards: unknown[];
  diamondMaterialRewards: unknown[];
  alert: unknown[];
  suggestFriend: boolean;
  pryResult: unknown[];
}

/* ===== 单机 / 结算 ===== */

/** 退出单机游戏请求（CS: AutoChessQuitSingleGameRequest { activityId, sceneId }） */
export interface AutoChessQuitSingleGameRequest {
  activityId: string;
  sceneId: string;
}

/** 退出单机游戏响应（CS: AutoChessQuitSingleGameResponse { result, battleInfo }） */
export interface AutoChessQuitSingleGameResponse extends PlayerDeltaResponse {
  result: number;
  battleInfo: ActAutoChessSyncInfoBattleInfo | null;
}

/** 结算游戏请求（CS: AutoChessSettleGameRequest { activityId, quitBattle }） */
export interface AutoChessSettleGameRequest {
  activityId: string;
  quitBattle?: boolean;
}

/** 赛季结算-出战棋子（CS: AutoChessSeasonSettleGameInfo.AutoChessSeasonSettleSquadInfo） */
export interface AutoChessSeasonSettleSquadInfo {
  chessId: string;
  equipId: string[];
}

/** 赛季结算-盟约（CS: AutoChessSeasonSettleGameInfo.AutoChessSeasonSettleBondInfo） */
export interface AutoChessSeasonSettleBondInfo {
  bondId: string;
  layer: number;
}

/** 赛季结算-Boss（CS: AutoChessSeasonSettleGameInfo.AutoChessSeasonSettleBossInfo） */
export interface AutoChessSeasonSettleBossInfo {
  bossId: string;
  isHiddenBoss: boolean;
}

/** 赛季结算-玩家战绩（CS: AutoChessSeasonSettleGameInfo.AutoChessSeasonSettleTeamInfo） */
export interface AutoChessSeasonSettleTeamInfo {
  uid: string;
  channel: number;
  passRound: number;
  gameCode: number;
  card: {
    title: string;
    nickname: string;
    nicknameNumber: string;
    level: number;
    trophyNum: number;
    secretary: string;
    secretarySkinId: string;
    secretarySkinSp: boolean;
    avatarType: string;
    avatarId: string;
    nameCardSkinId: string;
    nameCardSkinTmpl: number;
  };
  uidIndex: number;
}

/** 赛季结算-记录（CS: AutoChessSeasonSettleGameInfo.AutoChessRecordInfos） */
export interface AutoChessRecordInfos {
  trophyRecord: number;
  normalMilestone: number;
  dailyMilestone: number;
  dailyProcessAdd: number;
}

/** 赛季结算数据（CS: AutoChessSeasonSettleGameInfo） */
export interface AutoChessSeasonSettleGameInfo {
  modeId: string;
  bandId: string;
  startTs: number;
  endTs: number;
  gameFinished: boolean;
  isViolation: boolean;
  bossRecord: AutoChessSeasonSettleBossInfo[];
  onStageChars: AutoChessSeasonSettleSquadInfo[];
  onStageBond: AutoChessSeasonSettleBondInfo[];
  teamInfo: AutoChessSeasonSettleTeamInfo[];
  recordInfos: AutoChessRecordInfos;
}

/** 结算游戏响应（CS: AutoChessSettleGameResponse { result, gameSettleData }） */
export interface AutoChessSettleGameResponse extends PlayerDeltaResponse {
  result: number;
  gameSettleData: AutoChessSeasonSettleGameInfo | null;
}

/** 结算点赞请求（CS: AutoChessSettleLikeRequest { activityId, uid }） */
export interface AutoChessSettleLikeRequest {
  activityId: string;
  uid: string;
}

export type AutoChessSettleLikeResponse = PlayerDeltaResponse;

/** 上报战斗结果请求（服务端自定义，无 CS 对应类；宽松透传） */
export interface AutoChessReportRequest {
  [key: string]: unknown;
}

export type AutoChessReportResponse = PlayerDeltaResponse;
