/**
 * 肉鸽V2（集成战略）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * Roguelike、RL03、RL04 系列 Request/Response 类；字段以 CS 类为准，
 * 服务端实现有出入的字段以当前控制器契约为准（注释标注 CS 差异）。
 */
import { PlayerSquad } from "../character";
import { BattleData } from "../battle";
import { PlayerRoguelikeV2, RoguelikeNodePosition } from "../rlv2";
import { PlayerDeltaResponse } from "./common";

/* ===== 请求类型 ===== */

/** 放弃游戏请求（CS: RoguelikeTopicGiveUpGameRequest，无字段） */
export interface RoguelikeTopicGiveUpGameRequest {}

/**
 * 创建游戏请求（CS: RoguelikeTopicCreateGameRequest）
 * 服务端不读取 activityId，标为可选；mode 为字符串枚举（MONTH_TEAM/CHALLENGE/NORMAL…）
 */
export interface RoguelikeTopicCreateGameRequest {
  theme: string;
  mode: string;
  modeGrade: number;
  predefinedId: string | null;
  activityId?: string;
}

/** 选择初始密文（遗物）请求（CS: RoguelikeSelectInitialRelicRequest） */
export interface RoguelikeSelectInitialRelicRequest {
  select: string;
}

/** 选择初始招募组请求（CS: RoguelikeSelectInitialRecruitSetRequest） */
export interface RoguelikeSelectInitialRecruitSetRequest {
  select: string;
}

/** 激活招募票请求（CS: RoguelikeActivateTicketRequest） */
export interface RoguelikeActivateTicketRequest {
  id: string;
}

/** 招募干员请求（CS: RoguelikeRecruitCharRequest） */
export interface RoguelikeRecruitCharRequest {
  ticketIndex: string;
  optionId: string;
}

/** 结束事件请求（CS: RoguelikeFinishEventRequest，无字段） */
export interface RoguelikeFinishEventRequest {}

/**
 * 选择事件选项请求（CS: RoguelikeSelectChoiceRequest）
 * 抓包佐证：POST /rlv2/selectChoice body { "choice": "choice_leave" }
 */
export interface RoguelikeSelectChoiceRequest {
  choice: string;
}

/**
 * 选择事件选项响应（CS: RoguelikeSelectChoiceResponse : PlayerDeltaResponse
 * { items: List<RoguelikeItemBundle> }；服务端奖励经 rlv2:get:items 事件发放，仅返回增量）
 */
export type RoguelikeSelectChoiceResponse = PlayerDeltaResponse;

/** 移动请求（CS: RoguelikeMoveToRequest） */
export interface RoguelikeMoveToRequest {
  to: RoguelikeNodePosition;
}

/**
 * 移动并开始战斗请求
 * CS: RoguelikeStepMoveToAndStartBattleRequest { route: string[]; stageId: string }；
 * 服务端控制器契约为 { to, stageId, squad }，此处以服务端为准
 */
export interface RoguelikeStepMoveToAndStartBattleRequest {
  to: RoguelikeNodePosition;
  stageId: string;
  squad: PlayerSquad;
}

/**
 * 战斗结算请求（CS: RoguelikeFinishBattleRequest : CommonFinishBattleRequest）
 * CS 的 battleData 为 BattleDataInRequest { isCheat, completeTime, stats }，
 * 服务端契约使用 BattleData，此处以服务端为准
 */
export interface RoguelikeFinishBattleRequest {
  data: string;
  battleData: BattleData;
  battleLog: string;
}

/** 选择战斗奖励请求（CS: RoguelikeSelectRewardRequest） */
export interface RoguelikeSelectRewardRequest {
  index: number;
  sub: number;
}

/** 完成战斗奖励请求（服务端自定义，无 CS 对应类） */
export interface FinishBattleRewardRequest {}

/** 设置队伍携带请求（服务端自定义，无 CS 对应类） */
export interface SetTroopCarryRequest {
  troopCarry: string[];
}

/** 丢失密文（碎片）请求（CS: RL04LoseFragmentRequest） */
export interface RL04LoseFragmentRequest {
  fragmentIndex: string;
}

/** 使用灵感请求（CS: RL04UseInspirationRequest） */
export interface RL04UseInspirationRequest {
  fragmentIndex: string;
}

/** 置顶主题请求（CS: RoguelikePinTopicRequest） */
export interface RoguelikePinTopicRequest {
  id: string;
}

/** 刷新商店请求（CS: RoguelikeShopRefreshRequest，无字段） */
export interface RoguelikeShopRefreshRequest {}

/** 商店操作（离开）请求（CS: RoguelikeShopActionRequest） */
export interface RoguelikeShopActionRequest {
  buy: string[];
  recycle: string[];
  leave: number;
}

/**
 * 使用图腾请求（CS: RL03UseTotemRequest { totemIndex: string[]; nodeIndex: string[] }；
 * 服务端契约 totemIndex 为二元组，此处以服务端为准）
 */
export interface RL03UseTotemRequest {
  totemIndex: [string, string];
  nodeIndex: string[];
}

/** 确认预言请求（CS: RL03ConfirmPredictRequest，无字段） */
export interface RL03ConfirmPredictRequest {}

/** 关闭招募票请求（CS: RoguelikeCloseTicketRequest） */
export interface RoguelikeCloseTicketRequest {
  id: string;
}

/* ===== 响应类型 ===== */

/** 放弃游戏响应（CS: RoguelikeTopicGiveUpGameResponse） */
export type RoguelikeTopicGiveUpGameResponse = PlayerDeltaResponse;

/** 创建游戏响应（CS: RoguelikeTopicCreateGameResponse） */
export type RoguelikeTopicCreateGameResponse = PlayerDeltaResponse;

/** 选择初始密文响应（CS: RoguelikeSelectInitialRelicResponse） */
export type RoguelikeSelectInitialRelicResponse = PlayerDeltaResponse;

/** 选择初始招募组响应（CS: RoguelikeSelectInitialRecruitSetResponse） */
export type RoguelikeSelectInitialRecruitSetResponse = PlayerDeltaResponse;

/** 激活招募票响应（CS: RoguelikeActivateTicketResponse） */
export type RoguelikeActivateTicketResponse = PlayerDeltaResponse;

/** 招募干员响应（CS: RoguelikeRecruitCharResponse） */
export interface RoguelikeRecruitCharResponse extends PlayerDeltaResponse {
  chars: PlayerRoguelikeV2.CurrentData.RecruitChar[];
}

/** 结束事件响应（CS: RoguelikeFinishEventResponse） */
export type RoguelikeFinishEventResponse = PlayerDeltaResponse;

/** 移动响应（CS: RoguelikeMoveToResponse） */
export type RoguelikeMoveToResponse = PlayerDeltaResponse;

/** 移动并开始战斗响应（CS: RoguelikeStepMoveToAndStartBattleResponse；服务端仅返回增量） */
export type RoguelikeStepMoveToAndStartBattleResponse = PlayerDeltaResponse;

/** 战斗结算响应（CS: RoguelikeFinishBattleResponse : CommonFinishBattleResponse；服务端仅返回增量） */
export type RoguelikeFinishBattleResponse = PlayerDeltaResponse;

/** 选择战斗奖励响应（CS: RoguelikeSelectRewardResponse） */
export type RoguelikeSelectRewardResponse = PlayerDeltaResponse;

/** 完成战斗奖励响应（服务端自定义） */
export type FinishBattleRewardResponse = PlayerDeltaResponse;

/** 设置队伍携带响应（服务端自定义） */
export type SetTroopCarryResponse = PlayerDeltaResponse;

/** 丢失密文响应（CS: RL04LoseFragmentResponse） */
export type RL04LoseFragmentResponse = PlayerDeltaResponse;

/** 使用灵感响应（CS: RL04UseInspirationResponse） */
export type RL04UseInspirationResponse = PlayerDeltaResponse;

/** 置顶主题响应（CS: RoguelikePinTopicResponse） */
export type RoguelikePinTopicResponse = PlayerDeltaResponse;

/** 刷新商店响应（CS: RoguelikeShopRefreshResponse） */
export type RoguelikeShopRefreshResponse = PlayerDeltaResponse;

/** 商店操作响应（CS: RoguelikeShopActionResponse） */
export type RoguelikeShopActionResponse = PlayerDeltaResponse;

/** 使用图腾响应（CS: RL03UseTotemResponse） */
export type RL03UseTotemResponse = PlayerDeltaResponse;

/** 确认预言响应（CS: RL03ConfirmPredictResponse） */
export type RL03ConfirmPredictResponse = PlayerDeltaResponse;

/** 关闭招募票响应（CS: RoguelikeCloseTicketResponse） */
export type RoguelikeCloseTicketResponse = PlayerDeltaResponse;
