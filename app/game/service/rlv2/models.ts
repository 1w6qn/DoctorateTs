/**
 * 肉鸽V2（集成战略）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * Roguelike、RL03、RL04 系列 Request/Response 类；字段以 CS 类为准，
 * 服务端实现有出入的字段以当前控制器契约为准（注释标注 CS 差异）。
 */
import { PlayerSquad } from "../../domain/character";
import { BattleData } from "../../domain/battle";
import { PlayerRoguelikeV2, RoguelikeNodePosition } from "../../domain/rlv2";
import { PlayerDeltaResponse } from "../../domain/contracts/common";

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

/** 月度任务刷新响应（CS: RoguelikeTopicRefreshMissionResponse，body { theme, index }） */
export type RoguelikeTopicRefreshMissionResponse = PlayerDeltaResponse;

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

/* ===== rogue_3/4/5 机制 stub（控制器未实现，返回空增量）===== */

/** 通用肉鸽 stub 请求（bank/copper/gridZone/nodeMission 等未实现机制；不读取 body） */
export interface RoguelikeStubRequest {
  id?: string;
  index?: number;
  sub?: number;
}

/** 通用肉鸽 stub 响应（仅增量） */
export type RoguelikeStubResponse = PlayerDeltaResponse;

/** 肉鸽商店购买请求（CS: RoguelikeShopActionRequest { action, goodsId }；服务端控制器读 select） */
export interface RoguelikeBuyGoodsRequest {
  select?: number;
  action?: string;
  goodsId?: string;
}

/** 肉鸽商店购买响应（服务端仅返回增量） */
export type RoguelikeBuyGoodsResponse = PlayerDeltaResponse;

/* ===== 完整机制协议类型（2026-08-10 对照 CS 2.7.61 + 抓包补全）===== */

/** 读取结局变更请求（CS: RoguelikeReadEndingChangeRequest，无字段） */
export interface RoguelikeReadEndingChangeRequest {}

/** 读取结局变更响应 */
export type RoguelikeReadEndingChangeResponse = PlayerDeltaResponse;

/** 确认区域奖励请求（CS: RoguelikeZoneRewardRequest { itemType }） */
export interface RoguelikeZoneRewardRequest {
  itemType?: string;
}

/** 确认区域奖励响应 */
export type RoguelikeZoneRewardResponse = PlayerDeltaResponse;

/** 确认商人返回请求（CS: RoguelikeTraderReturnRequest，无字段） */
export interface RoguelikeTraderReturnRequest {}

/** 确认商人返回响应 */
export type RoguelikeTraderReturnResponse = PlayerDeltaResponse;

/** 离开特殊区域请求（CS: RoguelikeSpecialZoneLeaveRequest，无字段） */
export interface RoguelikeSpecialZoneLeaveRequest {}

/** 离开特殊区域响应 */
export type RoguelikeSpecialZoneLeaveResponse = PlayerDeltaResponse;

/** 战令领奖请求（抓包 { theme, rewards }，CS 无对应类） */
export interface RoguelikeBattlePassGetRewardRequest {
  theme: string;
  rewards: string[];
}

/** 战令领奖响应（CS 无对应类；抓包：items + playerDataDelta） */
export interface RoguelikeBattlePassGetRewardResponse extends PlayerDeltaResponse {
  items: { type?: string; id: string; count: number }[];
}

/** 银行存钱请求（CS: RoguelikeBankInvestRequest，无字段） */
export interface RoguelikeBankInvestRequest {}

/** 银行存钱响应 */
export type RoguelikeBankInvestResponse = PlayerDeltaResponse;

/** 银行取钱请求（CS: RoguelikeBankWithdrawRequest；抓包 { count }） */
export interface RoguelikeBankWithdrawRequest {
  count?: number;
}

/** 银行取钱响应 */
export type RoguelikeBankWithdrawResponse = PlayerDeltaResponse;

/** 确认节点任务请求（CS: RoguelikeConfirmNodeMissionRequest，无字段） */
export interface RoguelikeConfirmNodeMissionRequest {}

/** 确认节点任务响应 */
export type RoguelikeConfirmNodeMissionResponse = PlayerDeltaResponse;

/** 放弃节点任务请求（CS: RoguelikeGiveUpNodeMissionRequest，无字段） */
export interface RoguelikeGiveUpNodeMissionRequest {}

/** 放弃节点任务响应 */
export type RoguelikeGiveUpNodeMissionResponse = PlayerDeltaResponse;

/** 关闭节点任务提示请求（CS: RoguelikeReadMissionTipRequest，无字段） */
export interface RoguelikeReadMissionTipRequest {}

/** 关闭节点任务提示响应 */
export type RoguelikeReadMissionTipResponse = PlayerDeltaResponse;

/** 获取招募票助战列表请求（CS: RoguelikeGetTicketAssistListRequest） */
export interface RoguelikeGetTicketAssistListRequest {
  ticketIndex: string;
  profession: string;
}

/** 获取招募票助战列表响应 */
export type RoguelikeGetTicketAssistListResponse = PlayerDeltaResponse;

/** 招募助战干员请求（CS: RoguelikeRecruitAssistCharRequest） */
export interface RoguelikeRecruitAssistCharRequest {
  ticketIndex: string;
  profession: string;
  assistUid: string;
  assistCharId: string;
}

/** 招募助战干员响应 */
export type RoguelikeRecruitAssistCharResponse = PlayerDeltaResponse;

/** 远征选择请求（CS: RoguelikeExpeditionRequest { choice, leave }；抓包 body { choice, leave }） */
export interface RoguelikeExpeditionRequest {
  choice?: string;
  leave?: number;
}

/** 远征选择响应（抓包：{ result: 1 } + playerDataDelta） */
export interface RoguelikeExpeditionResponse extends PlayerDeltaResponse {
  result: number;
}

/** 确认远征返回请求（CS: RoguelikeExpedReturnRequest，无字段） */
export interface RoguelikeExpedReturnRequest {}

/** 确认远征返回响应 */
export type RoguelikeExpedReturnResponse = PlayerDeltaResponse;

/** 骰子选择请求（CS: RoguelikeDiceChoiceRequest { choice }；抓包 body 含 choice） */
export interface RoguelikeDiceChoiceRequest {
  choice?: string;
}

/** 骰子选择响应（抓包：{ result: 1 } + playerDataDelta） */
export interface RoguelikeDiceChoiceResponse extends PlayerDeltaResponse {
  result: number;
}

/** 献祭选择请求（CS: RoguelikeSacrificeRequest { choice, leave }） */
export interface RoguelikeSacrificeRequest {
  choice?: string;
  leave?: number;
}

/** 献祭选择响应 */
export type RoguelikeSacrificeResponse = PlayerDeltaResponse;

/** 铜币镀金请求（CS: RoguelikeGildRequest { choice, leave }） */
export interface RoguelikeGildRequest {
  choice?: string;
  leave?: number;
}

/** 铜币镀金响应 */
export type RoguelikeGildResponse = PlayerDeltaResponse;

/** 铜币重抽请求（COPPER 模块，抓包派生） */
export interface RoguelikeCopperRedrawRequest {}

/** 铜币重抽响应（ODPY 参考：{ copper, divineEventId } + playerDataDelta） */
export interface RoguelikeCopperRedrawResponse extends PlayerDeltaResponse {
  copper?: string[];
  divineEventId?: string;
}

/** 商店战斗开始请求（CS: RoguelikeShopBattleRequest，无字段） */
export interface RoguelikeShopBattleRequest {}

/** 商店战斗开始响应 */
export type RoguelikeShopBattleResponse = PlayerDeltaResponse;

/** 重掷节点请求（CS: RoguelikeRollNodeRequest { nodeIndex }；抓包 body { nodeIndex }） */
export interface RoguelikeRollNodeRequest {
  nodeIndex: string;
}

/** 重掷节点响应 */
export type RoguelikeRollNodeResponse = PlayerDeltaResponse;

/** 升级节点请求（CS: RoguelikeUpgradeNodeRequest { nodeType }；抓包 body { nodeType: "REST" }） */
export interface RoguelikeUpgradeNodeRequest {
  nodeType: string;
}

/** 升级节点响应 */
export type RoguelikeUpgradeNodeResponse = PlayerDeltaResponse;

/** 暂存招募票请求（CS: RoguelikeStashTicketRequest { index }） */
export interface RoguelikeStashTicketRequest {
  index: string;
}

/** 暂存招募票响应 */
export type RoguelikeStashTicketResponse = PlayerDeltaResponse;

/** 使用暂存票请求（CS: RoguelikeStashedTicketUseRequest { id }） */
export interface RoguelikeStashedTicketUseRequest {
  id: string;
}

/** 使用暂存票响应 */
export type RoguelikeStashedTicketUseResponse = PlayerDeltaResponse;

/** 选择初始探索工具请求（CS: RoguelikeSelectInitialExploreToolRequest { select }） */
export interface RoguelikeSelectInitialExploreToolRequest {
  select: string;
}

/** 选择初始探索工具响应 */
export type RoguelikeSelectInitialExploreToolResponse = PlayerDeltaResponse;

/** 炼金请求（抓包 { leave }；fragment 模块） */
export interface RoguelikeAlchemyRequest {
  leave?: number;
  index?: string[];
}

/** 炼金响应 */
export type RoguelikeAlchemyResponse = PlayerDeltaResponse;

/** 炼金奖励请求（抓包 { index }） */
export interface RoguelikeAlchemyRewardRequest {
  index?: number;
}

/** 炼金奖励响应 */
export type RoguelikeAlchemyRewardResponse = PlayerDeltaResponse;

/** 网格区域移动请求（抓包 { route: [nodeIndex] }） */
export interface RoguelikeGridZoneMoveToRequest {
  route: string[];
}

/** 网格区域移动响应 */
export type RoguelikeGridZoneMoveToResponse = PlayerDeltaResponse;

/** 网格区域移动并战斗请求（抓包 { route, stageId, squad }） */
export interface RoguelikeGridZoneMoveAndBattleStartRequest {
  route: string[];
  stageId: string;
  squad: PlayerSquad;
}

/** 网格区域移动并战斗响应 */
export type RoguelikeGridZoneMoveAndBattleStartResponse = PlayerDeltaResponse;

/** 网格区域空步（GRID_ZONE 模块）请求 */
export interface RoguelikeGridZoneEmptyStepRequest {}

/** 网格区域空步响应 */
export type RoguelikeGridZoneEmptyStepResponse = PlayerDeltaResponse;

/** 网格区域读取第 0 步（GRID_ZONE 模块）请求 */
export interface RoguelikeGridZoneReadStepZeroRequest {}

/** 网格区域读取第 0 步响应 */
export type RoguelikeGridZoneReadStepZeroResponse = PlayerDeltaResponse;

/** 游戏结算请求（抓包 body {}；结算逻辑已在控制器 gameSettle） */
export interface RoguelikeGameSettleRequest {}

/** 游戏结算响应 */
export type RoguelikeGameSettleResponse = PlayerDeltaResponse;

/** 废品操作请求（rogue_6 SCRAP 模块，抓包派生） */
export interface RoguelikeScrapRequest {
  action?: string;
  scrapId?: string;
}

/** 废品操作响应 */
export type RoguelikeScrapResponse = PlayerDeltaResponse;

/** 废品换乘请求（rogue_6 SCRAP MOVE 型，抓包 { scrapInstId, toWalk }） */
export interface RoguelikeScrapChangeVehicleRequest {
  scrapId?: string;
  scrapInstId?: string;
  toWalk?: number;
}

/** 废品换乘响应 */
export type RoguelikeScrapChangeVehicleResponse = PlayerDeltaResponse;

/** 丢弃废品请求（rogue_6 SCRAP 模块，抓包 { instId }） */
export interface RoguelikeScrapLoseRequest {
  instId: string;
}

/** 丢弃废品响应 */
export type RoguelikeScrapLoseResponse = PlayerDeltaResponse;
