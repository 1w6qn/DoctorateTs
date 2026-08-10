/**
 * 基建协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * BuildingSyncRequest / BuildingAssignCharRequest / BuildingTradingDeliveryRequest /
 * BuildingMeetingClue*Request 等 Request/Response 类；字段以 CS 类为准，
 * 服务端未返回的协议字段标为可选。
 * 部分接口（升级自定义等级等）无 CS 类对应，标注为服务端自定义。
 */
import { ItemBundle } from "@excel/character_table";
import { PlayerBuildingDIYSolution, PlayerBuildingMeetingClue } from "../playerdata";
import { PlayerDeltaResponse } from "./common";

/* ===== 同步与基础设置 ===== */

/** 同步基建数据请求（CS: BuildingSyncRequest，无字段） */
export interface BuildingSyncRequest {}

/** 同步基建数据响应（CS: BuildingSyncResponse） */
export interface BuildingSyncResponse extends PlayerDeltaResponse {
  ts: number;
}

/** 切换基建背景音乐请求（CS: BuildingChangeBGMRequest） */
export interface ChangeBGMRequest {
  musicId: string;
}

/** 切换基建背景音乐响应（CS: BuildingChangeBGMResponse） */
export type ChangeBGMResponse = PlayerDeltaResponse;

/**
 * 设置私人宿舍归属请求（CS: BuildingPayloadSetPrivateDormOwnerRequest）
 * CS 字段名为 charInsId，服务端读取 charInstId（以服务端为准）
 */
export interface SetPrivateDormOwnerRequest {
  slotId: string;
  charInsId?: number;
  charInstId: number;
}

/** 设置私人宿舍归属响应（CS: BuildingPayloadSetPrivateDormOwnerResponse） */
export type SetPrivateDormOwnerResponse = PlayerDeltaResponse;

/** 设置基建助战干员请求（CS: BuildingSetAssistRequest） */
export interface SetBuildingAssistRequest {
  type: number;
  charInstId: number;
}

/** 设置基建助战干员响应（CS: BuildingSetAssistResponse） */
export type SetBuildingAssistResponse = PlayerDeltaResponse;

/* ===== 房间管理 ===== */

/** 建造房间请求（CS: BuildingBuildRoomRequest） */
export interface BuildRoomRequest {
  roomSlotId: string;
  roomId: string;
}

/** 建造房间响应（CS: BuildingBuildRoomResponse；服务端仅返回增量） */
export type BuildRoomResponse = PlayerDeltaResponse;

/** 升级房间等级请求（CS: BuildingUpgradeRoomRequest） */
export interface UpgradeRoomRequest {
  roomSlotId: string;
  targetLevel: number;
}

/** 升级房间等级响应（CS: BuildingUpgradeRoomResponse；服务端仅返回增量） */
export type UpgradeRoomResponse = PlayerDeltaResponse;

/**
 * 完成房间升级请求（CS: BuildingUpgradeCompleteRoomRequest）
 * 服务端未读取请求体
 */
export interface CompleteUpgradeRoomRequest {
  roomSlotId?: string;
  targetLevel?: number;
}

/** 完成房间升级响应（CS: BuildingUpgradeCompleteRoomResponse；服务端仅返回增量） */
export type CompleteUpgradeRoomResponse = PlayerDeltaResponse;

/**
 * 降级房间请求（CS: BuildingDegradeRoomRequest）
 * CS 另有 targetLevel 字段，服务端未读取
 */
export interface DegradeRoomRequest {
  roomSlotId: string;
  targetLevel?: number;
}

/** 降级房间响应（CS: BuildingDegradeRoomResponse；服务端仅返回增量） */
export type DegradeRoomResponse = PlayerDeltaResponse;

/**
 * 专精升级请求（CS: UpdateSpecializationRequest）
 * CS 字段为 skillIndex，服务端读取 charInstId/targetSkill（以服务端为准）
 */
export interface UpgradeSpecializationRequest {
  charInstId: number;
  targetSkill: number;
  skillIndex?: number;
  reduceTimeBd?: unknown;
}

/** 专精升级响应（CS: UpdateSpecializationResponse） */
export type UpgradeSpecializationResponse = PlayerDeltaResponse;

/**
 * 完成专精升级请求（CS: CompleteUpgradeSpecializationRequest : BuildingRequest，无字段）
 * 服务端读取 charInstId/targetSkill（以服务端为准）
 */
export interface CompleteUpgradeSpecializationRequest {
  charInstId: number;
  targetSkill: number;
}

/** 完成专精升级响应（CS: CompleteUpgradeSpecializationResponse） */
export type CompleteUpgradeSpecializationResponse = PlayerDeltaResponse;

/** 升级自定义等级请求（服务端自定义，无 CS 对应类；服务端未读取请求体） */
export interface UpgradeDiyLevelRequest {}

/** 升级自定义等级响应（服务端自定义；仅增量） */
export type UpgradeDiyLevelResponse = PlayerDeltaResponse;

/* ===== 干员分配 ===== */

/** 分配干员到房间请求（CS: BuildingAssignCharRequest） */
export interface AssignCharRequest {
  roomSlotId: string;
  charInstIdList: number[];
}

/** 分配干员到房间响应（CS: BuildingAssignCharResponse） */
export type AssignCharResponse = PlayerDeltaResponse;

/**
 * 批量更换工作干员请求（CS: BuildingBatchChangeWorkCharRequest 无字段）
 * 服务端读取 roomSlotId/charInstIdList（以服务端为准）
 */
export interface BatchChangeWorkCharRequest {
  roomSlotId: string;
  charInstIdList: number[];
}

/** 批量更换工作干员响应（CS: BuildingBatchChangeWorkCharResponse） */
export type BatchChangeWorkCharResponse = PlayerDeltaResponse;

/**
 * 批量休息干员请求（CS: BuildingBatchChangeRestCharRequest 无字段）
 * 服务端读取 charInstIdList（以服务端为准）
 */
export interface BatchRestCharRequest {
  charInstIdList: number[];
}

/** 批量休息干员响应（CS: BuildingBatchChangeRestCharResponse） */
export type BatchRestCharResponse = PlayerDeltaResponse;

/** 获得信赖请求（CS: CharBuildIncIntimacyRequest） */
export interface GainIntimacyRequest {
  charInstId: number;
}

/** 获得信赖响应（CS: CharBuildIncIntimacyResponse） */
export type GainIntimacyResponse = PlayerDeltaResponse;

/** 获得全部信赖请求（CS: BuildingGainAllIntimacyRequest，无字段） */
export interface GainAllIntimacyRequest {}

/** 获得全部信赖响应（CS: BuildingGainAllIntimacyResponse { normal: Int32, assist: Int32 }） */
export interface GainAllIntimacyResponse extends PlayerDeltaResponse {
  normal: number;
  assist: number;
}

/** 获得助战信赖请求（CS: CharBuildIncAssistIntimacyRequest） */
export interface GainAssistIntimacyRequest {
  charInstId: number;
}

/** 获得助战信赖响应（CS: CharBuildIncAssistIntimacyResponse） */
export type GainAssistIntimacyResponse = PlayerDeltaResponse;

/** 确认私人宿舍信赖请求（CS: BuildingPayloadConfirmPrivateDormIntimacyRequest） */
export interface ConfirmPrivateDormIntimacyRequest {
  charInstId: number;
}

/** 确认私人宿舍信赖响应（CS: BuildingPayloadConfirmPrivateDormIntimacyResponse） */
export type ConfirmPrivateDormIntimacyResponse = PlayerDeltaResponse;

/** 清理房间槽位请求（CS: BuildingCleanRoomRequest） */
export interface CleanRoomSlotRequest {
  roomSlotId: string;
}

/** 清理房间槽位响应（CS: BuildingCleanRoomResponse；服务端仅返回增量） */
export type CleanRoomSlotResponse = PlayerDeltaResponse;

/* ===== 订单/生产 ===== */

/**
 * 加速订单请求（CS: BuildingTradingLaborAccelRequest）
 * CS 另有 cost 字段，服务端未读取
 */
export interface AccelerateOrderRequest {
  slotId: string;
  orderId: number;
  cost?: number;
}

/** 加速订单响应（CS: BuildingTradingLaborAccelResponse；服务端仅返回增量） */
export type AccelerateOrderResponse = PlayerDeltaResponse;

/**
 * 加速方案请求（CS: BuildingManufactLaborAccelRequest）
 * CS 另有 cost 字段，服务端未读取
 */
export interface AccelerateSolutionRequest {
  slotId: string;
  cost?: number;
}

/** 加速方案响应（CS: BuildingManufactLaborAccelResponse） */
export type AccelerateSolutionResponse = PlayerDeltaResponse;

/**
 * 完成订单请求（CS: BuildingTradingDeliveryRequest）
 * CS 的 orderId 为 Int64，服务端以 string 读取（以服务端为准）
 */
export interface DeliveryOrderRequest {
  slotId: string;
  orderId: string;
}

/** 完成订单响应（CS: BuildingTradingDeliveryResponse） */
export type DeliveryOrderResponse = PlayerDeltaResponse;

/**
 * 批量完成订单请求（CS: BuildingDeliveryBatchOrderRequest { slotList }——
 * 结算每个贸易站的全部库存订单）
 */
export interface DeliveryBatchOrderRequest {
  slotList?: string[];
}

/** 批量完成订单响应（CS: BuildingDeliveryBatchOrderResponse { delivered: Dictionary<String,List<ItemBundle>> }） */
export interface DeliveryBatchOrderResponse extends PlayerDeltaResponse {
  delivered: { [slotId: string]: ItemBundle[] };
}

/**
 * 删除订单请求（CS: BuildingTradingDeleteOrderRequest）
 * CS 的 orderId 为 Int64
 */
export interface DeleteOrderRequest {
  slotId: string;
  orderId: number;
}

/** 删除订单响应（CS: BuildingTradingDeleteOrderResponse） */
export type DeleteOrderResponse = PlayerDeltaResponse;

/** 制造站结算请求（CS: BuildingSettleManufactRequest { roomSlotIdList, supplement }） */
export interface SettleManufactureRequest {
  roomSlotIdList?: string[];
  supplement?: number;
}

/** 制造站结算响应（CS: BuildingSettleManufactResponse { supplement: Int32 }） */
export interface SettleManufactureResponse extends PlayerDeltaResponse {
  supplement: number;
}

/**
 * 贸易站结算请求（CS: BuildingSettleSaleRequest）
 * CS 字段为 roomSlotIdList，服务端读取 slotId（以服务端为准）
 */
export interface SettleSaleRequest {
  roomSlotIdList?: string[];
  slotId: string;
}

/** 贸易站结算响应（CS: BuildingSettleSaleResponse） */
export type SettleSaleResponse = PlayerDeltaResponse;

/** 更换制造方案请求（CS: BuildingChangeManufactRequest） */
export interface ChangeManufactureSolutionRequest {
  roomSlotId: string;
  targetFormulaId: string;
  solutionCount: number;
}

/** 更换制造方案响应（CS: BuildingChangeManufactResponse；服务端仅返回增量） */
export type ChangeManufactureSolutionResponse = PlayerDeltaResponse;

/**
 * 更换贸易方案请求（CS: BuildingChangeShopRequest）
 * CS 字段为 roomSlotId/stockIndex/targetFormulaId/solutionCount，
 * 服务端读取 slotId/solution（以服务端为准）
 */
export interface ChangeSaleSolutionRequest {
  roomSlotId?: string;
  stockIndex?: number;
  targetFormulaId?: string;
  solutionCount?: number;
  slotId: string;
  solution: { strategy: string; stockLimit: number };
}

/** 更换贸易方案响应（CS: BuildingChangeShopResponse；服务端仅返回增量） */
export type ChangeSaleSolutionResponse = PlayerDeltaResponse;

/** 更换自定义方案请求（CS: BuildingDIYChangeDIYSolutionRequest） */
export interface ChangeDiySolutionRequest {
  roomSlotId: string;
  solution: PlayerBuildingDIYSolution;
}

/** 更换自定义方案响应（CS: BuildingDIYChangeDIYResponse） */
export type ChangeDiySolutionResponse = PlayerDeltaResponse;

/**
 * 加工站合成请求（CS: BuildingWorkshopSynthesisRequest）
 * CS 无 roomSlotId，服务端额外读取（以服务端为准）
 */
export interface WorkshopSynthesisRequest {
  roomSlotId: string;
  formulaId: string;
  times: number;
}

/**
 * 加工站合成响应（CS: BuildingWorkshopSynthesisResponse）
 * CS 的 results 为 ItemBundle，服务端仅返回 results（additional/recoverCost 省略）
 */
export interface WorkshopSynthesisResponse extends PlayerDeltaResponse {
  results: ItemBundle | null;
  additional?: ItemBundle[];
  recoverCost?: number;
}

/**
 * 加工站分解请求（CS: BuildingWorkshopDecompositionRequest）
 * CS 字段为 furniId/times，服务端读取 furnitureId/count（以服务端为准）
 */
export interface WorkshopDecompositionRequest {
  furniId?: string;
  times?: number;
  furnitureId: string;
  count: number;
}

/** 加工站分解响应（CS: BuildingWorkshopDecompositionResponse；服务端仅返回增量） */
export type WorkshopDecompositionResponse = PlayerDeltaResponse;

/* ===== 线索系统 ===== */

/** 获取每日线索请求（CS: BuildingMeetingClueGetDailyClueRequest，无字段） */
export interface GetDailyClueRequest {}

/** 获取每日线索响应（CS: BuildingMeetingClueGetDailyClueResponse；服务端仅返回增量） */
export type GetDailyClueResponse = PlayerDeltaResponse;

/**
 * 发送线索请求（CS: BuildingMeetingClueSendClueRequest）
 * CS 字段为 friendId/clueId，服务端读取 id/friendId（以服务端为准）
 */
export interface SendClueRequest {
  friendId: string;
  clueId?: string;
  id: string;
}

/** 发送线索响应（CS: BuildingMeetingClueSendClueResponse） */
export type SendClueResponse = PlayerDeltaResponse;

/** 自动发送线索请求（CS: BuildingMeetingClueAutoSendClueRequest，无字段） */
export interface SendClueAutoRequest {}

/** 自动发送线索响应（CS: BuildingMeetingClueAutoSendClueResponse；服务端仅返回增量） */
export type SendClueAutoResponse = PlayerDeltaResponse;

/**
 * 接收线索到库存请求（CS: BuildingMeetingClueReceiveClueToStockRequest）
 * CS 字段为 clues 列表，服务端读取 id（以服务端为准）
 */
export interface ReceiveClueToStockRequest {
  clues?: string[];
  id: string;
}

/** 接收线索到库存响应（CS: BuildingMeetingClueReceiveClueToStockResponse） */
export type ReceiveClueToStockResponse = PlayerDeltaResponse;

/**
 * 放置线索到留言板请求（CS: BuildingMeetingCluePutClueToTheBoardRequest）
 * CS 字段为 clueId，服务端读取 id（以服务端为准）
 */
export interface PutClueToTheBoardRequest {
  clueId?: string;
  id: string;
}

/** 放置线索到留言板响应（CS: BuildingMeetingCluePutClueToTheBoardResponse） */
export type PutClueToTheBoardResponse = PlayerDeltaResponse;

/** 自动放置线索到留言板请求（CS: BuildingMeetingClueAutoEquipCluesRequest，无字段） */
export interface PutClueToTheBoardAutoRequest {}

/** 自动放置线索到留言板响应（CS: BuildingMeetingClueAutoEquipCluesResponse；服务端仅返回增量） */
export type PutClueToTheBoardAutoResponse = PlayerDeltaResponse;

/**
 * 删除自己持有的线索请求（CS: BuildingMeetingClueDeleteOwnClueRequest）
 * CS 字段为 clueId，服务端读取 id（以服务端为准）
 */
export interface DeleteOwnClueRequest {
  clueId?: string;
  id: string;
}

/** 删除自己持有的线索响应（CS: BuildingMeetingClueDeleteOwnClueResponse） */
export type DeleteOwnClueResponse = PlayerDeltaResponse;

/**
 * 删除接收到的线索请求（CS: BuildingMeetingClueDeleteReceiveClueRequest）
 * CS 字段为 clueId，服务端读取 id（以服务端为准）
 */
export interface DeleteReceiveClueRequest {
  clueId?: string;
  id: string;
}

/** 删除接收到的线索响应（CS: BuildingMeetingClueDeleteReceiveClueResponse） */
export type DeleteReceiveClueResponse = PlayerDeltaResponse;

/** 获取线索盒请求（CS: BuildingMeetingClueUpdateWaitingClueRequest，无字段） */
export interface GetClueBoxRequest {}

/**
 * 获取线索盒响应（CS: BuildingMeetingClueUpdateWaitingClueResponse）
 * 服务端 box 为 ownStock + receiveStock，复用 PlayerBuildingMeetingClue
 */
export interface GetClueBoxResponse extends PlayerDeltaResponse {
  box: PlayerBuildingMeetingClue[];
}

/** 获取线索好友列表请求（CS: BuildingGetFriendSortListInfoRequest，无字段） */
export interface GetClueFriendListRequest {}

/** 线索好友列表条目（服务端返回结构，CS 为 FriendSortViewModel） */
export interface ClueFriendInfo {
  uid: string;
  nickName: string;
  nickNumber: string;
  level: number;
}

/** 获取线索好友列表响应（CS: BuildingGetFriendSortListInfoResponse；服务端仅返回 result） */
export interface GetClueFriendListResponse extends PlayerDeltaResponse {
  result: ClueFriendInfo[];
  starFriendList?: string[];
}

/**
 * 获取会议室奖励请求（CS: BuildingMeetingClueGetMeetingRoomRewardRequest）
 * CS 字段为 type 列表，服务端未读取请求体
 */
export interface GetMeetingroomRewardRequest {
  type?: number[];
}

/** 会议室奖励条目（服务端返回结构） */
export interface MeetingroomRewardItem {
  type: string;
  count: number;
}

/** 获取会议室奖励响应（CS: BuildingMeetingClueGetMeetingRoomRewardResponse；服务端返回 rewards） */
export interface GetMeetingroomRewardResponse extends PlayerDeltaResponse {
  rewards: MeetingroomRewardItem[];
}

/* ===== 预设队列 ===== */

/**
 * 添加预设队列请求（CS: BuildingAddPresetQueueRequest）
 * CS 字段为 slotId，服务端读取 roomSlotId/presetName/charInstIdList（以服务端为准）
 */
export interface AddPresetQueueRequest {
  slotId?: string;
  roomSlotId: string;
  presetName: string;
  charInstIdList: number[];
}

/** 添加预设队列响应（CS: BuildingAddPresetQueueResponse） */
export type AddPresetQueueResponse = PlayerDeltaResponse;

/**
 * 删除预设队列请求（CS: BuildingDeletePresetQueueRequest）
 * CS 另有 index 字段，服务端未读取
 */
export interface DeletePresetQueueRequest {
  slotId?: string;
  index?: number;
  roomSlotId: string;
}

/** 删除预设队列响应（CS: BuildingDeletePresetQueueResponse） */
export type DeletePresetQueueResponse = PlayerDeltaResponse;

/**
 * 编辑预设队列请求（CS: BuildingEditPresetQueueRequest）
 * CS 字段为 slotId/index/queue，服务端读取 roomSlotId/presetName/charInstIdList（以服务端为准）
 */
export interface EditPresetQueueRequest {
  slotId?: string;
  index?: number;
  queue?: number[];
  roomSlotId: string;
  presetName?: string;
  charInstIdList?: number[];
}

/** 编辑预设队列响应（CS: BuildingEditPresetQueueResponse） */
export type EditPresetQueueResponse = PlayerDeltaResponse;

/**
 * 使用预设队列请求（CS: BuildingUsePresetQueueRequest）
 * CS 另有 index 字段，服务端未读取
 */
export interface UsePresetQueueRequest {
  slotId?: string;
  index?: number;
  roomSlotId: string;
}

/** 使用预设队列响应（CS: BuildingUsePresetQueueResponse） */
export type UsePresetQueueResponse = PlayerDeltaResponse;

/**
 * 使用单个预设队列请求（CS: BuildingUsePresetQueueRequest）
 * 服务端读取 roomSlotId
 */
export interface UseOnePresetQueueRequest {
  slotId?: string;
  index?: number;
  roomSlotId: string;
}

/** 使用单个预设队列响应（CS: BuildingUsePresetQueueResponse） */
export type UseOnePresetQueueResponse = PlayerDeltaResponse;

/**
 * 修改预设名称请求（CS: BuildingDIYRenamePresetSolutionRequest）
 * CS 字段为 solutionId/name，服务端读取 roomSlotId/presetName（以服务端为准）
 */
export interface ChangePresetNameRequest {
  solutionId?: number;
  name?: string;
  roomSlotId: string;
  presetName: string;
}

/** 修改预设名称响应（CS: BuildingDIYRenamePresetSolutionResponse） */
export type ChangePresetNameResponse = PlayerDeltaResponse;

/**
 * 保存自定义预设方案请求（CS: BuildingDIYSavePresetSolutionRequest）
 * CS 字段含 solutionId/roomType/thumbnail，服务端读取 presetName/solution（以服务端为准）
 */
export interface SaveDiyPresetSolutionRequest {
  solutionId?: number;
  roomType?: string;
  name?: string;
  thumbnail?: string;
  presetName: string;
  solution: unknown;
}

/** 保存自定义预设方案响应（CS: BuildingDIYSavePresetSolutionResponse） */
export type SaveDiyPresetSolutionResponse = PlayerDeltaResponse;

/**
 * 编辑锁定队列请求（CS: BuildingSaveDormLockRequest）
 * CS 字段为 lockPos 字典，服务端读取 roomSlotId/locked（以服务端为准）
 */
export interface EditLockQueueRequest {
  lockPos?: { [key: string]: number[] };
  roomSlotId: string;
  locked: boolean;
}

/** 编辑锁定队列响应（CS: BuildingSaveDormLockResponse） */
export type EditLockQueueResponse = PlayerDeltaResponse;

/* ===== 其他功能 ===== */

/**
 * 更改贸易站策略请求（CS: BuildingTradingChangeStrategyRequest）
 * CS 的 strategy 为 OrderType 枚举，服务端以字符串读取
 */
export interface ChangeStrategyRequest {
  slotId: string;
  strategy: string;
}

/** 更改贸易站策略响应（CS: BuildingTradingChangeStrategyResponse） */
export type ChangeStrategyResponse = PlayerDeltaResponse;

/**
 * 购买劳动力请求（CS: BuildingBuyLaborRequest）
 * CS 字段为 costAp/ts，服务端读取 buyCount（以服务端为准）
 */
export interface BuyLaborRequest {
  costAp?: number;
  ts?: number;
  buyCount: number;
}

/** 购买劳动力响应（CS: BuildingBuyLaborResponse） */
export type BuyLaborResponse = PlayerDeltaResponse;

/**
 * 确认留言板奖励请求（CS: BuildingPayloadConfirmMessageBoardRewardRequest，无字段）
 * 服务端未读取请求体
 */
export interface ConfirmMessageBoardRewardRequest {}

/** 确认留言板奖励响应（CS: BuildingPayloadConfirmMessageBoardRewardResponse；服务端仅返回增量） */
export type ConfirmMessageBoardRewardResponse = PlayerDeltaResponse;

/** 获取协助报告请求（CS: BuildingAssistReportRequest，无字段） */
export interface GetAssistReportRequest {}

/** 协助报告条目（CS: BuildingDailyReport；服务端返回空结构） */
export interface BuildingDailyReport {
  ts: number;
  manufacture: { [key: string]: unknown };
  trading: { [key: string]: unknown };
  favor: unknown[];
}

/** 获取协助报告响应（CS: BuildingAssistReportResponse；服务端返回 reports） */
export interface GetAssistReportResponse extends PlayerDeltaResponse {
  reports: BuildingDailyReport[];
}

/** 获取信息共享访客数请求（CS: BuildingMeetingClueGetInfoShareVisitorsRequest，无字段） */
export interface GetInfoShareVisitorsNumRequest {}

/** 获取信息共享访客数响应（CS: BuildingMeetingClueGetInfoShareVisitorsResponse） */
export interface GetInfoShareVisitorsNumResponse extends PlayerDeltaResponse {
  num: number;
}

/** 获取最近访客请求（CS: BuildingGetRecentVisitorsRequest，无字段） */
export interface GetRecentVisitorsRequest {}

/** 访客信息（CS: BuildingGetRecentVisitorsResponse.Visitor；服务端返回空列表） */
export interface RecentVisitor {
  uid: string;
  nickName: string;
  nickNumber: string;
  secretary: string;
  secretarySkinId: string;
  level: number;
  ts: number;
}

/** 获取最近访客响应（CS: BuildingGetRecentVisitorsResponse；服务端返回 visitors） */
export interface GetRecentVisitorsResponse extends PlayerDeltaResponse {
  visitors: RecentVisitor[];
}

/**
 * 获取他人留言板内容请求（CS: BuildingPayloadGetOthersMessageBoardContentRequest）
 * CS 字段为 uid，服务端透传请求体
 */
export interface GetOthersMessageBoardContentRequest {
  uid: string;
}

/** 获取他人留言板内容响应（CS: BuildingPayloadGetOthersMessageBoardContentResponse；服务端仅返回增量） */
export type GetOthersMessageBoardContentResponse = PlayerDeltaResponse;

/**
 * 获取缩略图 URL 请求（CS: BuildingDIYGetPresetThumbnailUrlRequest）
 * CS 字段为 solutionId 列表，服务端透传请求体
 */
export interface GetThumbnailUrlRequest {
  solutionId: number[];
}

/** 获取缩略图 URL 响应（CS: BuildingDIYGetPresetThumbnailUrlResponse；服务端仅返回增量） */
export type GetThumbnailUrlResponse = PlayerDeltaResponse;

/**
 * 发送表情请求（CS: BuildingSendEmojiRequest）
 * CS 字段为 friendId/emoji，服务端透传请求体
 */
export interface SendEmojiRequest {
  friendId: string;
  emoji: string;
}

/** 发送表情响应（CS: BuildingSendEmojiResponse；服务端仅返回增量） */
export type SendEmojiResponse = PlayerDeltaResponse;

/** 开始信息共享请求（CS: BuildingMeetingClueStartInfoShareRequest，无字段） */
export interface StartInfoShareRequest {}

/** 开始信息共享响应（CS: BuildingMeetingClueStartInfoShareResponse；服务端仅返回增量） */
export type StartInfoShareResponse = PlayerDeltaResponse;

/**
 * 访问基建请求（CS: VisitBuildingRequest）
 * CS 字段为 friendId，服务端透传请求体
 */
export interface VisitBuildingRequest {
  friendId: string;
}

/** 访问基建响应（CS: VisitBuildingResponse；服务端仅返回增量） */
export type VisitBuildingResponse = PlayerDeltaResponse;
