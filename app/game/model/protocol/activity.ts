/**
 * 活动协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * GetChainLogInRewardRequest / Activity.ActivityConfirmCheckinRequest /
 * Activity.ActivityRewardMilestoneRequest / Activity.Act12side.RecycleCharmsRequest 等
 * Request/Response 类；字段以 CS 类为准，服务端未返回的协议字段标为可选。
 * 部分接口（签到对决/开关活动/活动商店等）无直接 CS 类对应，标注为服务端自定义。
 */
import { ItemBundle } from "@excel/character_table";
import { PlayerDeltaResponse } from "./common";

/* ===== 签到类 ===== */

/** 获取连签登录奖励请求（CS: GetChainLogInRewardRequest） */
export interface GetChainLogInRewardRequest {
  index: number;
}

/**
 * 获取连签登录奖励响应（CS: GetChainLogInRewardResponse）
 * CS 的 reward 为单条 ActivityItemModel，服务端返回 ItemBundle[]
 */
export interface GetChainLogInRewardResponse extends PlayerDeltaResponse {
  reward: ItemBundle[];
}

/** 获取连签最终奖励请求（CS: GetChainLogInFinalRewardsRequest，无字段） */
export interface GetChainLogInFinalRewardsRequest {}

/**
 * 获取连签最终奖励响应（CS: GetChainLogInFinalRewardsResponse）
 * CS 字段名为 rewards，服务端返回 reward（以服务端为准）
 */
export interface GetChainLogInFinalRewardsResponse extends PlayerDeltaResponse {
  reward: ItemBundle[];
}

/** 获取开服签到奖励请求（CS: GetOpenServerCheckInRewardRequest） */
export interface GetOpenServerCheckInRewardRequest {
  index: number;
}

/**
 * 获取开服签到奖励响应（CS: GetOpenServerCheckInRewardResponse）
 * CS 的 reward 为单条 ActivityItemModel，服务端返回 ItemBundle[]
 */
export interface GetOpenServerCheckInRewardResponse extends PlayerDeltaResponse {
  reward: ItemBundle[];
}

/**
 * 获取活动签到奖励请求（CS: Activity.ActivityConfirmCheckinRequest）
 * CS 另有 dynOpt 字段，服务端未读取
 */
export interface GetActivityCheckInRewardRequest {
  index: number;
  activityId: string;
  dynOpt?: string;
}

/** 获取活动签到奖励响应（CS: Activity.ActivityConfirmCheckinResponse） */
export interface GetActivityCheckInRewardResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/**
 * 签到对决活动签到请求（服务端自定义）
 * 参考 CS PlayerActivity.PlayerCheckinVsTypeActivity / VersusCheckInData.TasteInfoData
 * tasteChoice：1=甜，2=咸
 */
export interface ActCheckinvsSignRequest {
  actId: string;
  tasteChoice: number;
}

/** 签到对决活动签到响应（服务端自定义） */
export interface ActCheckinvsSignResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/**
 * 获取开关型活动奖励请求（服务端自定义）
 * 参考 CS PlayerActivity.PlayerSwitchOnlyActivity
 */
export interface GetSwitchOnlyRewardRequest {
  activityId: string;
  reward: string;
}

/** 获取开关型活动奖励响应（服务端自定义；仅增量） */
export type GetSwitchOnlyRewardResponse = PlayerDeltaResponse;

/**
 * 获取签到奖励（通用入口）请求（服务端自定义）
 * 参考 CS PlayerActivity.PlayerCheckinAccessTypeActivity / PlayerBlessOnlyActivity
 */
export interface GetCheckInRewardRequest {
  activityId: string;
}

/** 获取签到奖励（通用入口）响应（服务端自定义） */
export interface GetCheckInRewardResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/**
 * 更换节日干员请求（服务端自定义）
 * 参考 CS PlayerActivity.PlayerBlessOnlyActivity.BlessOnlyFestival
 */
export interface ChangeFestivalCharRequest {
  activityId: string;
  index: number;
  newChar: string;
}

/** 更换节日干员响应（服务端自定义；仅增量） */
export type ChangeFestivalCharResponse = PlayerDeltaResponse;

/* ===== 里程碑 ===== */

/**
 * 领取活动里程碑奖励请求（CS: Activity.ActivityRewardMilestoneRequest）
 * 服务端 milestoneId 可缺省
 */
export interface RewardMilestoneRequest {
  activityId: string;
  milestoneId?: string;
}

/**
 * 领取活动里程碑奖励响应（CS: Activity.ActivityRewardMilestoneResponse）
 * CS 字段名为 items，服务端返回 item（以服务端为准）
 */
export interface RewardMilestoneResponse extends PlayerDeltaResponse {
  item: ItemBundle[];
}

/** 领取所有活动里程碑奖励请求（CS: Activity.ActivityRewardAllMilestoneRequest） */
export interface RewardAllMilestoneRequest {
  activityId: string;
}

/**
 * 领取所有活动里程碑奖励响应（CS: Activity.ActivityRewardAllMilestoneResponse）
 * CS 字段含 milestoneList/items，服务端仅返回 item（以服务端为准）
 */
export interface RewardAllMilestoneResponse extends PlayerDeltaResponse {
  item: ItemBundle[];
}

/* ===== 活动任务 ===== */

/**
 * 确认活动任务并领取奖励请求（CS: Activity.ActivityConfirmMissionRequest）
 * CS 另有 activityId 字段，服务端未读取
 */
export interface ConfirmActivityMissionRequest {
  missionId: string;
  activityId?: string;
}

/**
 * 确认活动任务并领取奖励响应（CS: Activity.ActivityConfirmMissionResponse）
 * CS 字段名为 items，服务端返回 rewards（以服务端为准）
 */
export interface ConfirmActivityMissionResponse extends PlayerDeltaResponse {
  rewards: ItemBundle[];
}

/**
 * 批量确认活动任务请求（CS: ConfirmMissionListRequest）
 * CS 与抓包字段名为 missionIds，服务端读取 missionIdList（以服务端为准）
 */
export interface ConfirmActivityMissionListRequest {
  missionIdList: string[];
  missionIds?: string[];
  activityId?: string;
}

/** 批量确认活动任务响应（服务端自定义，同单任务确认结构） */
export interface ConfirmActivityMissionListResponse extends PlayerDeltaResponse {
  rewards: ItemBundle[];
}

/**
 * 确认活动任务组请求（CS: Activity.ActivityConfirmMissionGroupRequest）
 * CS 字段名为 groupId，服务端读取 missionGroupId（以服务端为准）；CS 另有 activityId
 */
export interface ConfirmActivityMissionGroupRequest {
  missionGroupId: string;
  groupId?: string;
  activityId?: string;
}

/**
 * 确认活动任务组响应（CS: Activity.ActivityConfirmMissionGroupResponse）
 * CS 字段名为 items，服务端返回 rewards（以服务端为准）
 */
export interface ConfirmActivityMissionGroupResponse extends PlayerDeltaResponse {
  rewards: ItemBundle[];
}

/**
 * 自动确认活动任务请求（CS: AutoConfirmMissionsRequest）
 * CS 的 type 为 MissionType 枚举，服务端以字符串读取
 */
export interface AutoConfirmMissionsRequest {
  type: string;
}

/** 自动确认活动任务响应（CS: AutoConfirmMissionsResponse） */
export interface AutoConfirmMissionsResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/* ===== 活动商店 ===== */

/**
 * 兑换活动商店商品请求（服务端自定义）
 * count 缺省时服务端按 1 处理
 */
export interface ExchangeActivityShopItemRequest {
  shopId: string;
  goodId: string;
  count?: number;
}

/** 兑换活动商店商品响应（服务端自定义） */
export interface ExchangeActivityShopItemResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/**
 * 获取活动收集奖励请求（CS: Activity.ActivityGetCollectionRewardRequest）
 * CS 字段为 index，服务端读取 collectionId（以服务端为准）
 */
export interface GetActivityCollectionRewardRequest {
  activityId: string;
  index?: number;
  collectionId?: number;
}

/**
 * 获取活动收集奖励响应（CS: Activity.ActivityGetCollectionRewardResponse）
 * CS 字段名为 items，服务端返回 item（以服务端为准）
 */
export interface GetActivityCollectionRewardResponse extends PlayerDeltaResponse {
  item: ItemBundle[];
}

/** 获取活动商店信息请求（服务端自定义） */
export interface GetActivityShopInfoRequest {
  shopId: string;
}

/** 活动商店信息（服务端 tshop 结构） */
export interface ActivityShopInfo {
  coin: number;
  info: { id: string; count: number }[];
  progressInfo: { [key: string]: unknown };
}

/** 获取活动商店信息响应（服务端自定义） */
export interface GetActivityShopInfoResponse extends PlayerDeltaResponse {
  shopInfo: ActivityShopInfo;
}

/* ===== 信物 ===== */

/**
 * 回收信物请求（CS: Activity.Act12side.RecycleCharmsRequest）
 * CS 字段为 activityId，服务端读取 charmIds（以服务端为准）
 */
export interface RecycleCharmsRequest {
  activityId?: string;
  charmIds?: string[];
}

/**
 * 回收信物响应（CS: Activity.Act12side.RecycleCharmsResponse）
 * CS 字段含 settles/coinGot/items，服务端仅返回 result/recycleNum（以服务端为准）
 */
export interface RecycleCharmsResponse extends PlayerDeltaResponse {
  result: number;
  recycleNum: number;
}

/**
 * 尝试获取信物首通奖励请求（CS: Activity.Act12side.GetCharmFirstRewardRequest）
 * CS 字段为 activityId，服务端读取 charmId（以服务端为准）
 */
export interface TryGetCharmFirstRewardRequest {
  activityId?: string;
  charmId: string;
}

/**
 * 尝试获取信物首通奖励响应（CS: Activity.Act12side.GetCharmFirstRewardResponse）
 * CS 字段含 settles/coinGot，服务端返回 isFirst/reward（以服务端为准）
 */
export interface TryGetCharmFirstRewardResponse extends PlayerDeltaResponse {
  isFirst: boolean;
  reward: ItemBundle[];
}
