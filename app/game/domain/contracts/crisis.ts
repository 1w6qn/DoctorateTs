/**
 * 危机合约协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * CrisisV2 / Crisis / RecalRune 系列 Request/Response 类；字段以 CS 类为准。
 * 老版危机合约 V1 的 Request/Response 在 CS 2.7.61 中已移除，以服务端实现为准；
 * 本服务端部分响应体直接构造 playerDataDelta 对象（非 player.delta 展开）。
 */
import { PlayerCrisisShop, PlayerGoodItemData } from "../playerdata";
import { PlayerDeltaResponse, RoguelikePushMessage } from "./common";

/* ===== 危机合约 V1 请求 ===== */

/** 获取危机合约信息请求（CS 2.7.61 无对应类，老版 V1 协议已移除；服务端不读取 body） */
export interface CrisisGetInfoRequest {}

/** 危机合约V1战斗开始请求（CS 2.7.61 无对应类；服务端仅读取 stageId / rune） */
export interface CrisisV1BattleStartRequest {
  stageId: string;
  rune: string[];
}

/** 危机合约V1战斗结束请求（CS 2.7.61 无对应类；服务端不读取 body） */
export interface CrisisV1BattleFinishRequest {}

/** 获取危机合约V1商品列表请求（CS: CrisisCommonGetShopDataRequest，无字段） */
export interface CrisisGetGoodListRequest {}

/** 购买危机合约V1商品请求（CS: CrisisBuyShopRequest 含 goodId/count/perm；服务端仅读取 goodId/count） */
export interface CrisisBuyGoodsRequest {
  goodId: string;
  count: number;
}

/** 领取挑战奖励-任务请求（服务端自定义，无 CS 对应类） */
export interface CrisisChallengeRewardTaskRequest {
  seasonId: string;
  taskId: string;
}

/** 领取挑战奖励-积分请求（服务端自定义，无 CS 对应类） */
export interface CrisisChallengeRewardPointRequest {
  seasonId: string;
  pointId: string;
}

/** 领取挑战奖励-全部请求（服务端自定义，无 CS 对应类） */
export interface CrisisChallengeRewardAllRequest {
  seasonId: string;
}

/** 获取危机合约所有物品请求（服务端自定义，无 CS 对应类；服务端不读取 body） */
export interface CrisisGetAllItemsRequest {}

/** 解锁地图排名请求（服务端自定义，无 CS 对应类） */
export interface CrisisUnlockMapRankRequest {
  mapId: string;
}

/** 解锁符文请求（服务端自定义，无 CS 对应类） */
export interface CrisisUnlockRuneRequest {
  seasonId: string;
  runeId: string;
}

/* ===== 危机合约 V2 请求 ===== */

/** 获取危机合约V2信息请求（CS: CrisisV2GetInfoRequest，无字段） */
export interface CrisisV2GetInfoRequest {}

/** 危机合约V2战斗开始请求（CS: CrisisV2BattleStartRequest : CrisisStartBattleBaseRequest，含 squad/assistFriend） */
export interface CrisisV2BattleStartRequest {
  mapId: string;
  runeSlots: string[];
}

/** 危机合约V2战斗结束请求（CS: CrisisV2BattleFinishRequest : CommonFinishBattleRequest；服务端不读取 body） */
export interface CrisisV2BattleFinishRequest {}

/** 获取危机合约V2快照请求（CS: CrisisV2GetSnapshotRequest，无字段） */
export interface CrisisV2GetSnapshotRequest {}

/** 获取危机合约V2商品列表请求（CS: CrisisCommonGetShopDataRequest，无字段） */
export interface CrisisV2GetGoodListRequest {}

/** 确认危机合约V2任务请求（服务端自定义，无 CS 对应类；服务端不读取 body） */
export interface CrisisV2ConfirmMissionsRequest {}

/** 危机合约V2购买商品请求（CS: CrisisBuyShopRequest 含 goodId/count/perm；服务端仅读取 goodId/count） */
export interface CrisisV2BuyGoodRequest {
  goodId: string;
  count: number;
}

/* ===== 重构符文请求 ===== */

/** 重构符文战斗开始请求（CS: RecalRuneBattleStartRequest） */
export interface RecalRuneBattleStartRequest {
  seasonId: string;
  stageId: string;
  runes: string[];
  slots: unknown[];
  assistFriend: unknown;
}

/** 重构符文战斗结束请求（CS: RecalRuneBattleFinishRequest : CommonFinishBattleRequest；服务端仅读取 data） */
export interface RecalRuneBattleFinishRequest {
  data?: string;
}

/* ===== 危机合约 V1 响应 ===== */

/**
 * 获取危机合约信息响应（CS 2.7.61 无对应类）
 * data 为服务端从 data/crisis/*.json 加载的赛季数据，结构随文件而定
 */
export interface CrisisGetInfoResponse extends PlayerDeltaResponse {
  ts: number;
  data: unknown;
}

/** 危机合约V1战斗开始响应（服务端自定义，仅返回 battleId/result/sign/signStr 与增量） */
export interface CrisisV1BattleStartResponse extends PlayerDeltaResponse {
  battleId: string;
  result: number;
  sign: string;
  signStr: string;
}

/** 危机合约V1战斗结束响应（服务端自定义，返回 result/score/updateInfo 与增量） */
export interface CrisisV1BattleFinishResponse extends PlayerDeltaResponse {
  result: number;
  score: number;
  updateInfo: {
    point: {
      before: number;
      after: number;
    };
  };
}

/** 获取危机合约V1商品列表响应（CS: CrisisCommonGetShopDataResponse；服务端返回玩家商店数据） */
export interface CrisisGetGoodListResponse extends PlayerDeltaResponse {
  goodList: PlayerGoodItemData[];
  shop: PlayerCrisisShop;
}

/** 购买危机合约V1商品响应（CS: CrisisBuyShopResponse 含 items；服务端返回固定空 items） */
export interface CrisisBuyGoodsResponse extends PlayerDeltaResponse {
  items: unknown[];
}

/** 领取挑战奖励-任务响应（服务端自定义，返回固定空 items） */
export interface CrisisChallengeRewardTaskResponse extends PlayerDeltaResponse {
  items: unknown[];
}

/** 领取挑战奖励-积分响应（服务端自定义，返回固定空 items） */
export interface CrisisChallengeRewardPointResponse extends PlayerDeltaResponse {
  items: unknown[];
}

/** 领取挑战奖励-全部响应（服务端自定义，返回固定空 items） */
export interface CrisisChallengeRewardAllResponse extends PlayerDeltaResponse {
  items: unknown[];
}

/** 获取危机合约所有物品响应（服务端自定义，返回 shop/box 与增量） */
export interface CrisisGetAllItemsResponse extends PlayerDeltaResponse {
  shop: PlayerCrisisShop;
  box: unknown[];
}

/** 解锁地图排名响应（服务端自定义，仅返回增量） */
export type CrisisUnlockMapRankResponse = PlayerDeltaResponse;

/** 解锁符文响应（服务端自定义，仅返回增量） */
export type CrisisUnlockRuneResponse = PlayerDeltaResponse;

/* ===== 危机合约 V2 响应 ===== */

/**
 * 获取危机合约V2信息响应（CS: CrisisV2GetInfoResponse 含 ts/info）
 * info 为服务端从 data/crisisV2/*.json 加载的赛季数据，结构随文件而定
 */
export interface CrisisV2GetInfoResponse extends PlayerDeltaResponse {
  ts: number;
  info: unknown;
}

/** 危机合约V2战斗开始响应（CS: CrisisV2BattleStartResponse : CrisisStartBattleBaseResponse；服务端仅返回 result/battleId） */
export interface CrisisV2BattleStartResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
}

/** 危机合约V2战斗结束响应（CS: CrisisV2BattleFinishResponse : CommonFinishBattleResponse；服务端返回全部结算字段与增量） */
export interface CrisisV2BattleFinishResponse extends PlayerDeltaResponse {
  result: number;
  mapId: string;
  runeSlots: string[];
  runeIds: string[];
  isNewRecord: boolean;
  scoreRecord: number[];
  scoreCurrent: number[];
  runeCount: number[];
  commentNew: unknown[];
  commentOld: unknown[];
  ts: number;
}

/** 获取危机合约V2快照响应（CS: CrisisV2GetSnapshotResponse 含 simpleData/detailData；服务端返回空 detail/simple） */
export interface CrisisV2GetSnapshotResponse extends PlayerDeltaResponse {
  detail: unknown;
  simple: unknown;
}

/** 获取危机合约V2商品列表响应（CS: CrisisCommonGetShopDataResponse；服务端返回玩家商店数据） */
export interface CrisisV2GetGoodListResponse extends PlayerDeltaResponse {
  goodList: PlayerGoodItemData[];
  shop: PlayerCrisisShop;
}

/** 确认危机合约V2任务响应（服务端自定义，返回固定空 pushMessage） */
export interface CrisisV2ConfirmMissionsResponse extends PlayerDeltaResponse {
  pushMessage: RoguelikePushMessage[];
}

/** 危机合约V2购买商品响应（CS: CrisisBuyShopResponse 含 items；服务端返回固定空 items） */
export interface CrisisV2BuyGoodResponse extends PlayerDeltaResponse {
  items: unknown[];
}

/* ===== 重构符文响应 ===== */

/** 重构符文战斗开始响应（CS: RecalRuneBattleStartResponse : CrisisStartBattleBaseResponse；服务端仅返回 result/battleId） */
export interface RecalRuneBattleStartResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
}

/** 重构符文战斗结束响应（CS: RecalRuneBattleFinishResponse : CommonFinishBattleResponse；服务端返回全部结算字段与增量） */
export interface RecalRuneBattleFinishResponse extends PlayerDeltaResponse {
  seasonId: string;
  stageId: string;
  state: number;
  score: number;
  newRecord: boolean;
  runes: string[];
  hp: number;
  ts: number;
}
