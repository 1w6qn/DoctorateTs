/**
 * 关卡（quest）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * SquadFormationRequest / SquadRenameRequest / CommonStartBattleRequest /
 * CommonFinishBattleRequest / SaveBattleReplayRequest / LoadBattleReplayRequest /
 * SpecialStoryStageRewardRequest / UI.Stage.EditStageSixStarTagRequest 等
 * Request/Response 类；字段以 CS 类为准，服务端未返回的协议字段标为可选。
 */
import { ItemBundle } from "@excel/excel";
import { PlayerSquadItem } from "../../kernel/model";
import { CommonStartBattleRequest } from "../../kernel/battle-model";
import { PlayerDeltaResponse } from "../../kernel/http/common";

export { CommonStartBattleRequest };

/** 编队请求（CS: SquadFormationRequest；CS 的 squadId 为 String，服务端契约为 number） */
export interface SquadFormationRequest {
  squadId: number;
  slots: PlayerSquadItem[];
  changeSkill?: number;
}

/** 编队响应（CS: SquadFormationResponse） */
export type SquadFormationResponse = PlayerDeltaResponse;

/** 编队重命名请求（CS: SquadRenameRequest；CS 的 squadId 为 String，服务端契约为 number） */
export interface ChangeSquadNameRequest {
  squadId: number;
  name: string;
}

/** 编队重命名响应（CS: SquadRenameResponse） */
export type ChangeSquadNameResponse = PlayerDeltaResponse;

/**
 * 获取助战列表请求（CS: GetFriendAssistCharListRequest）
 * CS 另有 askRefresh/currSquadId 字段，服务端未读取
 */
export interface GetAssistListRequest {
  profession: string;
  askRefresh?: number;
  currSquadId?: string;
}

/** 获取助战列表响应（服务端返回助战干员信息列表） */
export interface GetAssistListResponse extends PlayerDeltaResponse {
  list: unknown[];
}

/**
 * 战斗开始响应（CS: DefaultStartBattleResponse : CommonStartBattleResponse）
 * 服务端额外返回 AP 保护相关字段
 */
export interface QuestBattleStartResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  apFailReturn: number;
  isApProtect: number;
  inApProtectPeriod: boolean;
  notifyPowerScoreNotEnoughIfFailed: boolean;
}

/**
 * 战斗结算请求（CS: CommonFinishBattleRequest）
 * CS 的 battleData 为 BattleDataInRequest，服务端契约仅读 isCheat/completeTime
 */
export interface QuestBattleFinishRequest {
  data: string;
  battleData: { isCheat: string; completeTime: number };
}

/**
 * 战斗结算响应（CS: DefaultFinishBattleResponse : CommonFinishBattleResponse）
 * 练习模式（isPractice）下服务端仅返回增量，其余结算字段可缺失故全部可选；
 * CS 的 result 字段服务端未返回
 */
export interface QuestBattleFinishResponse extends PlayerDeltaResponse {
  result?: number;
  apFailReturn?: number;
  expScale?: number;
  goldScale?: number;
  rewards?: ItemBundle[];
  firstRewards?: ItemBundle[];
  unlockStages?: string[];
  unusualRewards?: ItemBundle[];
  additionalRewards?: ItemBundle[];
  furnitureRewards?: ItemBundle[];
  alert?: unknown[];
  suggestFriend?: boolean;
  pryResult?: unknown[];
}

/** 获取战斗回放请求（CS: LoadBattleReplayRequest） */
export interface GetBattleReplayRequest {
  stageId: string;
}

/** 获取战斗回放响应（CS: LoadBattleReplayResponse） */
export interface GetBattleReplayResponse extends PlayerDeltaResponse {
  battleReplay: string;
}

/** 保存战斗回放请求（CS: SaveBattleReplayRequest） */
export interface SaveBattleReplayRequest {
  battleId: string;
  battleReplay: string;
}

/**
 * 保存战斗回放响应（CS: SaveBattleReplayResponse）
 * CS 含 result 字段，服务端未返回
 */
export type SaveBattleReplayResponse = PlayerDeltaResponse;

/**
 * 继续战斗请求（服务端自定义，无 CS 对应类）
 * 服务端未读取请求体，返回固定 stub
 */
export interface BattleContinueRequest {}

/** 继续战斗响应（服务端自定义，固定 stub 结构） */
export interface BattleContinueResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  apFailReturn: number;
}

/** 完成剧情关卡请求（CS: SpecialStoryStageRewardRequest） */
export interface FinishStoryStageRequest {
  stageId: string;
}

/** 完成剧情关卡响应（CS: SpecialStoryStageRewardResponse；服务端返回结算结构） */
export interface FinishStoryStageResponse extends PlayerDeltaResponse {
  result: number;
  alert: unknown[];
  rewards: ItemBundle[];
  unlockStages: string[];
}

/** 编辑六星干员标记请求（CS: UI.Stage.EditStageSixStarTagRequest） */
export interface EditStageSixStarTagRequest {
  stageId: string;
  selected: string[];
}

/** 编辑六星干员标记响应（CS: UI.Stage.EditStageSixStarTagResponse） */
export type EditStageSixStarTagResponse = PlayerDeltaResponse;

/* ===== 主线辅助接口（getCowLevelReward/getMainlineRecordRewards/getMainlineCache/unlockStageFog/unlockHideStage）===== */

/** 获取特殊关卡（牛关）奖励请求（CS: SpecialStoryStageRewardRequest） */
export interface GetCowLevelRewardRequest {
  stageId: string;
}

/** 获取特殊关卡奖励响应（CS: SpecialStoryStageRewardResponse） */
export interface GetCowLevelRewardResponse extends PlayerDeltaResponse {
  rewards: ItemBundle[];
}

/** 获取主线记录奖励请求（CS: ZoneRecordRewardRequest { stageId: string[] }） */
export interface GetMainlineRecordRewardsRequest {
  stageId: string[];
}

/** 获取主线记录奖励响应（CS: ZoneRecordRewardResponse { items: List<ItemGet> }；服务端返回空） */
export interface GetMainlineRecordRewardsResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 获取主线缓存请求（CS: GetMainlineCacheRequest，无字段） */
export interface GetMainlineCacheRequest {}

/** 获取主线缓存响应（CS: GetMainlineCacheResponse { items }；服务端返回空） */
export interface GetMainlineCacheResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 解锁关卡迷雾请求（服务端自定义；CS 无请求类） */
export interface UnlockStageFogRequest {
  stageId: string;
}

/** 解锁关卡迷雾响应（CS: UnlockStageFogResponse） */
export type UnlockStageFogResponse = PlayerDeltaResponse;

/** 解锁隐藏关卡请求（服务端自定义；写 dungeon.hideStages[stageId].unlock） */
export interface UnlockHideStageRequest {
  stageId: string;
}

/** 解锁隐藏关卡响应（服务端自定义） */
export type UnlockHideStageResponse = PlayerDeltaResponse;
