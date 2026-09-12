/**
 * 矢量突破V2协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.Activity.VecBreakV2 命名空间的
 * VecBreakV2SeasonRecordRequest / VecBreakV2ChangeBuffRequest /
 * VecBreakV2Offense/DefenseStartBattleRequest 等 Request/Response 类；
 * 字段以 CS 类为准，服务端未返回的协议字段标为可选。
 */
import { PlayerSquad, SquadFriendData } from "../../kernel/model";
import { PlayerDeltaResponse } from "../../kernel/http/common";
import type { ServerPayload } from "@excel/json-value";
import type { PlayerActivity } from "../../kernel/playerdata";

/**
 * VEC_BREAK_V2 活动存档（draft.activity.VEC_BREAK_V2[actId]）
 *
 * 形状登记在 scripts/playerdata-server-adapt.ts 的 SERVER_OVERRIDE_FIELDS
 * （生成类型 PlayerActivity.VEC_BREAK_V2 的条目即本别名），访问点不再需要 cast。
 */
export type VecBreakV2PlayerData = NonNullable<NonNullable<PlayerActivity["VEC_BREAK_V2"]>[string]>;

/** 获取赛季记录请求（CS: VecBreakV2SeasonRecordRequest，无字段） */
export interface VecBreakV2SeasonRecordRequest {}

/** 赛季记录结构（CS: VecBreakV2SeasonAchvInfo） */
export interface VecBreakV2SeasonAchvInfo {
  bestRecord: VecBreakV2SeasonBestRecordInfo;
  stageInfo: { [key: string]: VecBreakV2StageInfo };
}

/** 赛季关卡信息（CS: VecBreakV2StageInfo；参考 ODPY 用字符串状态 "COMPLETE"） */
export interface VecBreakV2StageInfo {
  stageId: string;
  state: number | string;
}

/** 赛季最佳记录（CS: VecBreakV2SeasonBestRecordInfo） */
export interface VecBreakV2SeasonBestRecordInfo {
  stageId: string;
  buff: string[];
  showTs: number;
  /**
   * 驻防编队：服务端原样透传存档 `activity.VEC_BREAK_V2[actId].squads`。
   * 该字段不在客户端模型（PlayerVecBreakV2）里、服务端只读不写，故按未建模载荷
   * （ServerPayload[]）声明——见 scripts/playerdata-server-adapt.ts 的 VEC_BREAK_V2 条目。
   */
  squad: VecBreakV2SeasonRecordCharInfo[] | ServerPayload[];
  assistChar: VecBreakV2SeasonRecordCharInfo;
}

/** 赛季记录干员信息（CS: VecBreakV2SeasonRecordCharInfo） */
export interface VecBreakV2SeasonRecordCharInfo {
  charId: string;
  currentTmpl: string;
  potentialRank: number;
  level: number;
  mainSkillLvl: number;
  evolvePhase: number;
  skin: string;
  skill: { skillIndex: number; specializeLevel: number };
  equip: { id: string; level: number };
}

/**
 * 获取赛季记录响应（CS: VecBreakV2SeasonRecordResponse { seasons }）
 * 字段名为 seasons（对齐 CS 与 ODPY），structure 与 seasonRecord 一致
 */
export interface VecBreakV2SeasonRecordResponse extends PlayerDeltaResponse {
  seasons: { [key: string]: VecBreakV2SeasonAchvInfo };
}

/** 更换增益列表请求（CS: VecBreakV2ChangeBuffRequest；服务端未读取请求体） */
export interface VecBreakV2ChangeBuffRequest {
  activityId: string;
  buffList: string[];
}

/** 更换增益列表响应（CS: VecBreakV2ChangeBuffResponse） */
export type VecBreakV2ChangeBuffResponse = PlayerDeltaResponse;

/** 防守战斗开始请求（CS: VecBreakV2DefenseStartBattleRequest） */
export interface VecBreakV2DefenseStartBattleRequest {
  activityId: string;
  stageId: string;
  squad: PlayerSquad;
}

/** 进攻战斗开始请求（CS: VecBreakV2OffenseStartBattleRequest） */
export interface VecBreakV2OffenseStartBattleRequest {
  activityId: string;
  stageId: string;
  squad: PlayerSquad;
  assistFriend: SquadFriendData;
}

/**
 * 战斗开始响应（CS: VecBreakV2Offense/DefenseStartBattleResponse : CommonStartBattleResponse）
 * CS 基类含 result/battleId，服务端仅返回这两项
 */
export interface VecBreakV2StartBattleResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
}

/**
 * 战斗结束请求（CS: VecBreakV2Offense/DefenseFinishBattleRequest : CommonFinishBattleRequest；
 * 服务端未读取请求体）
 */
export interface VecBreakV2FinishBattleRequest {
  data: string;
  battleData: { isCheat: string; completeTime: number };
}

/**
 * 战斗结束响应（CS: VecBreakV2Offense/DefenseFinishBattleResponse : DefaultFinishBattleResponse）
 * 参考 ODPY：返回 result/msBefore/msAfter/finTs 等
 */
export interface VecBreakV2FinishBattleResponse extends PlayerDeltaResponse {
  result: number;
  apFailReturn: number;
  goldScale: number;
  expScale: number;
  suggestFriend: boolean;
  msBefore: number;
  msAfter: number;
  finTs: number;
}

/** 防守编队槽位（CS: VecBreakV2DefendSlot） */
export interface VecBreakV2DefendSlot {
  charInstId: number;
  currentTmpl: string;
}

/** 设置防守请求（CS: VecBreakV2SetDefendRequest；服务端未读取请求体） */
export interface VecBreakV2SetDefendRequest {
  activityId: string;
  stageId: string;
  squadSlots: VecBreakV2DefendSlot[];
}

/** 设置防守响应（CS: VecBreakV2SetDefendResponse） */
export type VecBreakV2SetDefendResponse = PlayerDeltaResponse;
