/**
 * 矢量突破V2协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.Activity.VecBreakV2 命名空间的
 * VecBreakV2SeasonRecordRequest / VecBreakV2ChangeBuffRequest /
 * VecBreakV2Offense/DefenseStartBattleRequest 等 Request/Response 类；
 * 字段以 CS 类为准，服务端未返回的协议字段标为可选。
 */
import { PlayerSquad, SquadFriendData } from "../character";
import { PlayerDeltaResponse } from "./common";

/** 获取赛季记录请求（CS: VecBreakV2SeasonRecordRequest，无字段） */
export interface VecBreakV2SeasonRecordRequest {}

/** 赛季记录结构（CS: VecBreakV2SeasonAchvInfo） */
export interface VecBreakV2SeasonAchvInfo {
  bestRecord: VecBreakV2SeasonBestRecordInfo;
  stageInfo: { [key: string]: VecBreakV2StageInfo };
}

/** 赛季关卡信息（CS: VecBreakV2StageInfo） */
export interface VecBreakV2StageInfo {
  stageId: string;
  state: number;
}

/** 赛季最佳记录（CS: VecBreakV2SeasonBestRecordInfo） */
export interface VecBreakV2SeasonBestRecordInfo {
  stageId: string;
  buff: string[];
  showTs: number;
  squad: VecBreakV2SeasonRecordCharInfo[];
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
 * 获取赛季记录响应（CS: VecBreakV2SeasonRecordResponse）
 * CS 字段名为 seasons，服务端返回 seasonRecord（当前实现为空对象）
 */
export interface VecBreakV2SeasonRecordResponse extends PlayerDeltaResponse {
  seasonRecord: { [key: string]: VecBreakV2SeasonAchvInfo };
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
 * 战斗结束响应（CS: VecBreakV2Offense/DefenseFinishBattleResponse : DefaultFinishBattleResponse；
 * 服务端仅返回增量）
 */
export type VecBreakV2FinishBattleResponse = PlayerDeltaResponse;

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
