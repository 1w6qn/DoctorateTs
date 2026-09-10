/**
 * 爬塔（保全派驻）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.UI.ClimbTower 命名空间的
 * ClimbTowerXxxRequest / ClimbTowerXxxResponse 类；字段以 CS 类为准。
 * 协议层 Boolean 按 0/1 数字处理（如 isHard/giveUp），playerData 内的 bool 仍为 boolean。
 */
import { TowerTactical } from "../../kernel/playerdata";
import { PlayerDeltaResponse } from "../../kernel/http/common";

/* ===== 请求类型 ===== */

/** 创建爬塔游戏请求（CS: ClimbTowerCreateGameRequest；CS 中 isHard 为 bool，协议层按 0/1 数字） */
export interface ClimbTowerCreateGameRequest {
  tower: string;
  isHard: number;
}

/** 初始化神卡请求（CS: ClimbTowerInitGodCardRequest） */
export interface ClimbTowerInitGodCardRequest {
  godCardId: string;
}

/**
 * 初始化游戏请求（CS: ClimbTowerInitGameRequest；CS 中 strategy 为 TowerGameStrategy 枚举、
 * tactical 为 TowerTactical，服务端按字符串处理）
 */
export interface ClimbTowerInitGameRequest {
  strategy: string;
  tactical: TowerTactical;
}

/** 爬塔初始卡组槽位（对应 CS RequestSquadSlot 的序列化子集） */
export interface ClimbTowerInitSquadSlot {
  charInstId: number;
  skillIndex?: number;
  currentEquip?: string | null;
}

/** 初始化卡牌请求（CS: ClimbTowerInitSquadRequest，含 slots / assist；服务端仅读取 slots） */
export interface ClimbTowerInitSquadRequest {
  slots: ClimbTowerInitSquadSlot[];
}

/** 爬塔战斗开始请求（CS: ClimbTowerBattleStartRequest，含 stageId / squad；服务端仅读取 stageId） */
export interface ClimbTowerBattleStartRequest {
  stageId: string;
}

/** 爬塔战斗结束请求（CS: ClimbTowerBattleFinishRequest : CommonFinishBattleRequest，含 data；服务端仅读取 data） */
export interface ClimbTowerBattleFinishRequest {
  data: string;
}

/** 爬塔中场招募请求（CS: ClimbTowerHalftimeRecruitRequest，含 groupId/charId/giveUp；CS 中 giveUp 为 bool，协议层按 0/1 数字） */
export interface ClimbTowerHalftimeRecruitRequest {
  charId: string;
  giveUp: number;
}

/** 选择副神卡请求（CS: ClimbTowerRecruitSubGodCardRequest） */
export interface ClimbTowerRecruitSubGodCardRequest {
  subGodCardId: string;
}

/** 爬塔结算请求（CS: ClimbTowerSettleGameRequest，无字段） */
export interface ClimbTowerSettleGameRequest {}

/** 获取层首通奖励请求（CS: ClimbTowerLayerFirstPassRewardRequest，含 tower / layers） */
export interface ClimbTowerLayerFirstPassRewardRequest {
  /** 塔 id（缺省用 tower.current.status.tower） */
  tower?: string;
  /** 目标层（层号 1-based 或关卡 id，混用） */
  layers?: (number | string)[];
  /** 是否困难模式（协议层 0/1） */
  isHard?: number | boolean;
}

/** 获取赛季任务奖励请求（CS: ClimbTowerSeasonMissionAwardRequest，含 missionIds） */
export interface ClimbTowerSeasonMissionAwardRequest {
  /** 目标任务 id（缺省领取全部已达成任务） */
  missionIds?: string[];
}

/** 扫荡游戏请求（CS: ClimbTowerSweepRequest，含 tower / isHard / itemId / instIds） */
export interface ClimbTowerSweepRequest {
  /** 塔 id（缺省用 tower.current.status.tower） */
  tower?: string;
  /** 是否困难模式（协议层 0/1） */
  isHard?: number | boolean;
  /** 扫荡消耗道具（detailConst.sweepCostCount 个） */
  itemId?: string;
  /** 扫荡编队干员 instId */
  instIds?: number[];
}

/* ===== 响应类型 ===== */

/** 创建爬塔游戏响应（CS: ClimbTowerCreateGameResponse） */
export type ClimbTowerCreateGameResponse = PlayerDeltaResponse;

/** 初始化神卡响应（CS: ClimbTowerInitGodCardResponse） */
export type ClimbTowerInitGodCardResponse = PlayerDeltaResponse;

/** 初始化游戏响应（CS: ClimbTowerInitGameResponse） */
export type ClimbTowerInitGameResponse = PlayerDeltaResponse;

/** 初始化卡牌响应（CS: ClimbTowerInitSquadResponse） */
export type ClimbTowerInitSquadResponse = PlayerDeltaResponse;

/** 爬塔战斗开始响应（CS: ClimbTowerBattleStartResponse : DefaultStartBattleResponse；服务端省略协议字段） */
export type ClimbTowerBattleStartResponse = PlayerDeltaResponse;

/** 爬塔战斗掉落信息（CS: ClimbTowerBattleFinishDropInfo；服务端固定返回空数组） */
export interface ClimbTowerBattleFinishDropInfo {
  itemId: string;
  before: number;
  after: number;
  max: number;
}

/** 爬塔战斗陷阱信息（CS: ClimbTowerBattleFinishTrapInfo） */
export interface ClimbTowerBattleFinishTrapInfo {
  id: string;
  alias: string;
}

/**
 * 爬塔战斗结束响应（CS: ClimbTowerBattleFinishResponse : DefaultFinishBattleResponse；
 * 服务端仅返回 drop/isNewRecord/trap）
 */
export interface ClimbTowerBattleFinishResponse extends PlayerDeltaResponse {
  drop: ClimbTowerBattleFinishDropInfo[];
  isNewRecord: boolean;
  trap: ClimbTowerBattleFinishTrapInfo[];
}

/** 爬塔中场招募响应（CS: ClimbTowerHalftimeRecruitResponse） */
export type ClimbTowerHalftimeRecruitResponse = PlayerDeltaResponse;

/** 选择副神卡响应（CS: ClimbTowerRecruitSubGodCardResponse） */
export type ClimbTowerRecruitSubGodCardResponse = PlayerDeltaResponse;

/** 结算奖励项（CS: ClimbTowerBattleFinishResponse.ClimbTowerBattleFinishGameItemDelta 结构） */
export interface ClimbTowerSettleGameItemDelta {
  cnt: number;
  from: number;
  to: number;
}

/**
 * 爬塔结算响应（CS: ClimbTowerSettleGameResponse 含 finishTs；
 * 服务端返回 reward/ts，字段名与 CS 不一致）
 */
export interface ClimbTowerSettleGameResponse extends PlayerDeltaResponse {
  reward: {
    high: ClimbTowerSettleGameItemDelta;
    low: ClimbTowerSettleGameItemDelta;
  };
  ts: number;
}

/** 获取层奖励响应（CS: ClimbTowerLayerFirstPassRewardResponse；服务端返回 202 无响应体） */
export type ClimbTowerLayerFirstPassRewardResponse = PlayerDeltaResponse;

/** 获取赛季任务奖励响应（CS: ClimbTowerSeasonMissionAwardResponse；服务端返回 202 无响应体） */
export type ClimbTowerSeasonMissionAwardResponse = PlayerDeltaResponse;

/** 扫荡游戏响应（CS: ClimbTowerSweepResponse；服务端返回 202 无响应体） */
export type ClimbTowerSweepResponse = PlayerDeltaResponse;
