/**
 * 愚人节（Act3fun）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.Activity.Act3fun.Act3FunBattleStartRequst（CS 类名拼写即如此）/
 * Act3FunBattleStartResponse / Act3FunBattleFinishRequest / Act3FunBattleFinishResponse；
 * 路由路径使用 /act5fun/* 前缀。结算响应为服务端自定义结构，字段以当前服务端输出为准。
 */
import { PlayerDeltaResponse } from "./common";

/** 愚人节战斗开始请求（CS: Activity.Act3fun.Act3FunBattleStartRequst { stageId }；服务端不读取 body） */
export interface Act3FunBattleStartRequest {}

/**
 * 愚人节战斗开始响应（CS: Activity.Act3fun.Act3FunBattleStartResponse : DefaultStartBattleResponse）
 * 服务端 isApProtect 输出 0/1 数值，inApProtectPeriod/notifyPowerScoreNotEnoughIfFailed 输出布尔
 */
export interface Act3FunBattleStartResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  apFailReturn: number;
  isApProtect: number;
  inApProtectPeriod: boolean;
  notifyPowerScoreNotEnoughIfFailed: boolean;
}

/**
 * 愚人节战斗结算请求（CS: Activity.Act3fun.Act3FunBattleFinishRequest : CommonFinishBattleRequest）
 * CS 的 battleData 为 BattleDataInRequest，服务端契约仅读 isCheat/completeTime，此处以服务端为准
 */
export interface Act3FunBattleFinishRequest {
  data: string;
  battleData: { isCheat: string; completeTime: number };
}

/**
 * 愚人节战斗结算响应
 * 服务端自定义结构（与 CS Act3FunBattleFinishResponse : DefaultFinishBattleResponse 不同）
 */
export interface Act3FunBattleFinishResponse extends PlayerDeltaResponse {
  result: number;
  score: number;
  isHighScore: boolean;
  npcResult: { [key: string]: unknown };
  playerResult: Act3FunPlayerResult;
  reward: unknown[];
}

/** 愚人节战斗结算玩家结果（服务端自定义） */
export interface Act3FunPlayerResult {
  totalWin: number;
  streak: number;
  totalRound: number;
}
