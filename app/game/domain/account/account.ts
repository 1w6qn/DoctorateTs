/**
 * 账号/登录协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * LoginRequest/LoginResponse、SyncDataRequest/SyncDataResponse 类；
 * syncStatus/syncPushMessage 无独立 CS 类（对应 ServiceCode SYNC_STATUS/SYNC_PUSH_MSG），
 * 按服务端实际输出定义。
 */
import { PlayerDataModel } from "../playerdata";
import { PlayerDeltaResponse } from "../contracts/common";

/** 登录请求（CS: Torappu.LoginRequest；服务端仅读取 token） */
export interface LoginRequest {
  uid: string;
  token: string;
  assetsVersion: string;
  clientVersion: string;
  deviceId: string;
  deviceId2: string;
  deviceId3: string;
  networkVersion: string;
  udtVersion: string;
}

/** 登录响应（CS: Torappu.LoginResponse，非增量响应；失败时仅返回 result） */
export interface LoginResponse {
  result: number;
  uid?: string;
  secret?: string;
  serviceLicenseVersion?: number;
  majorVersion?: string;
}

/** 全量数据同步请求（CS: Torappu.SyncDataRequest；服务端不读取） */
export interface SyncDataRequest {
  /** CS: Torappu.PlatformKey 枚举数值 */
  platform: number;
}

/** 全量数据同步响应（CS: Torappu.SyncDataResponse : PlayerInitResponse） */
export interface SyncDataResponse {
  result: number;
  ts: number;
  /** 玩家全量数据（CS: JObject user，对应 PlayerInitResponse） */
  user: PlayerDataModel;
  playerDataDelta: PlayerDeltaResponse["playerDataDelta"];
}

/** 状态同步请求（CS 无独立类，对应 ServiceCode SYNC_STATUS；服务端不读取） */
export interface SyncStatusRequest {}

/** 状态同步响应（服务端实际输出：ts + 空 result + 增量） */
export interface SyncStatusResponse extends PlayerDeltaResponse {
  ts: number;
  result: {};
}

/** 推送消息同步请求（CS 无独立类，对应 ServiceCode SYNC_PUSH_MSG；服务端不读取） */
export interface SyncPushMessageRequest {}

/** 推送消息同步响应（服务端实际输出：now + next + 增量） */
export interface SyncPushMessageResponse extends PlayerDeltaResponse {
  now: number;
  next: number;
}
