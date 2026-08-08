/**
 * 任务协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * ConfirmMission/ConfirmMissionGroup/AutoConfirmMissions/ExchangeMissionRewards 系列类。
 */
import { ItemBundle } from "@excel/character_table";
import { PlayerDeltaResponse } from "./common";

/** 确认单个任务请求（CS: ConfirmMissionRequest） */
export interface ConfirmMissionRequest {
  missionId: string;
}

/** 确认单个任务响应（CS: ConfirmMissionResponse；服务端额外返回 items） */
export interface ConfirmMissionResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 确认任务组请求（CS: ConfirmMissionGroupRequest） */
export interface ConfirmMissionGroupRequest {
  missionGroupId: string;
}

/** 任务组奖励（CS: MissionGroupRewards） */
export interface MissionGroupRewards {
  id: string;
  items: ItemBundle[];
}

/** 确认任务组响应（CS: ConfirmMissionGroupResponse；服务端不返回 items） */
export interface ConfirmMissionGroupResponse extends PlayerDeltaResponse {
  items?: MissionGroupRewards[];
}

/** 自动确认任务请求（CS: AutoConfirmMissionsRequest；服务端读取 type） */
export interface AutoConfirmMissionsRequest {
  type: string;
}

/** 自动确认任务响应（CS: AutoConfirmMissionsResponse） */
export interface AutoConfirmMissionsResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 兑换任务奖励请求（CS: ExchangeMissionRewardsRequest） */
export interface ExchangeMissionRewardsRequest {
  targetRewardsId: string;
}

/** 兑换任务奖励响应（CS: ExchangeMissionRewardsResponse） */
export type ExchangeMissionRewardsResponse = PlayerDeltaResponse;
