/**
 * 深海（DeepSea）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.UI.DeepSeaRP.DeepSeaChangeTechBranchRequest / DeepSeaReadEventRequest 等；
 * 字段以 CS 类为准，服务端未读取的字段（如 groupId）标为可选。
 */
import { PlayerDeltaResponse } from "../../kernel/http/common";

/** 深海科技树分支数据（CS: UI.DeepSeaRP.TechBranchData） */
export interface TechBranchData {
  techTreeId: string;
  branchId: string;
}

/**
 * 切换深海科技树分支请求（CS: UI.DeepSeaRP.DeepSeaChangeTechBranchRequest）
 * CS 另有 groupId 字段，服务端未读取，标为可选
 */
export interface DeepSeaChangeTechBranchRequest {
  groupId?: string;
  branches: TechBranchData[];
}

/** 切换深海科技树分支响应（CS: UI.DeepSeaRP.DeepSeaChangeTechBranchResponse） */
export type DeepSeaChangeTechBranchResponse = PlayerDeltaResponse;

/**
 * 深海事件请求
 * CS: UI.DeepSeaRP.DeepSeaReadEventRequest { groupId/placeId/nodeId/eventId }；
 * 服务端不读取 body（返回空增量）
 */
export interface DeepSeaReadEventRequest {}

/** 深海事件响应（CS: UI.DeepSeaRP.DeepSeaReadEventResponse） */
export type DeepSeaReadEventResponse = PlayerDeltaResponse;

// ---- 2026-08-13 补全：CS Torappu.UI.DeepSeaRP 其余路由类型 ----

/** 发现地点（CS: DeepSeaDiscoverPlaceRequest { groupId, placeId }） */
export interface DeepSeaDiscoverPlaceRequest {
  groupId?: string;
  placeId: string;
}

/** 激活节点（CS: DeepSeaActivateNodeRequest { groupId, placeId }） */
export interface DeepSeaActivateNodeRequest {
  groupId?: string;
  placeId: string;
}

/** 完成剧情（CS: DeepSeaCompleteStoryRequest { groupId, placeId }） */
export interface DeepSeaCompleteStoryRequest {
  groupId?: string;
  placeId: string;
}

/** 开启宝藏（CS: DeepSeaOpenTreasureRequest { groupId, placeId }） */
export interface DeepSeaOpenTreasureRequest {
  groupId?: string;
  placeId: string;
}

/** 解锁科技树节点（CS: DeepSeaUnlockTechTreeRequest { groupId, placeId }） */
export interface DeepSeaUnlockTechTreeRequest {
  groupId?: string;
  placeId: string;
}

/** 选择分支（CS: DeepSeaSelectChoiceRequest { groupId, placeId }） */
export interface DeepSeaSelectChoiceRequest {
  groupId?: string;
  placeId: string;
}

/** 激活科技树（CS: DeepSeaActiveTechTreeRequest { groupId, techTreeId }） */
export interface DeepSeaActiveTechTreeRequest {
  groupId?: string;
  techTreeId: string;
}

/** 通用增量响应（各 deepSea 路由返回 playerDataDelta） */
export type DeepSeaDeltaResponse = PlayerDeltaResponse;
