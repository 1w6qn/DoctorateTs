/**
 * 深海（DeepSea）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.UI.DeepSeaRP.DeepSeaChangeTechBranchRequest / DeepSeaReadEventRequest 等；
 * 字段以 CS 类为准，服务端未读取的字段（如 groupId）标为可选。
 */
import { PlayerDeltaResponse } from "./common";

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
