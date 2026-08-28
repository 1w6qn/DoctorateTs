/**
 * 连锁竞技（Act1Lock / Interlock）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.Activity.Act1Lock.Act1LockGetMilestoneRequest 等 Request/Response 类；
 * 服务端当前为 stub 实现（不读取请求体，奖励列表固定返回空），请求类型为空接口。
 */
import { ItemBundle } from "@excel/excel";
import { PlayerDeltaResponse } from "../../kernel/http/common";

/** 获取连锁竞技里程碑奖励请求（CS: Activity.Act1Lock.Act1LockGetMilestoneRequest { activityId, mid }；服务端不读取 body） */
export interface Act1LockGetMilestoneRequest {}

/** 获取连锁竞技里程碑奖励响应（CS: Activity.Act1Lock.Act1LockGetMilestoneRespone；CS items 为 List<ActivityItemModel>，服务端固定返回空 items） */
export interface Act1LockGetMilestoneResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 批量获取连锁竞技里程碑奖励请求（CS: Activity.Act1Lock.Act1LockGetMilestoneBatchRequest { activityId }；服务端不读取 body） */
export interface Act1LockGetMilestoneBatchRequest {}

/** 批量获取连锁竞技里程碑奖励响应（CS: Activity.Act1Lock.Act1LockGetMilestoneBatchRespone；CS items 为 List<ActivityItemModel>，服务端固定返回空 items） */
export interface Act1LockGetMilestoneBatchResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 设置连锁竞技防守请求（CS: Activity.Act1Lock.Act1LockSetDefendRequest { activityId, stageId, isDefend }；服务端不读取 body） */
export interface Act1LockSetDefendRequest {}

/** 设置连锁竞技防守响应（CS: Activity.Act1Lock.Act1LockSetDefendResponse） */
export type Act1LockSetDefendResponse = PlayerDeltaResponse;

/** 设置连锁竞技编队请求（CS: Activity.Act1Lock.Act1LockSetSquadRequest { activityId, stageId, squad: RequestSquadSlot[] }；服务端不读取 body） */
export interface Act1LockSetSquadRequest {}

/** 设置连锁竞技编队响应（CS: Activity.Act1Lock.Act1LockSetSquadResponse） */
export type Act1LockSetSquadResponse = PlayerDeltaResponse;
