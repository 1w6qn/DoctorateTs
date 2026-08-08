/**
 * 支付（Pay）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.PayGetUnconfirmedOrderListResponse（CS 无对应请求类，请求体为空）；
 * 私服无真实支付，订单列表固定返回空。
 */
import { PlayerDeltaResponse } from "./common";

/** 未确认订单列表请求（CS 无对应请求类，请求体为空） */
export interface PayGetUnconfirmedOrderListRequest {}

/**
 * 未确认订单列表响应（CS: PayGetUnconfirmedOrderListResponse : System.Object { orderIdList }）
 * 服务端额外返回 playerDataDelta，此处以服务端输出为准
 */
export interface PayGetUnconfirmedOrderListResponse extends PlayerDeltaResponse {
  orderIdList: string[];
}
