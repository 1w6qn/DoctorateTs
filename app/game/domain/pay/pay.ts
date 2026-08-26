/**
 * 支付（Pay）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.PayGetUnconfirmedOrderListResponse / PayCreateOrderRequest /
 * PayCreateOrderResponse / PayConfirmOrderRequest / PayConfirmOrderResponse；
 * 服务端实现完整支付流程（订单持久化 data/pay/orders.json，状态机 created→paid→delivered），
 * 支持可配置真实/虚假支付（config.pay.mode）；支付宝/微信扩展端点参考 DoctoratePy pay.py。
 */
import { ItemBundle } from "@excel/character_table";
import { PlayerDeltaResponse } from "../contracts/common";

/** 未确认订单列表请求（CS 无对应请求类，请求体为空） */
export interface PayGetUnconfirmedOrderListRequest {}

/**
 * 未确认订单列表响应（CS: PayGetUnconfirmedOrderListResponse : System.Object { orderIdList }）
 * 服务端额外返回 playerDataDelta，此处以服务端输出为准
 */
export interface PayGetUnconfirmedOrderListResponse extends PlayerDeltaResponse {
  orderIdList: string[];
}

/** 创建订单请求（CS: Torappu.PayCreateOrderRequest） */
export interface PayCreateOrderRequest {
  storeId: number;
  goodId: string;
}

/**
 * 创建订单响应（CS: Torappu.PayCreateOrderResponse : System.Object）
 * extension 为 JSON 字符串（形状对齐抓包 tmp/pay_createOrder_res_1016.json：
 * appCode/amount/productName/extension.appStoreProductId/uid/outOrderId/ts/platform/sign）；
 * 服务端额外返回 playerDataDelta，此处以服务端输出为准
 */
export interface PayCreateOrderResponse extends PlayerDeltaResponse {
  result: number;
  orderId: string;
  extension: string;
  orderIdList?: string[];
  alertMinor: number;
  errMsg?: string;
}

/** 确认订单请求（CS: Torappu.PayConfirmOrderRequest） */
export interface PayConfirmOrderRequest {
  orderId: string;
  enterTs: number;
}

/**
 * 确认订单响应（CS: Torappu.PayConfirmOrderResponse : PlayerDeltaResponse）
 * CS receiveItems 为 { items, checkInItems }（List<RewardItemModel>），
 * 服务端以 ItemBundle[] 返回（同 storyreview 的 CS/服务端差异约定）
 */
export interface PayConfirmOrderResponse extends PlayerDeltaResponse {
  result: number;
  goodId: string;
  receiveItems: {
    items: ItemBundle[];
    checkInItems: ItemBundle[];
  };
}

/** 创建支付宝订单请求（DoctoratePy 兼容：orderId 对应 createOrder 返回的订单号） */
export interface PayCreateOrderAlipayRequest {
  orderId: string;
}

/** 创建支付宝订单响应（qs = 支付宝 page.pay 跳转参数） */
export interface PayCreateOrderAlipayResponse extends PlayerDeltaResponse {
  result: number;
  orderId: string;
  qs: string;
  prcie: number;
  pagePay: unknown;
  returnUrl: string;
}

/** 创建微信订单请求（DoctoratePy 兼容） */
export interface PayCreateOrderWechatRequest {
  orderId: string;
}

/** 创建微信订单响应（requestObj = 微信支付调起参数） */
export interface PayCreateOrderWechatResponse extends PlayerDeltaResponse {
  orderId: string;
  price: number;
  requestObj: {
    appid: string;
    partnerid: string;
    prepayid: string;
    package: string;
    noncestr: string;
    timestamp: number;
    sign: string;
  } | null;
}

/** 支付宝支付确认请求（DoctoratePy 兼容） */
export interface PayConfirmOrderAlipayRequest {
  orderId: string;
}

/** 支付宝支付确认响应 */
export interface PayConfirmOrderAlipayResponse extends PlayerDeltaResponse {
  status: number;
}

/** 微信支付确认请求（DoctoratePy 兼容） */
export interface PayConfirmOrderWechatRequest {
  orderId: string;
}

/** 微信支付确认响应 */
export interface PayConfirmOrderWechatResponse extends PlayerDeltaResponse {
  status: number;
}

/** 支付渠道异步回调请求（real 模式 notify_url；支持 out_trade_no/orderId） */
export interface PayNotifyRequest {
  orderId?: string;
  out_trade_no?: string;
  trade_status?: string;
}

/** 支付渠道异步回调响应 */
export interface PayNotifyResponse {
  result: number;
  errMsg?: string;
}

/** 支付成功页响应（DoctoratePy paySuccess 兼容；H5 支付跳转返回） */
export interface PaySuccessResponse {
  status: number;
  message: string;
}
