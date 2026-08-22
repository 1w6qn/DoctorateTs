/**
 * 支付（Pay）请求 zod schema
 *
 * 对应 protocol/pay.ts 的 Request 类型（参考 CS 2.7.61 协议类 + DoctoratePy pay.py），
 * 供 router/pay.ts 经 validateBody 做运行时校验。
 */
import { z } from "zod";

/** 未确认订单列表请求（CS 无请求类，请求体为空） */
export const getUnconfirmedOrderListSchema = z.object({});

/** 创建订单请求（CS: PayCreateOrderRequest { storeId, goodId }） */
export const createOrderSchema = z.object({
  storeId: z.number(),
  goodId: z.string(),
});

/** 确认订单请求（CS: PayConfirmOrderRequest { orderId, enterTs }） */
export const confirmOrderSchema = z.object({
  orderId: z.string(),
  enterTs: z.number(),
});

/** 创建支付宝订单请求（DoctoratePy 兼容 { orderId }） */
export const createOrderAlipaySchema = z.object({
  orderId: z.string(),
});

/** 创建微信订单请求（DoctoratePy 兼容 { orderId }） */
export const createOrderWechatSchema = z.object({
  orderId: z.string(),
});

/** 支付宝支付确认请求（DoctoratePy 兼容 { orderId }） */
export const confirmOrderAlipaySchema = z.object({
  orderId: z.string(),
});

/** 微信支付确认请求（DoctoratePy 兼容 { orderId }） */
export const confirmOrderWechatSchema = z.object({
  orderId: z.string(),
});

/** 支付渠道异步回调请求（real 模式 notify_url，支持 out_trade_no/orderId/trade_status） */
export const notifySchema = z.object({
  orderId: z.string().optional(),
  out_trade_no: z.string().optional(),
  trade_status: z.string().optional(),
});