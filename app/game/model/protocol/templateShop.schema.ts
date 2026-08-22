/**
 * 模板商店（TemplateShop）请求 zod schema
 *
 * 对应 protocol/templateShop.ts 的 Request 类型（参考 CS 2.7.61 协议类），
 * 供 router/templateShop.ts 经 validateBody 做运行时校验：缺失必填字段 /
 * 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 */
import { z } from "zod";

/** 获取模板商店商品列表请求（CS: UI.TemplateShop.TemplateGetGoodListRequest { shopId }） */
export const templateGetGoodListSchema = z.object({
  shopId: z.string(),
});

/** 购买模板商店商品请求（CS: UI.TemplateShop.TemplateBuyGoodRequest { shopId, goodId, count }） */
export const templateBuyGoodSchema = z.object({
  shopId: z.string(),
  goodId: z.string(),
  count: z.number(),
});