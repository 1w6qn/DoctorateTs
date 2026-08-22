/**
 * 邮件收藏（mailCollection）请求 zod schema
 *
 * 对应 protocol/mailCollection.ts 的 MailCollectionGetListRequest（无字段），
 * 供 router/mailCollection.ts 经 validateBody 做运行时校验。
 */
import { z } from "zod";

/** 获取邮件收藏列表请求（CS: MailCollectionGetListRequest，无字段） */
export const getListSchema = z.object({});