/**
 * 叙拉古人（siracusaMap）请求 zod schema
 *
 * 对应协议无独立 protocol 文件，按 router/siracusaMap.ts 各 handler 实际读取的
 * req.body 字段定义（参考 CS 2.7.61 中 Torappu.UI.SiracusaMap.SiracusaMapService
 * 系列请求类）。供 router 经 validateBody 做运行时校验：缺失必填字段 / 类型
 * 不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 *
 * 约定：
 * - 各请求必含 groupId + 特性 id，其中特性 id 是业务必填字段。
 * - .optional() 表示服务端未读取的字段（groupId/taskId/operaId 等）。
 */
import { z } from "zod";

/** 干员卡选择请求（CS: SiracusaMapCharCardSelectRequest { groupId, cardId }） */
export const cardSelectSchema = z.object({
  groupId: z.string().optional(),
  cardId: z.string(),
});

/** 剧情选项选择请求（CS: SiracusaMapAvgOptionSelectRequest { groupId, taskId, optionId }） */
export const avgOptionSelectSchema = z.object({
  groupId: z.string().optional(),
  taskId: z.string().optional(),
  optionId: z.string(),
});

/** 剧情任务完成请求（CS: SiracusaMapAvgTaskFinishRequest { groupId, taskId }） */
export const avgTaskFinishSchema = z.object({
  groupId: z.string().optional(),
  taskId: z.string(),
});

/** 道具卡获得请求（CS: SiracusaMapAvgItemCardGainRequest { groupId, taskId, itemCardId }） */
export const avgItemCardGainSchema = z.object({
  groupId: z.string().optional(),
  taskId: z.string().optional(),
  itemCardId: z.string(),
});

/** 歌剧评论点赞请求（CS: SiracusaMapOperaCommentLikeRequest { groupId, operaId, commentId }） */
export const operaCommentLikeSchema = z.object({
  groupId: z.string().optional(),
  operaId: z.string().optional(),
  commentId: z.string(),
});

/** 任务环奖励领取请求（CS: SiracusaTaskRingGainRewardRequest { groupId, taskRingId }） */
export const taskRingGainRewardSchema = z.object({
  groupId: z.string().optional(),
  taskRingId: z.string(),
});