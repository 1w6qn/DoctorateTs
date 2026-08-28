/**
 * 第五周年探索（explore）请求 zod schema
 *
 * 对应协议无独立 protocol 文件，按 router/explore.ts 各 handler 实际读取的
 * req.body 字段定义（参考 CS 2.7.61 中 Torappu.FifthAnnivService 系列请求类）。
 * 供 router 经 validateBody 做运行时校验：缺失必填字段 / 类型不符时返回
 * HTTP 4xx，避免非法 body 传入控制器抛 500。
 *
 * 约定：
 * - 必填字段用对应类型（如 id/groupId/index 等）。
 * - .optional() 表示服务端未读取或可缺省的字段。
 * - 空请求体用 z.object({})。
 */
import { z } from "zod";

/** 领取单个探索任务奖励请求（CS: ExploreClaimSingleMissionRequest { id }） */
export const confirmMissionSchema = z.object({
  id: z.string(),
});

/** 批量领取探索任务奖励请求（CS: ExploreClaimAllMissionRequest { idList }；idList 缺省为空数组） */
export const confirmMissionListSchema = z.object({
  idList: z.array(z.string()).optional(),
});

/** 选择初始探索组请求（CS: ExploreSelectInitGroupRequest { groupId, heritage }；heritage 服务端未读） */
export const selectInitGroupSchema = z.object({
  groupId: z.string(),
  heritage: z.boolean().optional(),
});

/** 事件选项选择请求（CS: ExploreSelectEventOptionRequest { index }） */
export const selectEventChoiceSchema = z.object({
  index: z.number(),
});

/** 目标选项选择请求（CS: ExploreSelectTargetOptionRequest { index }） */
export const selectTargetChoiceSchema = z.object({
  index: z.number(),
});

/** 确认通过目标请求（CS: ExploreConfirmPassTargetRequest，服务端不读取 body） */
export const confirmPassTargetSchema = z.object({});

/** 放弃探索请求（CS: ExploreGiveUpGameRequest，服务端不读取 body） */
export const giveUpGameSchema = z.object({});

/** 探索结算请求（CS: ExploreSettleGameRequest，服务端不读取 body） */
export const settleGameSchema = z.object({});