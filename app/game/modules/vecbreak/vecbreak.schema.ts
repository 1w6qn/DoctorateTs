/**
 * 矢量突破V2请求 zod schema
 *
 * 对应 protocol/vecbreak.ts 的 Request 类型（参考 CS 2.7.61 中
 * Torappu.Activity.VecBreakV2 命名空间），供 router/vecbreak.ts 经 validateBody
 * 做运行时校验：缺失必填字段 / 类型不符时返回 HTTP 4xx，避免非法 body 传入
 * 控制器抛 500。
 *
 * 约定：
 * - 必填字段（activityId/stageId 等）用对应类型。
 * - 整包转发给 battle.start 的复杂嵌套对象（squad/assistFriend）用 z.json() 透传；
 *   squadSlots/battleData 服务端不读内层字段，同样透传（battleData 可选）。
 * - 服务端不读取 body 的端点用 z.object({})。
 *
 * 修复（2026-09-09）：进攻链路三处原为 `z.object({})`，zod 会静默剥掉全部字段——
 * `battleStart` 拿不到 stageId/squad（无法复用标准战斗开始），`battleFinish` 拿不到 data/battleData
 * （无法结算），此处按 CS 类型补齐（与 campaignV2/act1vhalfidle 同类缺陷）。
 */
import { z } from "zod";

/** 获取赛季记录请求（CS: VecBreakV2SeasonRecordRequest，无字段） */
export const getSeasonRecordSchema = z.object({});

/** 更换增益列表请求（CS: VecBreakV2ChangeBuffRequest；服务端读 activityId + buffList） */
export const changeBuffListSchema = z.object({
  activityId: z.string(),
  buffList: z.array(z.string()),
});

/** 防守战斗开始请求（CS: VecBreakV2DefenseStartBattleRequest；squad 为复杂嵌套对象） */
export const defendBattleStartSchema = z.object({
  activityId: z.string(),
  stageId: z.string(),
  squad: z.json(),
});

/** 防守战斗结束请求（CS: VecBreakV2DefenseFinishBattleRequest : CommonFinishBattleRequest） */
export const defendBattleFinishSchema = z.object({
  data: z.string().optional(),
  battleData: z.json().optional(),
});

/** 设置防守请求（CS: VecBreakV2SetDefendRequest；squadSlots 为复杂嵌套数组） */
export const setDefendSchema = z.object({
  activityId: z.string(),
  stageId: z.string(),
  squadSlots: z.json(),
});

/** 进攻战斗开始请求（CS: VecBreakV2OffenseStartBattleRequest : DefaultStartBattleRequest + activityId） */
export const battleStartSchema = z.object({
  activityId: z.string().optional(),
  stageId: z.string(),
  squad: z.json().optional(),
  assistFriend: z.json().optional(),
  usePracticeTicket: z.number().optional(),
});

/** 进攻战斗结束请求（CS: VecBreakV2OffenseFinishBattleRequest : CommonFinishBattleRequest） */
export const battleFinishSchema = z.object({
  data: z.string().optional(),
  battleData: z.json().optional(),
});
