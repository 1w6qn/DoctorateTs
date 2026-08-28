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
 * - 复杂嵌套对象（squad/squadSlots 等）用 z.any()，仅保证键存在。
 * - 服务端不读取 body 的端点用 z.object({})。
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
  squad: z.any(),
});

/** 防守战斗结束请求（CS: VecBreakV2DefenseFinishBattleRequest，服务端不读取 body） */
export const defendBattleFinishSchema = z.object({});

/** 设置防守请求（CS: VecBreakV2SetDefendRequest；squadSlots 为复杂嵌套数组） */
export const setDefendSchema = z.object({
  activityId: z.string(),
  stageId: z.string(),
  squadSlots: z.any(),
});

/** 进攻战斗开始请求（CS: VecBreakV2OffenseStartBattleRequest，服务端不读取 body） */
export const battleStartSchema = z.object({});

/** 进攻战斗结束请求（CS: VecBreakV2OffenseFinishBattleRequest，服务端不读取 body） */
export const battleFinishSchema = z.object({});