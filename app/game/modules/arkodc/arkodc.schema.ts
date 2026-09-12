/**
 * arkodc（act53side「直到大地变成一颗酸橙」ODC 小游戏）请求 zod schema
 *
 * 参照 app/game/modules/arkodc/routes.ts 顶部内联的 ArkOdc*Request 接口，为各端点建立
 * 请求格式约束：缺失必填字段 / 类型不符时由 validateBody 中间件返回 HTTP 4xx。
 *
 * 约定：
 * - topicId 为主要业务字段，多数端点经 isInvalidTopicId 容错（缺失返回业务错误），故可选；
 * - battleStart 必填 topicId（记录供 battleFinish 使用）；
 * - battleFinish 必填 data（解密用），operationId/actorId 可选。
 */
import { z } from "zod";

/** ODC 开始战斗（CS: ArkOdcBattleStartRequest { groupId, topicId, stageId? }） */
export const arkOdcBattleStartSchema = z.object({
  groupId: z.string().optional(),
  topicId: z.string(),
  stageId: z.string().optional(),
});

/** ODC 战斗结算（CS: ArkOdcBattleFinishRequest { data, battleData, operationId?, actorId? }） */
export const arkOdcBattleFinishSchema = z.object({
  data: z.string(),
  // battleData 为客户端完整战报对象，仅保证存在，不做深类型校验
  battleData: z.json(),
  operationId: z.string().optional(),
  actorId: z.string().optional(),
});

/** ODC 保存位置（CS: ArkOdcTaskSavePositionRequest { topicId, x, y, z }） */
export const arkOdcSavePositionSchema = z.object({
  groupId: z.string().optional(),
  topicId: z.string(),
  x: z.number(),
  y: z.number(),
  z: z.number(),
});

/** ODC 触发互动（CS: ArkOdcTriggerActionRequest；字段均可选，缺失时返回业务错误） */
export const arkOdcTriggerActionSchema = z.object({
  groupId: z.string().optional(),
  topicId: z.string().optional(),
  operationId: z.string().optional(),
  actorId: z.string().optional(),
  avgId: z.string().nullable().optional(),
  awardId: z.string().nullable().optional(),
});

/** ODC 重启任务（CS: ArkOdcTaskRestartRequest { groupId?, topicId? }） */
export const arkOdcRestartSchema = z.object({
  groupId: z.string().optional(),
  topicId: z.string().optional(),
});