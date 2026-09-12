/**
 * 愚人节（act3fun/act4fun/act5fun/act6fun/act7fun）请求 zod schema
 *
 * 参照 app/game/modules/aprilFool/aprilFool.ts 中各类 Request 接口，为
 * app/game/modules/aprilFool/routes.ts 全部端点建立请求格式约束：缺失必填字段 / 类型不符时
 * 由 validateBody 中间件返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 *
 * 约定：
 * - 开始战斗（battleStart）与直播结算（liveSettle）为 stub（handler 不读 body），
 *   用 z.object({})。
 * - 结算端点 handler 仅读 data（解密用），battleData 复杂对象按需用 z.json()。
 */
import { z } from "zod";

/** act5fun 开始战斗（stub，handler 不读 body） */
export const act5funBattleStartSchema = z.object({});

/** act5fun 战斗结算（CS: Act3FunBattleFinishRequest { data, battleData }；handler 双字段判空） */
export const act5funBattleFinishSchema = z.object({
  data: z.string(),
  // battleData 为客户端完整战报对象，仅保证存在，不做深类型校验
  battleData: z.json(),
});

/** act3fun 开始战斗（stub，handler 不读 body） */
export const act3funBattleStartSchema = z.object({});

/** act3fun 战斗结算（handler 仅读 data 解密） */
export const act3funBattleFinishSchema = z.object({
  data: z.string(),
});

/** act4fun 开始战斗（stub，handler 不读 body） */
export const act4funBattleStartSchema = z.object({});

/** act4fun 战斗结算（stub，handler 不读 body） */
export const act4funBattleFinishSchema = z.object({});

/** act4fun 直播结算（stub，handler 不读 body） */
export const act4funLiveSettleSchema = z.object({});

/** act6fun 开始战斗（stub，handler 不读 body） */
export const act6funBattleStartSchema = z.object({});

/** act6fun 战斗结算（handler 仅读 data 解密） */
export const act6funBattleFinishSchema = z.object({
  data: z.string(),
});

/** act7fun 开始战斗（stub，handler 不读 body） */
export const act7funBattleStartSchema = z.object({});

/** act7fun 战斗结算（handler 仅读 data 解密） */
export const act7funBattleFinishSchema = z.object({
  data: z.string(),
});

/** act6fun 领奖（handler 不读 body；兼容 rewardId 可选字段） */
export const act6funRecvRewardSchema = z.object({
  rewardId: z.string().optional(),
});