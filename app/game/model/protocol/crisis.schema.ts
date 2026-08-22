/**
 * 危机合约（crisis）请求 zod schema
 *
 * 对应 protocol/crisis.ts 中 Crisis / CrisisV2 / RecalRune 系列 Request 接口字段，
 * 供 router/crisis.ts 经 validateBody 做运行时校验：缺失必填字段 / 类型不符时
 * 返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 *
 * 约定：
 * - 必填字段用对应类型（z.string/z.number/z.array）
 * - 服务端不读取 body 的端点用空对象 z.object({})
 * - 复杂嵌套对象用 z.any()（如 slots / assistFriend），仅保证键存在不深检
 */

import { z } from "zod";

/* ===== 危机合约 V1 请求 ===== */

/** 获取危机合约信息请求（服务端不读取 body） */
export const crisisGetInfoSchema = z.object({});

/** 危机合约V1战斗开始请求（服务端仅读取 stageId / rune） */
export const crisisV1BattleStartSchema = z.object({
  stageId: z.string(),
  rune: z.array(z.string()),
});

/** 危机合约V1战斗结束请求（服务端不读取 body） */
export const crisisV1BattleFinishSchema = z.object({});

/** 获取危机合约V1商品列表请求（服务端不读取 body） */
export const crisisGetGoodListSchema = z.object({});

/** 购买危机合约V1商品请求（服务端仅读取 goodId / count） */
export const crisisBuyGoodsSchema = z.object({
  goodId: z.string(),
  count: z.number(),
});

/** 领取挑战奖励-任务请求（服务端自定义） */
export const crisisChallengeRewardTaskSchema = z.object({
  seasonId: z.string(),
  taskId: z.string(),
});

/** 领取挑战奖励-积分请求（服务端自定义） */
export const crisisChallengeRewardPointSchema = z.object({
  seasonId: z.string(),
  pointId: z.string(),
});

/** 领取挑战奖励-全部请求（服务端自定义） */
export const crisisChallengeRewardAllSchema = z.object({
  seasonId: z.string(),
});

/** 获取危机合约所有物品请求（服务端不读取 body） */
export const crisisGetAllItemsSchema = z.object({});

/** 解锁地图排名请求（服务端自定义） */
export const crisisUnlockMapRankSchema = z.object({
  mapId: z.string(),
});

/** 解锁符文请求（服务端自定义） */
export const crisisUnlockRuneSchema = z.object({
  seasonId: z.string(),
  runeId: z.string(),
});

/* ===== 危机合约 V2 请求 ===== */

/** 获取危机合约V2信息请求（无字段） */
export const crisisV2GetInfoSchema = z.object({});

/** 危机合约V2战斗开始请求（服务端仅读取 mapId / runeSlots） */
export const crisisV2BattleStartSchema = z.object({
  mapId: z.string(),
  runeSlots: z.array(z.string()),
});

/** 危机合约V2战斗结束请求（服务端不读取 body） */
export const crisisV2BattleFinishSchema = z.object({});

/** 获取危机合约V2快照请求（无字段） */
export const crisisV2GetSnapshotSchema = z.object({});

/** 获取危机合约V2商品列表请求（无字段） */
export const crisisV2GetGoodListSchema = z.object({});

/** 确认危机合约V2任务请求（服务端不读取 body） */
export const crisisV2ConfirmMissionsSchema = z.object({});

/** 危机合约V2购买商品请求（服务端仅读取 goodId / count） */
export const crisisV2BuyGoodSchema = z.object({
  goodId: z.string(),
  count: z.number(),
});

/* ===== 重构符文请求 ===== */

/**
 * 重构符文战斗开始请求（CS: RecalRuneBattleStartRequest）
 * slots 为 unknown[]、assistFriend 为 unknown，均用 z.any() 不做深检
 */
export const recalRuneBattleStartSchema = z.object({
  seasonId: z.string(),
  stageId: z.string(),
  runes: z.array(z.string()),
  slots: z.any().optional(),
  assistFriend: z.any().optional(),
});

/** 重构符文战斗结束请求（服务端仅读取可选 data） */
export const recalRuneBattleFinishSchema = z.object({
  data: z.string().optional(),
});