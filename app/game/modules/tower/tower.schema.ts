/**
 * 爬塔（保全派驻）请求 zod schema
 *
 * 对应 protocol/tower.ts 的 Request 类型（参考 CS 2.7.61 中
 * Torappu.UI.ClimbTower 命名空间），供 router/tower.ts 经 validateBody 做运行时
 * 校验：缺失必填字段 / 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器
 * 抛 500。
 *
 * 约定：
 * - 协议层 Boolean 按 0/1 数字处理（如 isHard/giveUp）。
 * - 整包存储/转发的复杂嵌套对象（tactical）用 z.json()；handler 会读内层字段的
 *   （slots 的 charInstId/skillIndex/currentEquip）按被读字段收紧，passthrough 保留其余字段。
 * - 空请求体用 z.object({})。
 */
import { z } from "zod";

/** 创建爬塔游戏请求（CS: ClimbTowerCreateGameRequest；isHard 协议层为 0/1 数字） */
export const createGameSchema = z.object({
  tower: z.string(),
  isHard: z.number(),
});

/** 初始化神卡请求（CS: ClimbTowerInitGodCardRequest） */
export const initGodCardSchema = z.object({
  godCardId: z.string(),
});

/** 初始化游戏请求（CS: ClimbTowerInitGameRequest；tactical 为复杂嵌套对象） */
export const initGameSchema = z.object({
  strategy: z.string(),
  tactical: z.json(),
});

/**
 * 初始化卡牌请求（CS: ClimbTowerInitSquadRequest，含 slots/assist；服务端仅读 slots）
 *
 * slots 每项按 handler（tower/routes.ts#initCard）实际读取的字段收紧：
 * `charInstId`（查 troop.chars）、`skillIndex`/`currentEquip`（缺省由干员数据兜底）。
 * 非空校验仍留在 handler（空数组返回 result:1 业务错误，不能由 schema 提前 422）。
 */
export const initCardSchema = z.object({
  slots: z.array(
    z.object({
      charInstId: z.number(),
      skillIndex: z.number().optional(),
      currentEquip: z.string().nullable().optional(),
    }).passthrough(),
  ),
});

/** 爬塔战斗开始请求（CS: ClimbTowerBattleStartRequest，服务端仅读 stageId） */
export const battleStartSchema = z.object({
  stageId: z.string(),
});

/** 爬塔战斗结束请求（CS: ClimbTowerBattleFinishRequest，服务端仅读 data） */
export const battleFinishSchema = z.object({
  data: z.string(),
});

/** 爬塔中场招募请求（CS: ClimbTowerHalftimeRecruitRequest；giveUp 协议层为 0/1 数字） */
export const recruitSchema = z.object({
  charId: z.string(),
  giveUp: z.number(),
});

/** 选择副神卡请求（CS: ClimbTowerRecruitSubGodCardRequest） */
export const chooseSubGodCardSchema = z.object({
  subGodCardId: z.string(),
});

/** 爬塔结算请求（CS: ClimbTowerSettleGameRequest，无字段） */
export const settleGameSchema = z.object({});

/**
 * 获取层首通奖励请求（CS: ClimbTowerLayerFirstPassRewardRequest）
 *
 * 修复（2026-09-09）：原为 `z.object({})` —— zod 会静默剥掉 tower/layers，
 * handler 永远拿不到请求内容（与 campaignV2/act1vhalfidle 同类缺陷）。
 */
export const layerRewardSchema = z.object({
  tower: z.string().optional(),
  layers: z.array(z.json()).optional(),
  isHard: z.union([z.number(), z.boolean()]).optional(),
});

/** 获取赛季任务奖励请求（CS: ClimbTowerSeasonMissionAwardRequest；被两个拼写端点复用） */
export const seasonMissionsAwardSchema = z.object({
  missionIds: z.array(z.string()).optional(),
});

/** 扫荡游戏请求（CS: ClimbTowerSweepRequest） */
export const sweepGameSchema = z.object({
  tower: z.string().optional(),
  isHard: z.union([z.number(), z.boolean()]).optional(),
  itemId: z.string().optional(),
  instIds: z.array(z.number()).optional(),
});