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
 * - 复杂嵌套对象（tactical/slots 等）用 z.any() 或 z.array(z.any())，仅保证
 *   键存在、结构由 manager 自行处理，避免对客户端完整结构误伤。
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
  tactical: z.any(),
});

/** 初始化卡牌请求（CS: ClimbTowerInitSquadRequest，含 slots/assist；服务端仅读 slots） */
export const initCardSchema = z.object({
  slots: z.array(z.any()),
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

/** 获取层奖励请求（CS: ClimbTowerLayerFirstPassRewardRequest，服务端不读取 body） */
export const layerRewardSchema = z.object({});

/** 获取赛季任务奖励请求（CS: ClimbTowerSeasonMissionAwardRequest，服务端不读取 body；被两个拼写端点复用） */
export const seasonMissionsAwardSchema = z.object({});

/** 扫荡游戏请求（CS: ClimbTowerSweepRequest，服务端不读取 body） */
export const sweepGameSchema = z.object({});