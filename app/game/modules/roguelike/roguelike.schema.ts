/**
 * 老版集成战略（roguelike v1）请求 zod schema
 *
 * 参照 app/game/modules/roguelike/models.ts 中各类 Request 接口，为
 * app/game/modules/roguelike/routes.ts 各端点建立请求格式约束：缺失必填字段 / 类型不符时
 * 由 validateBody 中间件返回 HTTP 4xx。
 *
 * 约定：
 * - createGame/finishGame/giveUpGame/milestoneReward/milestoneRewardTryBest
 *   为 stub（handler 不读 body），用 z.object({})；
 * - upgradeOutBuff 读 theme/id/buffId（兼容 id 与 buffId 两种字段名）。
 */
import { z } from "zod";

/** 创建游戏（stub，handler 不读 body） */
export const roguelikeCreateGameSchema = z.object({});

/** 结束游戏（stub，handler 不读 body） */
export const roguelikeFinishGameSchema = z.object({});

/** 放弃游戏（stub，handler 不读 body） */
export const roguelikeGiveUpGameSchema = z.object({});

/** 里程碑奖励（stub，handler 不读 body） */
export const roguelikeMilestoneRewardSchema = z.object({});

/** 尝试最佳里程碑奖励（stub，handler 不读 body） */
export const roguelikeMilestoneRewardTryBestSchema = z.object({});

/** 升级局外增益（服务端自定义；兼容 id/buffId 字段名，二者取一而非强制同传） */
export const roguelikeUpgradeOutBuffSchema = z.object({
  theme: z.string(),
  // 客户端可能用 id 或 buffId 其一（见 handler 归一化），两字段均标可选以兼容两种调用
  id: z.string().optional(),
  buffId: z.string().optional(),
});