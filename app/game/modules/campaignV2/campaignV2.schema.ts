/**
 * 主线战役V2请求 zod schema
 *
 * 参照 app/game/modules/campaignV2/campaignV2.ts 中各类 Request 接口，为
 * app/game/modules/campaignV2/routes.ts 各端点建立请求格式约束：缺失必填字段 / 类型不符时
 * 由 validateBody 中间件返回 HTTP 4xx。
 *
 * 约定：
 * - battleStart 经 battle.start 读取 stageId/squad/usePracticeTicket，squad 复杂对象用 z.json()；
 * - battleFinish 由 handler 判空 data/battleData，两者均必填；
 * - battleSweep/getBreakReward/getExMissionReward 为 stub（handler 不读 body），用 z.object({})。
 */
import { z } from "zod";

/**
 * 主线战役V2战斗开始（CS: CampaignStartBattleRequest : CommonStartBattleRequest）
 * 必填 stageId/squad；其余协议字段服务端容错（battle.start 对缺失字段有默认回退）故可选
 */
export const campaignV2BattleStartSchema = z.object({
  stageId: z.string(),
  // squad 为完整编队对象，仅保证存在，不做深类型校验
  squad: z.json(),
  isRetro: z.number().optional(),
  pray: z.number().optional(),
  battleType: z.number().optional(),
  continuous: z.json().optional(),
  usePracticeTicket: z.number().optional(),
  assistFriend: z.null().optional(),
  isReplay: z.number().optional(),
  startTs: z.number().optional(),
});

/** 主线战役V2战斗结束（CS: CampaignFinishBattleRequest；handler 判空 data/battleData） */
export const campaignV2BattleFinishSchema = z.object({
  data: z.string(),
  // battleData 为客户端完整战报对象，仅保证存在，不做深类型校验
  battleData: z.json(),
});

/**
 * 主线战役V2扫荡（CS: CampaignSweepRequest { stageId, itemId, instId }）
 *
 * 修复（2026-09-09）：原为 z.object({}) → zod 剥掉全部字段，handler 拿不到 stageId，
 * 于是「扫荡」既无法校验记录也无从扣代理指挥卡，变成无条件发合成玉。
 */
export const campaignV2BattleSweepSchema = z.object({
  stageId: z.string(),
  // 代理指挥卡（EXTERMINATION_AGENT）：客户端必带，服务端据此扣券
  itemId: z.string().optional(),
  instId: z.number().optional(),
});

/**
 * 主线战役V2突破奖励（CS: CampaignConfirmBreakRewardRequest { stageId, indexList }）
 *
 * 修复（2026-09-09）：原为 `z.object({})` → 字段被剥掉，handler 拿不到 stageId/indexList
 *（领取永远空转）。indexList 为空表示一键领取全部可领档位。
 */
export const campaignV2GetBreakRewardSchema = z.object({
  stageId: z.string(),
  indexList: z.array(z.number()).optional(),
});

/**
 * 主线战役V2额外任务奖励（CS: CampaignGetCommonMissionRewardRequest { id }）
 *
 * 修复（2026-09-09）：原为 `z.object({})` → 字段被剥掉，handler 拿不到任务 id。
 */
export const campaignV2GetExMissionRewardSchema = z.object({
  id: z.string(),
});