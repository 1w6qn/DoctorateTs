/**
 * 主线战役V2请求 zod schema
 *
 * 参照 app/game/model/protocol/campaignV2.ts 中各类 Request 接口，为
 * app/game/router/campaignV2.ts 各端点建立请求格式约束：缺失必填字段 / 类型不符时
 * 由 validateBody 中间件返回 HTTP 4xx。
 *
 * 约定：
 * - battleStart 经 battle.start 读取 stageId/squad/usePracticeTicket，squad 复杂对象用 z.any()；
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
  squad: z.any(),
  isRetro: z.number().optional(),
  pray: z.number().optional(),
  battleType: z.number().optional(),
  continuous: z.any().optional(),
  usePracticeTicket: z.number().optional(),
  assistFriend: z.null().optional(),
  isReplay: z.number().optional(),
  startTs: z.number().optional(),
});

/** 主线战役V2战斗结束（CS: CampaignFinishBattleRequest；handler 判空 data/battleData） */
export const campaignV2BattleFinishSchema = z.object({
  data: z.string(),
  // battleData 为客户端完整战报对象，仅保证存在，不做深类型校验
  battleData: z.any(),
});

/** 主线战役V2扫荡（stub，handler 不读 body） */
export const campaignV2BattleSweepSchema = z.object({});

/** 主线战役V2突破奖励（stub，handler 不读 body） */
export const campaignV2GetBreakRewardSchema = z.object({});

/** 主线战役V2额外任务奖励（stub，handler 不读 body） */
export const campaignV2GetExMissionRewardSchema = z.object({});