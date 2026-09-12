/**
 * 符文学徒试炼（rune）请求 zod schema
 *
 * 无独立 protocol/rune.ts 类型文件（协议类型直接定义在 router/rune.ts 内），
 * 此处按 handler 实际读取的 req.body 字段定义：
 * - battleStart 读取 RuneStartBattleRequest（: CommonStartBattleRequest，额外 rune/isPractice）
 * - battleFinish 读取 RuneFinishBattleRequest（data / battleData / battleLog）
 *
 * 供 router/rune.ts 经 validateBody 做运行时校验，避免非法 body 抛 500。
 * 约定：必填字段用对应类型，复杂嵌套对象用 z.json()。
 */

import { z } from "zod";

/**
 * 符文学徒试炼开始战斗请求
 * （CS: RuneStartBattleRequest : CommonStartBattleRequest；squad 为 PlayerSquad 复杂对象）
 */
export const runeStartBattleSchema = z.object({
  isRetro: z.number(),
  pray: z.number(),
  battleType: z.number(),
  continuous: z.object({
    battleTimes: z.number(),
  }),
  usePracticeTicket: z.number(),
  stageId: z.string(),
  // squad 为 PlayerSquad 复杂嵌套对象，仅保证键存在不深检
  squad: z.json(),
  // assistFriend 为 null | SquadFriendData，仅保证键存在不深检
  assistFriend: z.json().nullable(),
  isReplay: z.number(),
  startTs: z.number(),
  // 学徒试炼附加字段（CS: RuneStartBattleRequest 扩展；可省略）
  rune: z.array(z.string()).optional(),
  isPractice: z.boolean().optional(),
});

/** 符文学徒试炼战斗结算请求（CS: RuneFinishBattleRequest） */
export const runeFinishBattleSchema = z.object({
  data: z.string(),
  battleData: z.object({
    isCheat: z.string(),
    completeTime: z.number(),
  }),
  // battleLog 服务端不读，标为可选
  battleLog: z.string().optional(),
});