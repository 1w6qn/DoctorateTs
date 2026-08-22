/**
 * 干员基建技能组合（信物小队）请求 zod schema
 *
 * 对应 protocol/charm.ts（复用 home.ts 的 CharmSetSquadRequest { squad: string[] }），
 * 供 router/charm.ts 经 validateBody 做运行时校验。
 */
import { z } from "zod";

/** 设置信物小队请求（CS: Activity.Act12side.UI.CharmSetSquadRequest { squad }） */
export const setSquadSchema = z.object({
  squad: z.array(z.string()),
});