/**
 * 自走棋（AutoChess，卫戍协议）请求 zod schema
 *
 * 字段对应 CS 2.7.61 的 Request 类（见 autochess.protocol.ts）；
 * 战斗结束类请求的 data/battleData 为加密战斗数据与战斗日志，服务端不深入解析，
 * 故按可选字段放行（与 bossRush/enemyDuel 的 finish schema 一致）。
 */
import { z } from "zod";

/** 部署项（CS: Deploy { skillIndex, currentEquip }） */
const deploySchema = z.object({
  skillIndex: z.number().int().default(1),
  currentEquip: z.string().nullable().optional(),
});

/** 自定义干员部署项（CS: DiyCharDeploy，额外 diyChar/origChessId） */
const diyCharDeploySchema = deploySchema.extend({
  diyChar: z.string().nullable().optional(),
  origChessId: z.string().nullable().optional(),
});

/** 同步赛季信息（CS: ActAutoChessSyncInfoRequest { actId }） */
export const autoChessSyncInfoSchema = z.object({
  actId: z.string(),
});

/** 设置棋池部署（CS: AutoChessSetChessPoolDeployRequest { actId, chessPool }） */
export const autoChessSetChessPoolDeploySchema = z.object({
  actId: z.string(),
  chessPool: z.record(z.string(), deploySchema),
});

/** 设置棋池自定干员（CS: AutoChessSetChessPoolDiyCharRequest { actId, diyChessPool }） */
export const autoChessSetChessPoolDiyCharSchema = z.object({
  actId: z.string(),
  diyChessPool: z.record(z.string(), diyCharDeploySchema),
});

/** 移除棋池角色（CS: AutoChessRemoveChessPoolCharRequest { actId, chessId }） */
export const autoChessRemoveChessPoolCharSchema = z.object({
  actId: z.string(),
  chessId: z.string(),
});

/** 设置棋池助战（CS: AutoChessSetFriendAssistRequest { actId, assistChessId, assistUid }） */
export const autoChessSetChessPoolAssistSchema = z.object({
  actId: z.string(),
  assistChessId: z.string(),
  assistUid: z.string(),
});

/** 获取好友助战列表（CS: AutoChessGetFriendAssistListRequest { actId, charId }） */
export const autoChessGetFriendAssistListSchema = z.object({
  actId: z.string(),
  charId: z.string(),
});

/** 创建队伍（CS: AutoChessCreateTeamRequest { activityId, modeId, matchOpt, matchFlag }） */
export const autoChessCreateTeamSchema = z.object({
  activityId: z.string(),
  modeId: z.string(),
  matchOpt: z.number().int().optional().default(0),
  matchFlag: z.boolean().optional().default(false),
});

/** 加入队伍（CS: AutoChessJoinTeamRequest { activityId, teamId }） */
export const autoChessJoinTeamSchema = z.object({
  activityId: z.string(),
  teamId: z.string(),
});

/** 开始匹配（CS: AutoChessStartMatchRequest { activityId, option }） */
export const autoChessStartMatchSchema = z.object({
  activityId: z.string(),
  option: z
    .object({
      mode: z.string(),
      matchType: z.number().int().optional().default(0),
    })
    .nullable()
    .optional(),
});

/** 查询匹配（CS: AutoChessQueryMatchRequest { activityId, needLeave }） */
export const autoChessQueryMatchSchema = z.object({
  activityId: z.string(),
  needLeave: z.number().int().optional().default(0),
});

/** 多人战斗开始（CS: AutoChessMultiBattleStartRequest { activityId, sceneId }） */
export const autoChessMultiBattleStartSchema = z.object({
  activityId: z.string(),
  sceneId: z.string(),
});

/** 引导战斗开始（CS: AutoChessTrainingBattleStartRequest { activityId, stageId }） */
export const autoChessTrainingBattleStartSchema = z.object({
  activityId: z.string(),
  stageId: z.string(),
});

/** 引导战斗结束（CS: AutoChessTrainingBattleFinishRequest : CommonFinishBattleRequest + activityId） */
export const autoChessTrainingBattleFinishSchema = z.object({
  activityId: z.string(),
  data: z.string().optional(),
  battleData: z.unknown().optional(),
});

/** 多人战斗结束（CS: AutoChessMultiBattleFinishRequest : CommonFinishBattleRequest + activityId/sceneId） */
export const autoChessMultiBattleFinishSchema = z.object({
  activityId: z.string(),
  sceneId: z.string(),
  data: z.string().optional(),
  battleData: z.unknown().optional(),
});

/** 退出单机游戏（CS: AutoChessQuitSingleGameRequest { activityId, sceneId }） */
export const autoChessQuitSingleGameSchema = z.object({
  activityId: z.string(),
  sceneId: z.string(),
});

/** 结算游戏（CS: AutoChessSettleGameRequest { activityId, quitBattle }） */
export const autoChessSettleGameSchema = z.object({
  activityId: z.string(),
  quitBattle: z.boolean().optional().default(false),
});

/** 结算点赞（CS: AutoChessSettleLikeRequest { activityId, uid }） */
export const autoChessSettleLikeSchema = z.object({
  activityId: z.string(),
  uid: z.string(),
});

/** 上报战斗结果（服务端自定义，宽松透传） */
export const autoChessReportSchema = z.object({}).passthrough();

/** 赛季入口兜底（/act1autochess、/act2autochess） */
export const autoChessSeasonEntrySchema = z.object({}).passthrough();
