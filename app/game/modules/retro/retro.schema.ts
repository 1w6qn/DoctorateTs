/**
 * 复刻/插曲（Retro）请求体 zod schema
 *
 * 参照反编译 CS（com.hypergryph.arknights_2.7.61.cs "Torappu" 命名空间下
 * RetroUnlockRetroBlockRequest / RetroTrailRewardRequest / RetroGetPassRewardRequest，
 * 以及 Torappu.Activity.Act20side.RetroCarCompetitionStart/Finish Request 类）协议类
 * 字段定义，为 app/game/modules/retro/routes.ts 全部端点建立请求格式约束：缺失必填字段 /
 * 类型不符时由 validateBody 中间件返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 *
 * 约定：战车竞速 start/finish 请求服务端不读 body，对应 CS 请求类为空结构，故用空对象。
 */
import { z } from "zod";

/** 解锁复刻区块请求（CS: RetroUnlockRetroBlockRequest { retroId }） */
export const unlockRetroBlockSchema = z.object({
  retroId: z.string(),
});

/** 获取复刻轨迹奖励请求（CS: RetroTrailRewardRequest { retroId, rewardId }） */
export const getRetroTrailRewardSchema = z.object({
  retroId: z.string(),
  rewardId: z.string(),
});

/** 获取复刻通行证奖励请求（CS: RetroGetPassRewardRequest { retroId, activityId }） */
export const getRetroPassRewardSchema = z.object({
  retroId: z.string(),
  activityId: z.string(),
});

/** 复刻战车竞速开始请求（CS: Activity.Act20side.RetroCarCompetitionStartRequest；服务端不读 body） */
export const competitionStartSchema = z.object({});

/** 复刻战车竞速结算请求（CS: Activity.Act20side.RetroCarCompetitionFinishRequest；服务端不读 body） */
export const competitionFinishSchema = z.object({});