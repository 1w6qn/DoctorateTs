/**
 * 剧情回顾（storyreview）请求 zod schema
 *
 * 对应 protocol/storyreview.ts 中 MarkStoryAcceKnownRequest / ReadStoryRequest /
 * UnlockStoryByCoinRequest / StoryReviewRewardRequest / StoryReviewGetTrialRewardRequest
 * 等 Request 接口字段，供 router/storyreview.ts 经 validateBody 做运行时校验：
 * 缺失必填字段 / 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 */

import { z } from "zod";

/** 标记剧情回顾加速为已知请求（CS: MarkStoryAcceKnownRequest，无字段；服务端不读取 body） */
export const markStoryAcceKnownSchema = z.object({});

/** 阅读剧情回顾请求（CS: ReadStoryRequest） */
export const readStorySchema = z.object({
  storyId: z.string(),
});

/** 用硬币解锁剧情回顾请求（CS: UnlockReviewByCoinRequest） */
export const unlockStoryByCoinSchema = z.object({
  storyId: z.string(),
});

/** 领取剧情回顾分组奖励请求（CS: StoryReviewRewardRequest） */
export const rewardGroupSchema = z.object({
  groupId: z.string(),
});

/** 领取剧情回顾试玩奖励请求（CS: StoryReviewGetTrialRewardRequest） */
export const trailRewardSchema = z.object({
  groupId: z.string(),
  rewardIdList: z.array(z.string()),
});