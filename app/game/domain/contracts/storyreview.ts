/**
 * 剧情回顾（StoryReview）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * MarkStoryAcceKnownRequest / ReadStoryRequest / UnlockReviewByCoinRequest /
 * StoryReviewRewardRequest / StoryReviewGetTrialRewardRequest 等 Request/Response 类；
 * 字段以 CS 类为准，服务端未返回的协议字段（如 readCount）标为可选。
 */
import { ItemBundle } from "@excel/character_table";
import { PlayerDeltaResponse } from "./common";

/** 标记剧情回顾加速为已知请求（CS: MarkStoryAcceKnownRequest，无字段；服务端不读取 body） */
export interface MarkStoryAcceKnownRequest {}

/** 标记剧情回顾加速为已知响应（CS: MarkStoryAcceKnownResponce，注意 CS 类名拼写为 Responce） */
export type MarkStoryAcceKnownResponse = PlayerDeltaResponse;

/** 阅读剧情回顾请求（CS: ReadStoryRequest） */
export interface ReadStoryRequest {
  storyId: string;
}

/** 阅读剧情回顾响应（CS: ReadStoryResponse { readCount }；服务端省略 readCount） */
export interface ReadStoryResponse extends PlayerDeltaResponse {
  readCount?: number;
}

/** 用硬币解锁剧情回顾请求（CS: UnlockReviewByCoinRequest） */
export interface UnlockStoryByCoinRequest {
  storyId: string;
}

/** 用硬币解锁剧情回顾响应（CS: UnlockReviewByCoinResponse { unlockTs }） */
export interface UnlockStoryByCoinResponse extends PlayerDeltaResponse {
  unlockTs: number;
}

/** 领取剧情回顾分组奖励请求（CS: StoryReviewRewardRequest） */
export interface StoryReviewRewardRequest {
  groupId: string;
}

/** 领取剧情回顾分组奖励响应（CS: StoryReviewRewardResponse；CS items 为 List<RewardItemModel>，服务端返回 ItemBundle[]） */
export interface StoryReviewRewardResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 领取剧情回顾试玩奖励请求（CS: StoryReviewGetTrialRewardRequest） */
export interface StoryReviewGetTrialRewardRequest {
  groupId: string;
  rewardIdList: string[];
}

/** 领取剧情回顾试玩奖励响应（CS: StoryReviewGetTrialRewardResponse；CS items 为 List<RewardItemModel>，服务端返回 ItemBundle[]） */
export interface StoryReviewGetTrialRewardResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}
