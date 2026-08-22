/**
 * 深海（DeepSea）请求 zod schema
 *
 * 对应 protocol/deepsea.ts 的 Request 类型（参考 CS 2.7.61 中的
 * Torappu.UI.DeepSeaRP 命名空间），供 router/deepsea.ts 经 validateBody 做
 * 运行时校验：缺失必填字段 / 类型不符时返回 HTTP 4xx，避免非法 body 传入
 * 控制器抛 500。
 *
 * 约定：
 * - 必填字段用对应类型（如 placeId/techTreeId 等 string）。
 * - .optional() 表示服务端未读取的字段（如 groupId）。
 * - 空请求体用 z.object({})。
 */
import { z } from "zod";

/** 深海科技树分支数据（CS: UI.DeepSeaRP.TechBranchData） */
export const techBranchDataSchema = z.object({
  techTreeId: z.string(),
  branchId: z.string(),
});

/**
 * 切换深海科技树分支请求（CS: DeepSeaChangeTechBranchRequest；groupId 服务端未读）
 */
export const changeTechBranchSchema = z.object({
  groupId: z.string().optional(),
  branches: z.array(techBranchDataSchema),
});

/** 深海事件请求（CS: DeepSeaReadEventRequest，服务端不读取 body） */
export const readEventSchema = z.object({});

/** 发现地点请求（CS: DeepSeaDiscoverPlaceRequest；groupId 服务端未读） */
export const discoverPlaceSchema = z.object({
  groupId: z.string().optional(),
  placeId: z.string(),
});

/** 激活节点请求（CS: DeepSeaActivateNodeRequest；groupId 服务端未读） */
export const activateNodeSchema = z.object({
  groupId: z.string().optional(),
  placeId: z.string(),
});

/** 完成剧情请求（CS: DeepSeaCompleteStoryRequest；groupId 服务端未读） */
export const completeStorySchema = z.object({
  groupId: z.string().optional(),
  placeId: z.string(),
});

/** 开启宝藏请求（CS: DeepSeaOpenTreasureRequest；groupId 服务端未读） */
export const openTreasureSchema = z.object({
  groupId: z.string().optional(),
  placeId: z.string(),
});

/** 解锁科技树节点请求（CS: DeepSeaUnlockTechTreeRequest；groupId 服务端未读） */
export const unlockTechTreeSchema = z.object({
  groupId: z.string().optional(),
  placeId: z.string(),
});

/** 激活科技树请求（CS: DeepSeaActiveTechTreeRequest；groupId 服务端未读） */
export const activeTechTreeSchema = z.object({
  groupId: z.string().optional(),
  techTreeId: z.string(),
});

/** 选择分支请求（CS: DeepSeaSelectChoiceRequest；groupId 服务端未读） */
export const selectChoiceSchema = z.object({
  groupId: z.string().optional(),
  placeId: z.string(),
});