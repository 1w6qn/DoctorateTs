/**
 * 干员轮换（charRotation）请求 zod schema
 *
 * 对应 protocol/charRotation.ts 中 CharRotationSetCurrentPresetRequest /
 * CharRotationCreatePresetRequest / CharRotationUpdatePresetRequest /
 * CharRotationDeletePresetRequest 等 Request 接口字段，供 router/charRotation.ts
 * 经 validateBody 做运行时校验：缺失必填字段 / 类型不符时返回 HTTP 4xx，
 * 避免非法 body 传入控制器抛 500。
 *
 * 约定：
 * - 必填字段用对应类型（z.string/z.number）
 * - 复杂嵌套对象用 z.any()（如 data 内的 slots），仅保证键存在不深检
 */

import { z } from "zod";

/** 设置当前轮换配置请求（CS: CharRotationSetCurrentPresetRequest） */
export const setCurrentSchema = z.object({
  instId: z.string(),
});

/** 创建轮换预设请求（CS: CharRotationCreatePresetRequest，无字段） */
export const createPresetSchema = z.object({});

/** 删除轮换预设请求（CS: CharRotationDeletePresetRequest） */
export const deletePresetSchema = z.object({
  instId: z.string(),
});

/**
 * 更新轮换预设请求（CS: CharRotationUpdatePresetRequest）
 * flag 为 UpdateFlag 枚举数值；data 内层字段均可选且 slots 为复杂嵌套，仅保证键存在
 */
export const updatePresetSchema = z.object({
  instId: z.string(),
  flag: z.number(),
  // data 内字段全部可选（name/background/homeTheme/secretarySkinId/secretaryCharInstId/slots），
  // slots 为 PlayerCharRotationSlot[] 复杂对象数组，整体用 z.any() 不做深检
  data: z.any(),
});