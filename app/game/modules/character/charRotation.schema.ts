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
 * - handler 会读内层字段的 data 按被读字段收紧（passthrough 保留其余协议字段）；
 *   slots 整体透传存储，故仅收紧到「JSON 数组」
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
 * flag 为 UpdateFlag 枚举数值；data 内层字段均可选，按 CharRotationManager#updatePreset
 * 实际读取的字段收紧（slots 作为整体透传存储），passthrough 保留服务端未读的协议字段
 */
export const updatePresetSchema = z.object({
  instId: z.string(),
  flag: z.number(),
  // data 内字段全部可选（name/background/homeTheme/secretarySkinId/secretaryCharInstId/slots），
  // slots 为 PlayerCharRotationSlot[]——服务端整段赋值给 charRotation.preset[].slots，不读元素字段
  data: z
    .object({
      name: z.string().optional(),
      background: z.string().optional(),
      homeTheme: z.string().optional(),
      secretarySkinId: z.string().optional(),
      secretaryCharInstId: z.string().optional(),
      slots: z.array(z.json()).optional(),
    })
    .passthrough(),
});