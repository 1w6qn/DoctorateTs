/**
 * 首页（home）请求 zod schema
 *
 * 对应 protocol/home.ts 的 Request 类型（参考 CS 2.7.61 协议类），以及
 * protocol/charRotation.ts 中 home 路由引用的干员轮换 Request 类型。
 * 供 router/home.ts 经 validateBody 做运行时校验：缺失必填字段 /
 * 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 */
import { z } from "zod";

/* ===== 主题与背景 ===== */

/** 更换首页主题请求（CS: SetHomeThemeRequest { themeId }） */
export const setHomeThemeSchema = z.object({
  themeId: z.string(),
});

/** 设置首页背景请求（CS: SetHomeBackgroundRequest { bgID }） */
export const setBackgroundSchema = z.object({
  bgID: z.string(),
});

/* ===== 干员轮换（protocol/charRotation） ===== */

/** 设置当前轮换配置请求（CS: CharRotationSetCurrentPresetRequest { instId }） */
export const charRotationSetCurrentSchema = z.object({
  instId: z.string(),
});

/** 创建轮换预设请求（CS: CharRotationCreatePresetRequest，空请求体） */
export const charRotationCreatePresetSchema = z.object({});

/**
 * 更新轮换预设请求（CS: CharRotationUpdatePresetRequest { instId, flag, data }）
 *
 * data 内层字段全部可选，口径同 character/charRotation.schema.ts：按
 * CharRotationManager#updatePreset 实际读取的字段收紧（slots 整体透传），
 * passthrough 保留服务端未读取的协议字段（如 secretaryShowSpDynIllust）。
 */
export const charRotationUpdatePresetSchema = z.object({
  instId: z.string(),
  flag: z.number(),
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

/** 删除轮换预设请求（CS: CharRotationDeletePresetRequest { instId }） */
export const charRotationDeletePresetSchema = z.object({
  instId: z.string(),
});

/* ===== 干员标记 ===== */

/** 修改干员星级标记请求（CS: ChangeStarMarkCharRequest { chrIdDict }）；chrIdDict 为 charId→标记 字典，handler 逐项读取 */
export const changeMarkStarSchema = z.object({
  chrIdDict: z.record(z.string(), z.number()),
});

/* ===== 设置 ===== */

/** 设置低电量模式请求（CS: SetLowPowerRequest { newValue }） */
export const setLowPowerSchema = z.object({
  newValue: z.number(),
});

/** 切换 NPC 语音请求（CS: ChangeRogueNpcVoiceLanRequest { id, voiceLan }） */
export const npcAudioChangeLanSchema = z.object({
  id: z.string(),
  voiceLan: z.string(),
});

/* ===== 剧情 ===== */

/** 完成剧情请求（CS: FinishStoryRequest { storyId }） */
export const finishStorySchema = z.object({
  storyId: z.string(),
});

/* ===== 事件上报 ===== */

/** 客户端事件批量上报请求（服务端自定义，空请求体） */
export const batchEventSchema = z.object({});

/* ===== 信物与烟火 ===== */

/** 设置信物小队请求（CS: CharmSetSquadRequest { squad }） */
export const charmSetSquadSchema = z.object({
  squad: z.array(z.string()),
});

/** 保存烟花棋盘槽位请求（CS: FireworkSavePlateSlotRequest { groupId?, slots }）；slots 复杂，用 z.json() */
export const fireworkSavePlateSlotsSchema = z.object({
  groupId: z.string().optional(),
  slots: z.json(),
});

/** 更换烟花动物请求（CS: FireworkChangeAnimalRequest { animal, groupId? }） */
export const fireworkChangeAnimalSchema = z.object({
  animal: z.string(),
  groupId: z.string().optional(),
});

/* ===== 战车与陷阱队 ===== */

/** 确认出战战车请求（服务端自定义 { car }）；car 复杂，用 z.json() */
export const confirmBattleCarSchema = z.object({
  car: z.json(),
});

/** 设置陷阱队请求（CS: SetTemplateTrapRequest { trapDomainId, trapSquad }）；trapSquad 可为数字/字符串 id */
export const setTrapSquadSchema = z.object({
  trapDomainId: z.string(),
  trapSquad: z.array(z.union([z.string(), z.number()])),
});

/** 特殊干员置顶请求（服务端自定义 { instId }，instId 可为数字/字符串） */
export const pinSpecialOperatorSchema = z.object({
  instId: z.union([z.string(), z.number()]),
});