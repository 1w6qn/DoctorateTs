/**
 * 干员养成（charBuild）请求 zod schema
 *
 * 对应 protocol/charBuild.ts 中 SetDefaultSkillRequest / UpgradeCharRequest /
 * EvolveCharRequest / UnlockEquipmentRequest 等 Request 接口字段，供
 * router/charBuild.ts 经 validateBody 做运行时校验：缺失必填字段 / 类型不符时
 * 返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 *
 * 约定：
 * - 必填字段用对应类型（z.string/z.number/z.boolean/z.array）
 * - 服务端不读或可省略的字段 .optional()
 * - 复杂嵌套对象用 z.any()（如 expMats / squad 等），仅保证键存在不深检
 */

import { z } from "zod";

/* ===== 基础养成 ===== */

/** 设置默认技能请求（CS: SetDefaultSkillRequest） */
export const setDefaultSkillSchema = z.object({
  charInstId: z.number(),
  defaultSkillIndex: z.number(),
});

/** 干员升级请求（CS: UpgradeCharRequest；expMats 为 ItemBundle[] 复杂对象数组） */
export const upgradeCharSchema = z.object({
  charInstId: z.number(),
  // expMats 为 ItemBundle[] 复杂嵌套，仅保证为数组，元素结构不深检
  expMats: z.array(z.any()),
});

/** 干员精英化请求（CS: EvolveCharRequest；destEvolvePhase 为 EvolvePhase 枚举数值） */
export const evolveCharSchema = z.object({
  charInstId: z.number(),
  destEvolvePhase: z.number(),
});

/** 锁定干员请求（服务端自定义） */
export const lockCharSchema = z.object({
  charInstIdList: z.array(z.number()),
});

/** 出售干员请求（CS: SellCharRequest） */
export const sellCharSchema = z.object({
  charInstIdList: z.array(z.number()),
});

/** 提升潜能请求（CS: BoostPotentialRequest） */
export const boostPotentialSchema = z.object({
  charInstId: z.number(),
  itemId: z.string(),
  targetRank: z.number(),
});

/** 升级技能请求（CS: UpgradeSkillRequest） */
export const upgradeSkillSchema = z.object({
  charInstId: z.number(),
  targetLevel: z.number(),
});

/** 专精升级请求（CS: UpgradeSpecializationRequest） */
export const upgradeSpecializationSchema = z.object({
  charInstId: z.number(),
  skillIndex: z.number(),
  targetLevel: z.number(),
});

/** 完成专精升级请求（服务端契约） */
export const completeUpgradeSpecializationSchema = z.object({
  charInstId: z.number(),
  skillIndex: z.number(),
  targetLevel: z.number(),
});

/** 更换干员皮肤请求（CS: ChangeCharSkinRequest） */
export const changeCharSkinSchema = z.object({
  charInstId: z.number(),
  skinId: z.string(),
});

/** 更换干员模组模板请求（CS: ChangeCharTemplateRequest） */
export const changeCharTemplateSchema = z.object({
  charInstId: z.number(),
  templateId: z.string(),
});

/** 获取特殊干员任务奖励请求（CS: GetSpCharMissionRewardRequest） */
export const getSpCharMissionRewardSchema = z.object({
  charId: z.string(),
  missionId: z.string(),
});

/**
 * 使用道具精英化请求（CS: EvolveCharUseItemRequest；handler 同时兼容
 * charInstId/instId 与服务端契约 charInstId/instId 的 CS 别名 charInsId/itemInsId）
 */
export const evolveCharUseItemSchema = z.object({
  charInstId: z.number().optional(),
  charInsId: z.number().optional(),
  itemId: z.string(),
  instId: z.number().optional(),
  itemInsId: z.number().optional(),
});

/** 使用道具升至满级请求（服务端契约，兼容 CS 别名） */
export const upgradeCharLevelMaxUseItemSchema = z.object({
  charInstId: z.number().optional(),
  charInsId: z.number().optional(),
  itemId: z.string(),
  instId: z.number().optional(),
  itemInsId: z.number().optional(),
});

/** 使用道具专精满级请求（服务端契约，兼容 CS 别名） */
export const upgradeSpecializedSkillUseItemSchema = z.object({
  charInstId: z.number().optional(),
  charInsId: z.number().optional(),
  skillIndex: z.number(),
  itemId: z.string(),
  instId: z.number().optional(),
  itemInsId: z.number().optional(),
});

/* ===== 干员密录（addon） ===== */

/** 解锁干员密录剧情请求（服务端自定义） */
export const addonStoryUnlockSchema = z.object({
  charId: z.string(),
  storyId: z.string(),
});

/** 干员密录关卡开始请求（CS: HandBookAddonStageBattleStartRequest；squad 为复杂对象） */
export const addonStageBattleStartSchema = z.object({
  charId: z.string(),
  stageId: z.string(),
  // squad 为 PlayerSquad 复杂嵌套对象，仅保证键存在
  squad: z.any(),
  stageType: z.string(),
});

/** 干员密录关卡结算请求（CS: HandBookAddonStageBattleFinishRequest : CommonFinishBattleRequest） */
export const addonStageBattleFinishSchema = z.object({
  data: z.string(),
  battleData: z.object({
    isCheat: z.string(),
    completeTime: z.number(),
  }),
});

/* ===== 模组 ===== */

/**
 * 解锁模组请求（CS: UI.UnlockEquipmentRequest；templateId 服务端不读，标为可选）
 */
export const unlockEquipmentSchema = z.object({
  charInstId: z.number(),
  templateId: z.string().optional(),
  equipId: z.string(),
});

/** 升级模组请求（CS: UI.UpgradeEquipmentRequest；templateId 服务端不读） */
export const upgradeEquipmentSchema = z.object({
  charInstId: z.number(),
  templateId: z.string().optional(),
  equipId: z.string(),
  targetLevel: z.number(),
});

/** 装备模组请求（CS: UI.UniEquipSetEquipRequest；templateId 服务端不读） */
export const setEquipmentSchema = z.object({
  charInstId: z.number(),
  templateId: z.string().optional(),
  equipId: z.string(),
});

/* ===== 语音 ===== */

/** 批量设置干员语音请求（CS: BatchSetCharVoiceLanRequest） */
export const batchSetCharVoiceLanSchema = z.object({
  voiceLan: z.string(),
});

/** 设置干员语音请求（CS: SetCharVoiceLanRequest） */
export const setCharVoiceLanSchema = z.object({
  charList: z.array(z.number()),
  voiceLan: z.string(),
});

/** 设置皮肤动态立绘请求（CS: ChangeCharSkinSpStateRequest） */
export const changeSkinSpStateSchema = z.object({
  skinId: z.string(),
  isSpecial: z.boolean(),
});