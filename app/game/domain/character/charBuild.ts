/**
 * 干员养成协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu 命名空间的
 * SetDefaultSkillRequest / UpgradeCharRequest / EvolveCharRequest / BoostPotentialRequest /
 * UI.UnlockEquipmentRequest 等 Request/Response 类；字段以 CS 类为准，
 * 服务端未返回的协议字段标为可选。
 */
import { ItemBundle } from "@excel/excel";
import { PlayerSquad } from "../shared/model";
import { PlayerDeltaResponse, RoguelikePushMessage } from "../contracts/common";

/* ===== 基础养成 ===== */

/** 设置默认技能请求（CS: SetDefaultSkillRequest） */
export interface SetDefaultSkillRequest {
  charInstId: number;
  defaultSkillIndex: number;
}

/** 设置默认技能响应（CS: SetDefaultSkillResponse） */
export type SetDefaultSkillResponse = PlayerDeltaResponse;

/**
 * 干员升级请求（CS: UpgradeCharRequest）
 * CS 的 expMats 为 ExpMat[]（{ id, count }），服务端契约使用 ItemBundle[]
 */
export interface UpgradeCharRequest {
  charInstId: number;
  expMats: ItemBundle[];
}

/** 干员升级响应（CS: UpgradeCharResponse） */
export type UpgradeCharResponse = PlayerDeltaResponse;

/**
 * 干员精英化请求（CS: EvolveCharRequest）
 * CS 的 destEvolvePhase 为 EvolvePhase 枚举
 */
export interface EvolveCharRequest {
  charInstId: number;
  destEvolvePhase: number;
}

/** 干员精英化响应（CS: EvolveCharResponse） */
export type EvolveCharResponse = PlayerDeltaResponse;

/**
 * 锁定干员请求（服务端自定义，无 CS 对应类）
 * 服务端实现为安全空操作：仅校验干员存在性（2.7.61 客户端数据模型无 locked
 * 字段，锁定功能已随旧版本下架），不做任何写入
 */
export interface LockCharRequest {
  charInstIdList: number[];
}

/** 锁定干员响应（服务端自定义） */
export type LockCharResponse = PlayerDeltaResponse;

/**
 * 出售干员请求（CS: SellCharRequest）
 * 服务端实现为安全空操作：官方已下架干员出售，重复干员在获取时自动转化为
 * 资质凭证（onCharGet），直接删除 roster 会破坏编队/助战/图鉴引用
 */
export interface SellCharRequest {
  charInstIdList: number[];
}

/** 出售干员响应（CS: SellCharResponse） */
export type SellCharResponse = PlayerDeltaResponse;

/** 提升潜能请求（CS: BoostPotentialRequest） */
export interface BoostPotentialRequest {
  charInstId: number;
  itemId: string;
  targetRank: number;
}

/**
 * 提升潜能响应（CS: BoostPotentialResponse）
 * CS 字段为 resultOneSuc，服务端返回 result
 */
export interface BoostPotentialResponse extends PlayerDeltaResponse {
  result: number;
}

/** 升级技能请求（CS: UpgradeSkillRequest） */
export interface UpgradeSkillRequest {
  charInstId: number;
  targetLevel: number;
}

/** 升级技能响应（CS: UpgradeSkillResponse） */
export type UpgradeSkillResponse = PlayerDeltaResponse;

/** 专精升级请求（CS: UpgradeSpecializationRequest） */
export interface UpgradeSpecializationRequest {
  charInstId: number;
  skillIndex: number;
  targetLevel: number;
}

/** 专精升级响应（CS: UpgradeSpecializationResponse） */
export type UpgradeSpecializationResponse = PlayerDeltaResponse;

/**
 * 完成专精升级请求（服务端契约；CS 同名类 CompleteUpgradeSpecializationRequest
 * 继承 BuildingRequest 且无字段，此处以服务端契约为准）
 */
export interface CompleteUpgradeSpecializationRequest {
  charInstId: number;
  skillIndex: number;
  targetLevel: number;
}

/** 完成专精升级响应（CS: CompleteUpgradeSpecializationResponse） */
export type CompleteUpgradeSpecializationResponse = PlayerDeltaResponse;

/** 更换干员皮肤请求（CS: ChangeCharSkinRequest） */
export interface ChangeCharSkinRequest {
  charInstId: number;
  skinId: string;
}

/** 更换干员皮肤响应（CS: ChangeCharSkinResponse） */
export type ChangeCharSkinResponse = PlayerDeltaResponse;

/** 更换干员模组模板请求（CS: ChangeCharTemplateRequest） */
export interface ChangeCharTemplateRequest {
  charInstId: number;
  templateId: string;
}

/** 更换干员模组模板响应（CS: ChangeCharTemplateResponse） */
export type ChangeCharTemplateResponse = PlayerDeltaResponse;

/** 获取特殊干员任务奖励请求（CS: GetSpCharMissionRewardRequest） */
export interface GetSpCharMissionRewardRequest {
  charId: string;
  missionId: string;
}

/** 获取特殊干员任务奖励响应（CS: GetSpCharMissionRewardResponse；服务端仅返回增量） */
export type GetSpCharMissionRewardResponse = PlayerDeltaResponse;

/** 使用道具精英化请求（CS: EvolveCharUseItemRequest；itemId 为精二直升券如 voucher_elite_II_6） */
export interface EvolveCharUseItemRequest {
  charInstId: number;
  itemId: string;
  instId: number;
}

/** 使用道具精英化响应（CS: EvolveCharUseItemResponse） */
export type EvolveCharUseItemResponse = PlayerDeltaResponse;

/**
 * 使用道具升至满级请求（服务端契约；CS 同名类 UpgradeCharLevelMaxRequest
 * 字段为 charInsId/itemId/itemInsId，服务端读取 charInstId/itemId/instId；
 * itemId 为满级直升券如 voucher_levelmax_6）
 */
export interface UpgradeCharLevelMaxUseItemRequest {
  charInstId: number;
  itemId: string;
  instId: number;
}

/** 使用道具升至满级响应（CS: UpgradeCharLevelMaxResponse） */
export type UpgradeCharLevelMaxUseItemResponse = PlayerDeltaResponse;

/**
 * 使用道具专精满级请求（CS: UpgradeSpecializedSkillUseItemRequest）
 * CS 字段为 charInsId/itemInsId，服务端读取 charInstId/instId；
 * itemId 为专精直升券如 voucher_skill_specialLevelMax_6
 */
export interface UpgradeSpecializedSkillUseItemRequest {
  charInstId: number;
  skillIndex: number;
  itemId: string;
  instId: number;
}

/** 使用道具专精满级响应（CS: UpgradeSpecializedSkillUseItemResponse） */
export type UpgradeSpecializedSkillUseItemResponse = PlayerDeltaResponse;

/* ===== 干员密录（addon） ===== */

/**
 * 解锁干员密录剧情请求（服务端自定义，无 CS 对应类）
 * 服务端读取 charId/storyId
 */
export interface AddonStoryUnlockRequest {
  charId: string;
  storyId: string;
}

/** 勋章完成推送消息（对齐官服 addonStory/unlock 响应的 pushMessage[0]） */
export interface MedalFinishPushMessage {
  path: "medalFinish";
  payload: { idList: string[] };
}

/**
 * 解锁干员密录剧情响应（服务端自定义）
 * 对照官服抓包（tmp/charBuild_addonStory_unlock_res_1107.json）：
 * 响应含 rewards:null + 增量 + pushMessage medalFinish（解锁密录发放勋章时推送）
 * pushMessage 采用通用 `RoguelikePushMessage[]`（medal.ts rewardMedal 同样推 medalFinish），
 * 兼容增量带出的通用推送；具体形状见 {@link MedalFinishPushMessage}。
 */
export interface AddonStoryUnlockResponse extends PlayerDeltaResponse {
  rewards: null;
  pushMessage?: RoguelikePushMessage[];
}

/** 干员密录关卡开始请求（CS: HandBookAddonStageBattleStartRequest） */
export interface AddonStageBattleStartRequest {
  charId: string;
  stageId: string;
  squad: PlayerSquad;
  stageType: string;
}

/** 干员密录关卡开始响应（CS: HandBookAddonStageBattleStartResponse；服务端返回 battleId + 增量） */
export interface AddonStageBattleStartResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  apFailReturn: number;
  isApProtect: number;
  inApProtectPeriod: boolean;
  notifyPowerScoreNotEnoughIfFailed: boolean;
}

/**
 * 干员密录关卡结算请求（CS: HandBookAddonStageBattleFinishRequest : CommonFinishBattleRequest）
 * CS 的 battleData 为 BattleDataInRequest，服务端契约仅读 isCheat/completeTime
 */
export interface AddonStageBattleFinishRequest {
  data: string;
  battleData: { isCheat: string; completeTime: number };
}

/**
 * 干员密录关卡结算响应（CS: HandBookAddonStageBattleFinishResponse : CommonFinishBattleResponse）
 * 服务端透传 battle:finish 事件结果，字段可缺失故全部可选
 */
export interface AddonStageBattleFinishResponse extends PlayerDeltaResponse {
  result?: number;
  apFailReturn?: number;
  rewards?: ItemBundle[];
  firstRewards?: ItemBundle[];
  unlockStages?: string[];
  unusualRewards?: ItemBundle[];
  additionalRewards?: ItemBundle[];
  furnitureRewards?: ItemBundle[];
  alert?: unknown[];
  suggestFriend?: boolean;
  pryResult?: unknown[];
}

/* ===== 模组 ===== */

/** 解锁模组请求（CS: UI.UnlockEquipmentRequest） */
export interface UnlockEquipmentRequest {
  charInstId: number;
  templateId: string;
  equipId: string;
}

/** 解锁模组响应（CS: UI.UnlockEquipmentResponse） */
export type UnlockEquipmentResponse = PlayerDeltaResponse;

/** 升级模组请求（CS: UI.UpgradeEquipmentRequest） */
export interface UpgradeEquipmentRequest {
  charInstId: number;
  templateId: string;
  equipId: string;
  targetLevel: number;
}

/** 升级模组响应（CS: UI.UpgradeEquipmentResponse） */
export type UpgradeEquipmentResponse = PlayerDeltaResponse;

/** 装备模组请求（CS: UI.UniEquipSetEquipRequest） */
export interface SetEquipmentRequest {
  charInstId: number;
  templateId: string;
  equipId: string;
}

/** 装备模组响应（CS: UI.UniEquipSetEquipResponse） */
export type SetEquipmentResponse = PlayerDeltaResponse;

/* ===== 语音 ===== */

/** 批量设置干员语音请求（CS: BatchSetCharVoiceLanRequest；CS 的 voiceLan 为 VoiceLangType 枚举） */
export interface BatchSetCharVoiceLanRequest {
  voiceLan: string;
}

/** 批量设置干员语音响应（CS: BatchSetCharVoiceLanResponse） */
export type BatchSetCharVoiceLanResponse = PlayerDeltaResponse;

/** 设置干员语音请求（CS: SetCharVoiceLanRequest；CS 的 voiceLan 为 VoiceLangType 枚举） */
export interface SetCharVoiceLanRequest {
  charList: number[];
  voiceLan: string;
}

/** 设置干员语音响应（CS: SetCharVoiceLanResponse） */
export type SetCharVoiceLanResponse = PlayerDeltaResponse;

/**
 * 设置皮肤动态立绘请求（CS: ChangeCharSkinSpStateRequest）
 * CS 的 isSpecial 为 Boolean，写入 playerData skin.skinSp（boolean），此处保持 boolean
 */
export interface ChangeCharSkinSpStateRequest {
  skinId: string;
  isSpecial: boolean;
}

/** 设置皮肤动态立绘响应（CS: ChangeCharSkinSpStateResponse） */
export type ChangeCharSkinSpStateResponse = PlayerDeltaResponse;
