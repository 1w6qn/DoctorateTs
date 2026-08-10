import type { ClassDef } from "./playerdata-parser";
import { applyAdaptOps } from "./types-adapt";

/**
 * excel 表根类映射（数据驱动）
 *
 * 表键 → cs 根类名（Torappu.* 短名）。两类结构：
 *  - 包装类：JSON 顶层为具名字段（如 stage_table 的 stages/runeStageGroups/... → StageTable）
 *  - 元素类：JSON 顶层为字典（如 character_table 的 { charId: CharacterData } → CharacterData）
 * 多根表（一个 JSON 多个顶层 key 各自独立类型）用 { [jsonKey]: 根类 } 形式。
 *
 * 根类由 data/excel/*.json 顶层结构 × cs 类字段匹配自动反推 + 校验闭环修正。
 */
export const EXCEL_TABLE_ROOTS: Record<string, string | Record<string, string>> = {
  character_table: "CharacterData",
  skill_table: "SkillDataBundle",
  stage_table: "StageTable",
  item_table: "InventoryData",
  building_data: "BuildingData",
  gacha_table: "GachaData",
  mission_table: "MissionTable",
  medal_table: "MedalData",
  story_table: "StoryData",
  zone_table: "ZoneTable",
  skin_table: "SkinTable",
  retro_table: "RetroStageTable",
  campaign_table: "CampaignTable",
  uniequip_table: "UniEquipTable",
  favor_table: "FavorTable",
  chapter_table: "ChapterData",
  open_server_table: "OpenServerSchedule",
  char_master_table: "CharMasterBasicData",
  char_patch_table: "CharPatchData",
  charword_table: "CharWordTable",
  charm_table: "CharmData",
  crisis_table: "CrisisClientData",
  display_meta_table: "DisplayMetaData",
  enemy_database: "EnemyDatabase",
  enemy_handbook_table: {
    levelInfoData: "EnemyHandbookLevelInfoData",
    enemyRaceData: "EnemyHandbookRaceData",
  },
  ep_breakbuff_table: "EPBreakBuffData",
  extra_battlelog_table: "ExtraBattleLogData",
  handbook_team_table: "HandbookTeamData",
  hotupdate_meta_table: "HotUpdateMetaTable",
  meta_ui_table: "MetaUIDisplayTable",
  player_avatar_table: "PlayerAvatarData",
  range_table: "RangeData",
  replicate_table: "ReplicateTable",
  roguelike_table: "RoguelikeTable",
  shop_client_table: "ShopClientData",
  special_operator_table: "SpecialOperatorTable",
  story_review_table: "StoryReviewGroupClientData",
  story_review_meta_table: "StoryReviewMetaTable",
  arkvent_table: "ArkOdcTable",
  gamedata_const: "GameDataConsts",
  handbook_info_table: "HandbookInfoTable",
  checkin_table: "CheckInTable",
  activity_table: "ActivityTable",
  battle_equip_table: "BattleEquipPack",
  char_meta_table: "CharMetaTable",
  crisis_v2_table: "CrisisV2SharedData",
  sandbox_perm_table: "SandboxPermTable",
  climb_tower_table: "ClimbTowerTable",
  roguelike_topic_table: "RoguelikeTopicTable",
};

/** 覆盖所有表根（多根表展开为值集合） */
export function allTableRoots(): string[] {
  const out = new Set<string>();
  for (const r of Object.values(EXCEL_TABLE_ROOTS)) {
    if (typeof r === "string") out.add(r);
    else Object.values(r).forEach(v => out.add(v));
  }
  return [...out];
}

/**
 * excel 协议适配层（表结构修正，数据驱动）
 *
 * 与 playerdata 适配层同机制：
 *  - renameFields：客户端字段名 → JSON key（如 key 命名差异）
 *  - addFields：JSON 有、客户端类未声明的字段
 *  - overrideFields：整接口覆盖（继承类解析为空接口时补 JSON 实际结构）
 *  - optionalFields：JSON 部分条目省略的字段
 * 维护流程：validate-excel-json.ts 审计报告 → 补清单 → 重生成 → 再审计
 */
export const EXCEL_RENAME_FIELDS: Record<string, Record<string, string>> = {
  // 干员技能：JSON 用旧版字段名（FBS 同款），cs 2.7.61 为 specializeLevelUpData/initialUnlockCond
  CharacterData_MainSkill: {
    specializeLevelUpData: "levelUpCostCond",
    initialUnlockCond: "unlockCond",
  },
};

export const EXCEL_ADD_FIELDS: Record<string, Record<string, string>> = {
  // 关卡额外条件/信息（2.7.61 客户端类未声明，JSON 有）
  StageData: {
    extraCondition: "{ index: number; template: string; unlockParam: string[] }[]",
    extraInfo: "{ stageId: string; rewards: ItemBundle[]; progressInfo: object; imageId: string; keyItemId: string; unlockDesc: string }[]",
  },
  // 皮肤配图字段（JSON 有，cs 2.7.61 CharSkinData 未声明）
  CharSkinData: {
    illustId: "string",
    spIllustId: "string",
    dynIllustId: "string",
    spDynIllustId: "string",
    avatarId: "string",
    spAvatarId: "string",
    portraitId: "string",
    spPortraitId: "string",
    dynPortraitId: "string",
    dynEntranceId: "string",
    buildingId: "string",
    battleSkin: "string",
    isBuySkin: "boolean",
  },
  // 每日/每周奖励配置：JSON 条目字段（cs MissionDailyRewardConf 结构分叉）
  MissionDailyRewardConf: {
    groupId: "string",
    id: "string",
    periodicalPointCost: "number",
    type: "string",
    sortIndex: "number",
    rewards: "ItemBundle[]",
  },
  // 语音字典：JSON 词条含 dict 字段
  VoiceLangData: { dict: "object" },
  // 每日/每周奖励配置（MissionWeeklyRewardConf 与 Daily 同构）
  MissionWeeklyRewardConf: {
    groupId: "string",
    id: "string",
    periodicalPointCost: "number",
    type: "string",
    sortIndex: "number",
    rewards: "ItemBundle[]",
  },
  // 勋章分类计数（JSON 按类型分键，cs 类未声明）
  MedalPerData: {
    playerMedal: "object",
    stageMedal: "object",
    campMedal: "object",
    towerMedal: "object",
    growthMedal: "object",
    storyMedal: "object",
    buildMedal: "object",
    activityMedal: "object",
    rogueMedal: "object",
    hiddenMedal: "object",
  },
  // 开服活动条目

  CharMasterBasicData: { candidates: "object[]" },
  CharPatchData_PatchInfo: { default: "object" },
  NameCardV2RemovableModuleData: { id: "string", type: "string" },
  GameDataConsts: { TSO: "number" },
  ActivityTable_ActivityExtraData: { MAINLINE_BP: "object" },
  // 战斗日志分类（JSON 顶层按固定 key 分键）
  ExtraBattleLogData: {
    SELECTOR: "object",
    DEATHDETAIL: "object",
    PROJECTILEBORN: "object",
    OUTPUT_DAMAGE_TOTAL: "object",
  },
  RecruitPool: { recruitConstants: "object" },
  // 开服活动条目
  OpenServerScheduleItem: {
    constData: "object",
    openseverTaskGroup1: "object",
    openseverTaskGroup2: "object",
    firstDiamondShardMailCount: "number",
    initApMailEndTs: "number",
    resFullOpenUnlockStageId: "string",
    resFullOpenDuration: "number",
    resFullOpenTitle: "string",
    resFullOpenDesc: "string",
    resFullOpenGuideGroupThreshold: "number",
    resFullOpenStartTime: "number",
    groupDataMap: "object",
    onceDataMap: "object",
    checkinDataMap: "object",
    priceDataMap: "object",
    missionDataMap: "object",
    checkinGpData: "object",
    newsDataMap: "object",
    giftPackagePicDataMap: "object",
    openStyleData: "object",
    groupList: "object",
  },
  // 故事回顾元数据（包装类）
  StoryReviewMetaTable: {
    miniActTrialData: "MiniActTrialData",
    actArchiveResData: "object",
    actArchiveData: "object",
    trainingCampData: "object",
  },
  // 肉鸽道具 value（FBS 兼容：JSON 含 value）
  RoguelikeGameItemData: { value: "number" },
  // 沙盒权限详情（按模式分键）
  SandboxPermDetailData: { SANDBOX_V2: "object", SANDBOX_V3: "object" },
  // 商店客户端：低阶/高阶商店缩写 key（线格式字典）
  ShopClientData: { ls: "object", os: "object" },
  // 肉鸽常量表（JSON 有，cs RoguelikeTable 未声明全字段）
  RoguelikeTable: {
    playerLevelTable: "object",
    recruitPopulationTable: "object",
    charUpgradeTable: "object",
    eventTypeTable: "object",
    shopDialogs: "object",
    shopRelicDialogs: "object",
    eventTypeDialogs: "object",
  },
  // 热更图片条目（JSON 有视频字段）
  HotUpdateMetaPicData: { videoId: "string", videoPath: "string" },
  // 肉鸽常量表补充
  RoguelikeTable: {
    shopTicketDialogs: "object",
    mimicEnemyIds: "string[]",
    clearZoneScores: "object",
    moveToNodeScore: "number",
    clearNormalBattleScore: "number",
    clearEliteBattleScore: "number",
    clearBossBattleScore: "number",
    upgradeRarityScore: "number",
    collectEndingScore: "number",
    eventTypeIcons: "object",
    choiceScenes: "object",
  },

};

export const EXCEL_OVERRIDE_FIELDS: Record<string, Record<string, string>> = {
  // 掉落详情：JSON 实际为 DisplayRewards 基类字段 + occPercent（客户端类为 GetPercent 系列，结构分叉）
  StageData_DisplayDetailRewards: {
    "[server]": "{ occPercent: OccPer; type: ItemType; id: string; dropType: StageDropType }",
  },
  // 活动自定义数据：JSON 按活动类型分键
  ActivityCustomData: {
    "[server]": "{ [key: string]: object }",
  },
  // 阵营手册数据（JSON 按阵营分键）
  HandbookTeamData: {
    "[server]": "{ [key: string]: object }",
  },
  // 活动详情（JSON 按活动类型分键）
  ActivityTable_ActivityDetailTable: {
    "[server]": "{ [key: string]: object }",
  },
  // 肉鸽活动（JSON 含 SEED_MODE 等活动类型键）
  RoguelikeActivityTable: {
    "[server]": "{ [key: string]: object }",
  },
  // 肉鸽主题自定义数据（JSON 按主题分键）
  RoguelikeTopicCustomizeData: {
    "[server]": "{ [key: string]: object }",
  },
};

export const EXCEL_OPTIONAL_FIELDS: Record<string, string[]> = {};

/** 枚举值补充（JSON 含客户端 2.7.61 枚举未定义的新值，如 StageDropType.COMPLETE_ONLY） */
export const EXCEL_ENUM_ADDITIONS: Record<string, string[]> = {
  StageDropType: ["COMPLETE_ONLY"],
};

/** 字段类型覆盖（最高优先级，适配后应用）："Iface.field" → TS 类型 */
export const EXCEL_FIELD_TYPE_OVERRIDES: Record<string, string> = {
  // 技能 spType 线格式混合：多数为字符串枚举名，1760 处为数值（8）
  "SpData.spType": "SpType | number",
  // 攻击范围方向：JSON 为数值枚举（1/2/4/8）
  "RangeData.direction": "number | string",
  // 符文职业掩码：JSON 为数值位掩码（58/581/1023），非字符串枚举
  "RuneData_Selector.professionMask": "number | ProfessionCategory",
  // 肉鸽表数值/字符串枚举混合
  "RoguelikeConstTable_CharUpgradeData.evolvePhase": "number | string",
  "RoguelikeRecruitTicketFeature.profession": "number | string",
  "RoguelikeRecruitTicketFeature.rarity": "number | string",
  "RoguelikeRecruitTicketFeature.rarityList": "(number | string)[]",
  "RoguelikeRecruitTicketFeature.extraFreeRarity": "(number | string)[]",
  "RoguelikeGameRecruitTicketData.profession": "number | string",
  "RoguelikeGameRecruitTicketData.rarity": "number | string",
  "RoguelikeUpgradeTicketFeature.profession": "number | string",
  "RoguelikeUpgradeTicketFeature.rarity": "number | string",
  "RoguelikeUpgradeTicketFeature.rarityList": "(number | string)[]",
  "RoguelikeGameUpgradeTicketData.profession": "number | string",
  "RoguelikeGameUpgradeTicketData.rarity": "number | string",
};

/** 附加索引签名的接口（运行时以 dict 键访问，如 CharacterTable[charId]） */
export const EXCEL_INDEX_SIGNATURES: string[] = ["CharacterData", "StoryReviewGroupClientData"];

/**
 * 应用 excel 协议适配：rename → add → override → 字段覆盖（共享应用逻辑）
 * @param classes - 客户端闭包类定义
 * @returns 适配后的类定义列表（不修改入参）
 */
export function applyExcelAdapt(classes: ClassDef[]): ClassDef[] {
  return applyAdaptOps(classes, {
    rename: EXCEL_RENAME_FIELDS,
    add: EXCEL_ADD_FIELDS,
    override: EXCEL_OVERRIDE_FIELDS,
    optional: EXCEL_OPTIONAL_FIELDS,
    fieldTypeOverrides: EXCEL_FIELD_TYPE_OVERRIDES,
  });
}
