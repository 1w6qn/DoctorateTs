/**
 * Excel 数据表管理模块
 * 
 * 负责加载和管理所有游戏配置数据表（Excel 数据），包括角色、关卡、物品、抽卡等数据。
 * 所有数据表在服务器启动时加载，运行时只读访问。
 */

import { readJson, readJsonSync } from "@utils/file";
import { logger } from "@utils/logger";
import {
  ActivityTable,
  BattleEquipPack,
  BuildingData,
  CampaignTable,
  CharMasterBasicData,
  CharMetaTable,
  CharPatchData,
  CharWordTable,
  CharmData,
  CheckInTable,
  ClimbTowerTable,
  CrisisClientData,
  CrisisV2SharedData,
  DisplayMetaData,
  EnemyDatabase,
  EnemyHandbookLevelInfoData,
  EnemyHandbookRaceData,
  EPBreakBuffData,
  ExtraBattleLogData,
  FavorTable,
  GameDataConsts,
  GachaData,
  HandbookInfoTable,
  HandbookTeamData,
  HotUpdateMetaTable,
  MedalData,
  MetaUIDisplayTable,
  PlayerAvatarData,
  RangeData,
  ReplicateTable,
  RetroStageTable,
  RoguelikeActivityTable,
  SandboxPermItemData,
  SandboxPermTable,
  ShopClientData,
  SkillDataBundle,
  SkinTable,
  SpecialOperatorTable,
  StoryData,
  StoryReviewGroupClientData,
  StoryReviewMetaTable,
  UniEquipData,
  UniEquipTable,
  ZoneTable,
  MissionData,
  RoguelikeGridZoneModuleData,
  RoguelikeWeatherModuleData,
  RoguelikeScrapModuleData,
  ChapterData,
  Blackboard,
  RoguelikeBuff,
  CharacterData,
  ItemBundle,
  ExternalBuff,
  EquipTalentData,
  TalentData,
  ActivityPotentialCharacterInfo,
  ApSupplyFeature,
  ExpItemFeature,
  FavorCharacterInfo,
  FullPotentialCharacterInfo,
  ItemPackInfo,
  ItemData,
  ItemClassifyType,
  ItemRarity,
  OccPer,
  UniCollectionInfo,
  MissionTable,
  CrossAppShareMissionConst,
  CrossAppShareMission,
  DailyMissionGroupInfo,
  MissionGroup,
  MissionDailyRewardConf,
  MissionWeeklyRewardConf,
  OpenServerSchedule,
  OpenServerConst,
  OpenServerData,
  TotalCheckinData,
  ChainLoginData,
  OpenServerItemData,
  NewbieCheckInPackageData,
  NewbieCheckInPackageRewardData,
  ReturnData,
  OpenServerScheduleItem,
  StageTable,
  ActCustomStageData,
  ApProtectZoneInfo,
  StageValidInfo,
  StageDiffGroupTable,
  WeeklyForceOpenTable,
  MapThemeData,
  OverrideDropInfo,
  SpecialBattleFinishStageData,
  StageFogInfo,
  StageStartCond,
  StageData,
  StoryStageShowGroup,
  TileAppendInfo,
  TimelyDropTimeInfo,
  TimelyDropInfo,
  OverrideUnlockInfo,
  RoguelikeTopicTable,
  RoguelikeTopicConst,
  RoguelikeTopicDetail,
  RoguelikeArchiveComponentData,
  ActArchiveBuffData,
  ActArchiveCapsuleData,
  ActArchiveCapsuleItemData,
  ActArchiveChatData,
  ActArchiveChatGroupData,
  ActArchiveChatItemData,
  ActArchiveEndbookData,
  ActArchiveRelicData,
  ActArchiveRelicItemData,
  ActArchiveTrapData,
  ActArchiveTrapItemData,
  RoguelikeArchiveUnlockCondData,
  RoguelikeArchiveEnroll,
  RoguelikeArchiveUnlockCondDesc,
  RoguelikeTopicBankReward,
  TipData,
  RoguelikeBattleSummeryDescriptionData,
  RoguelikeTopicCapsule,
  RoguelikeTopicChallenge,
  RoguelikeTopicChallengeTask,
  RoguelikeGameChoiceSceneData,
  RoguelikeGameChoiceData,
  RoguelikeTopicDetailConst,
  RoguelikeTopicDifficulty,
  RoguelikeEndingDetailText,
  RoguelikeGameEndingData,
  RoguelikeTopicEnroll,
  RoguelikeGameConst,
  RoguelikeTopicBPGrandPrize,
  RoguelikeGameInitData,
  RoguelikeGameItemData,
  RoguelikeTopicMilestoneUpdateData,
  RoguelikeTopicBP,
  RoguelikeTopicMonthMission,
  RoguelikeTopicMonthSquad,
  RoguelikeGameNodeTypeData,
  RoguelikeGameRecruitGrpData,
  RoguelikeGameRecruitTicketData,
  RoguelikeGameRelicParamData,
  RoguelikeGameRelicData,
  RoguelikeGameShopDialogData,
  RoguelikeGameShopDialogTypeData,
  RoguelikeGameShopDialogGroupData,
  RoguelikeGameStageData,
  RoguelikePredefinedConstStyleData,
  RoguelikeGameTrapData,
  RoguelikeGameExploreToolData,
  RoguelikeTopicUpdate,
  RoguelikeGameUpgradeTicketData,
  RoguelikeGameVariationData,
  RoguelikeGameCharBuffData,
  RoguelikeGameSquadBuffData,
  RoguelikeGameZoneData,
  ActArchiveBuffItemData,
  ActArchiveEndbookGroupData,
  ActArchiveEndbookItemData,
  RoguelikeBandRefData,
  RoguelikeGameCustomTicketData,
  RoguelikeTaskData,
  RoguelikeGameTreasureData,
  ActArchiveChaosData,
  ActArchiveChaosItemData,
  ActArchiveTotemData,
  ActArchiveTotemItemData,
  RoguelikeDifficultyUpgradeRelicGroupData,
  RoguelikeDifficultyUpgradeRelicData,
  RoguelikePredefinedStyleData,
  RoguelikeGameNodeSubTypeData,
  ActArchiveDisasterData,
  ActArchiveDisasterItemData,
  ActArchiveFragmentData,
  ActArchiveFragmentItemData,
  RoguelikeEndingRelicDetailText,
  RoguelikeRollNodeData,
  RoguelikeRollNodeGroupData,
  RoguelikeModule,
  RoguelikeChaosModuleData,
  RoguelikeChaosData,
  RoguelikeChaosRangeData,
  RoguelikeChaosPredefineLevelInfo,
  RoguelikeChaosModuleConsts,
  RoguelikeDiceModuleData,
  RoguelikeDiceData,
  RoguelikeDiceRuleData,
  RoguelikeDicePredefineData,
  RoguelikeDiceRuleGroupData,
  RoguelikeDisasterModuleData,
  RoguelikeDisasterData,
  RoguelikeFragmentModuleData,
  RoguelikeAlchemyData,
  RoguelikeAlchemyFormulationData,
  RoguelikeFragmentBuffData,
  RoguelikeFragmentData,
  RoguelikeFragmentLevelRelatedData,
  RoguelikeFragmentTypeData,
  RoguelikeFragmentModuleConsts,
  RoguelikeNodeUpgradeModuleData,
  RoguelikeNodeUpgradeData,
  RoguelikePermNodeUpgradeItemData,
  RoguelikeTempNodeUpgradeItemData,
  RoguelikeSanCheckModuleData,
  RoguelikeSanCheckConsts,
  RoguelikeSanRangeData,
  RoguelikeTotemBuffModuleData,
  RoguelikeTotemModuleConsts,
  RoguelikeTotemSubBuffData,
  RoguelikeTotemBuffData,
  RoguelikeTotemLinkedNodeTypeData,
  RoguelikeVisionModuleData,
  RoguelikeVisionModuleConsts,
  RoguelikeVisionData,
  RoguelikeTopicBasicData,
  RoguelikeTopicConfig,
} from "./types_excel_gen";


import { buildRoguelikeConsts } from "./roguelike_consts_gen";






export class Excel {
  BattleEquipTable!: BattleEquipPack;
  BuildingData!: BuildingData;
  CharacterTable!: CharacterTable;
  GameDataConst!: GameDataConsts;
  ItemTable!: ServerItemTable;
  StageTable!: StageTable;
  CheckinTable!: CheckInTable;
  StoryReviewMetaTable!: StoryReviewMetaTable;
  GachaTable!: GachaData;
  MissionTable!: MissionTable;
  RoguelikeTopicTable!: RoguelikeTopicTable;
  UniequipTable!: UniEquipTable;
  StoryReviewTable!: StoryReviewGroupClientData;
  FavorTable!: FavorTable;
  MedalTable!: MedalData;
  GachaDetailTable!: GachaDetailTable;
  CharMetaTable!: CharMetaTable;
  SkinTable!: SkinTable;
  OpenServerTable!: OpenServerSchedule;
  RetroTable!: RetroStageTable;
  RoguelikeConsts!: { [key: string]: RoguelikeConst };
  ShopTable!: ShopData;
  ActivityTable!: ActivityTable;
  CampaignTable!: CampaignTable;
  ChapterTable!: { [key: string]: ChapterData };
  CharMasterTable!: { [key: string]: CharMasterBasicData };
  CharPatchTable!: CharPatchData;
  CharmTable!: CharmData;
  ClimbTowerTable!: ClimbTowerTable;
  CrisisTable!: CrisisClientData;
  CrisisV2SharedData!: CrisisV2SharedData;
  DisplayMetaTable!: DisplayMetaData;
  EpBreakBuffData!: EPBreakBuffData;
  ExtraBattleLogData!: ExtraBattleLogData;
  HotUpdateMetaTable!: HotUpdateMetaTable;
  MetaUIDisplayTable!: MetaUIDisplayTable;
  PlayerAvatarTable!: PlayerAvatarData;
  RangeTable!: RangeData;
  ReplicateTable!: ReplicateTable;
  RoguelikeActivityTable!: RoguelikeActivityTable;
  /** 沙盒活动表（cs 无对应包装类，JSON 按活动分键的松散视图） */
  SandboxActTable!: { [key: string]: object };
  SandboxPermTable!: SandboxPermTable;
  SandboxTable!: { [key: string]: SandboxPermItemData };
  ShopClientTable!: ShopClientData;
  SpecialOperatorTable!: SpecialOperatorTable;
  StoryData!: StoryData;
  UniEquipData!: UniEquipData;
  ZoneTable!: ZoneTable;
  ArkventTable!: any;

  /**
   * 懒加载大表（B-1 性能优化）
   *
   * 以下为启动期不触碰、请求期才用的大表（合计 ~30MB JSON）——从 init() 的
   * 全量加载移出，首次访问时同步 parse（单次 ~30-65ms，摊到首个用到该表的请求）。
   * 启动解析时间与常驻内存下降；访问模式与字段完全一致（getter 透明）。
   *
   * 注意：热重载（index.ts 后台更新后再次 excel.init()）必须 resetLazyTables()
   * 使缓存失效，否则重载后的懒加载表仍返回旧数据（陈旧数据 bug）。
   */
  private _handbookInfoTable?: HandbookInfoTable;
  get HandbookInfoTable(): HandbookInfoTable {
    return (this._handbookInfoTable ??= readJsonSync<HandbookInfoTable>(
      "./data/excel/handbook_info_table.json",
    ));
  }

  private _charWordTable?: CharWordTable;
  get CharWordTable(): CharWordTable {
    return (this._charWordTable ??= readJsonSync<CharWordTable>(
      "./data/excel/charword_table.json",
    ));
  }

  private _enemyDatabase?: EnemyDatabase;
  get EnemyDatabase(): EnemyDatabase {
    return (this._enemyDatabase ??= readJsonSync<EnemyDatabase>(
      "./data/excel/enemy_database.json",
    ));
  }

  private _enemyHandbookLevelInfoTable?: EnemyHandbookLevelInfoData;
  get EnemyHandbookLevelInfoTable(): EnemyHandbookLevelInfoData {
    return (this._enemyHandbookLevelInfoTable ??= readJsonSync<EnemyHandbookLevelInfoData>(
      "./data/excel/enemy_handbook_table.json",
    ));
  }

  private _enemyHandbookRaceTable?: EnemyHandbookRaceData;
  get EnemyHandbookRaceTable(): EnemyHandbookRaceData {
    return (this._enemyHandbookRaceTable ??= readJsonSync<EnemyHandbookRaceData>(
      "./data/excel/enemy_handbook_table.json",
    ));
  }

  private _handbookTeamTable?: HandbookTeamData;
  get HandbookTeamTable(): HandbookTeamData {
    return (this._handbookTeamTable ??= readJsonSync<HandbookTeamData>(
      "./data/excel/handbook_team_table.json",
    ));
  }

  private _skillDataBundle?: SkillDataBundle;
  get SkillDataBundle(): SkillDataBundle {
    return (this._skillDataBundle ??= readJsonSync<SkillDataBundle>(
      "./data/excel/skill_table.json",
    ));
  }

  /**
   * 会客室线索数据表（官方 clue_data.json）
   *
   * 线索阵营/编号/过期天数等常量；`expiredDays`（线索过期天数）供
   * BuildingManager 好友赠送线索的自动过期移除使用。懒加载（小表）。
   */
  private _clueData?: any;
  get ClueData(): any {
    return (this._clueData ??= readJsonSync<any>("./data/excel/clue_data.json"));
  }

  /**
   * 奇象巡展 ARKDEX 完整模块数据（生物/属性克制/道具/特质/NPC/模式/捕获区）
   * 来源：activity_table.json → activity.arkHub.act1arkhub.moduleData.arkdexModule
   * （官方 CDN 热更，2026-08-17 导出到 data/arkhub/arkdex.json）
   */
  private _arkhubCreatureTable?: Record<string, any>;
  get ArkhubCreatureTable(): Record<string, any> {
    return (this._arkhubCreatureTable ??= readJsonSync<Record<string, any>>(
      "./data/arkhub/arkdex.json",
    ));
  }

  /**
   * 失效懒加载大表缓存（热重载后调用，避免返回陈旧数据）
   *
   * init() 重载数据时清空私有缓存字段，使后续 getter 访问重新读盘。
   */
  resetLazyTables(): void {
    this._handbookInfoTable = undefined;
    this._charWordTable = undefined;
    this._enemyDatabase = undefined;
    this._enemyHandbookLevelInfoTable = undefined;
    this._enemyHandbookRaceTable = undefined;
    this._handbookTeamTable = undefined;
    this._skillDataBundle = undefined;
    this._clueData = undefined;
    this._arkhubCreatureTable = undefined;
  }

  /**
   * 后台预热全部懒加载大表（B-5 性能优化）
   *
   * 首个请求触达大表（干员详情/档案/技能/敌人图鉴等）时同步 parse 30-65ms，
   * 会卡住该请求。起服后（listen 回调）后台预热一次，把成本移到请求路径之外。
   * 返回预热总耗时（毫秒）供日志观测；可重复调用（getter 已缓存，二次调用零成本）。
   */
  async warmupLazyTables(): Promise<number> {
    const t0 = Date.now();
    // 依次触碰所有懒加载 getter（同步 readJsonSync + parse）
    void this.HandbookInfoTable;
    void this.CharWordTable;
    void this.EnemyDatabase;
    void this.EnemyHandbookLevelInfoTable;
    void this.EnemyHandbookRaceTable;
    void this.HandbookTeamTable;
    void this.SkillDataBundle;
    return Date.now() - t0;
  }

  constructor() {}

  /**
   * 初始化所有 Excel 数据表
   *
   * 从 data/excel/ 目录下批量并行加载所有 JSON 格式的数据表文件
   * （Promise.all 并发读文件 + parse，避免串行 IO），并初始化商店数据。
   * 同一文件被多个 key 引用时先去重，仅读取/解析一次，各 key 共享同一对象引用。
   */
  async init(): Promise<void> {
    // 热重载（后台更新后再次 init）时先失效懒加载大表缓存，避免返回陈旧数据
    this.resetLazyTables();
    const loaders: [keyof Excel, string][] = [
      ["MissionTable", "./data/excel/mission_table.json"],
      ["BattleEquipTable", "./data/excel/battle_equip_table.json"],
      ["BuildingData", "./data/excel/building_data.json"],
      ["CharacterTable", "./data/excel/character_table.json"],
      ["GameDataConst", "./data/excel/gamedata_const.json"],
      ["ItemTable", "./data/excel/item_table.json"],
      ["StageTable", "./data/excel/stage_table.json"],
      ["CheckinTable", "./data/excel/checkin_table.json"],
      ["StoryReviewMetaTable", "./data/excel/story_review_meta_table.json"],
      ["GachaTable", "./data/excel/gacha_table.json"],
      ["RoguelikeTopicTable", "./data/excel/roguelike_topic_table.json"],
      ["UniequipTable", "./data/excel/uniequip_table.json"],
      ["FavorTable", "./data/excel/favor_table.json"],
      ["StoryReviewTable", "./data/excel/story_review_table.json"],
      ["MedalTable", "./data/excel/medal_table.json"],
      ["CharMetaTable", "./data/excel/char_meta_table.json"],
      ["SkinTable", "./data/excel/skin_table.json"],
      ["OpenServerTable", "./data/excel/open_server_table.json"],
      ["RetroTable", "./data/excel/retro_table.json"],
      ["GachaDetailTable", "./data/gacha_detail_table.json"],
      ["ActivityTable", "./data/excel/activity_table.json"],
      ["CampaignTable", "./data/excel/campaign_table.json"],
      ["ChapterTable", "./data/excel/chapter_table.json"],
      ["CharMasterTable", "./data/excel/char_master_table.json"],
      ["CharPatchTable", "./data/excel/char_patch_table.json"],
      ["CharmTable", "./data/excel/charm_table.json"],
      ["ClimbTowerTable", "./data/excel/climb_tower_table.json"],
      ["CrisisTable", "./data/excel/crisis_table.json"],
      ["CrisisV2SharedData", "./data/excel/crisis_v2_table.json"],
      ["DisplayMetaTable", "./data/excel/display_meta_table.json"],
      ["EpBreakBuffData", "./data/excel/ep_breakbuff_table.json"],
      ["ExtraBattleLogData", "./data/excel/extra_battlelog_table.json"],
      ["HotUpdateMetaTable", "./data/excel/hotupdate_meta_table.json"],
      ["MetaUIDisplayTable", "./data/excel/meta_ui_table.json"],
      ["PlayerAvatarTable", "./data/excel/player_avatar_table.json"],
      ["RangeTable", "./data/excel/range_table.json"],
      ["ReplicateTable", "./data/excel/replicate_table.json"],
      ["RoguelikeActivityTable", "./data/excel/roguelike_table.json"],
      ["SandboxActTable", "./data/excel/sandbox_table.json"],
      ["SandboxPermTable", "./data/excel/sandbox_perm_table.json"],
      ["SandboxTable", "./data/excel/sandbox_table.json"],
      ["ShopClientTable", "./data/excel/shop_client_table.json"],
      ["SpecialOperatorTable", "./data/excel/special_operator_table.json"],
      ["StoryData", "./data/excel/story_table.json"],
      ["UniEquipData", "./data/excel/uniequip_data.json"],
      ["ZoneTable", "./data/excel/zone_table.json"],
      ["ArkventTable", "./data/excel/arkvent_table.json"],
    ];

    // 去重后的唯一路径：同一文件被多个 key 引用时只读取/解析一次，
    // 各 key 共享同一对象引用（只读数据表，共享安全）。
    const uniquePaths = [...new Set(loaders.map(([, path]) => path))];
    const results = await Promise.all(uniquePaths.map((path) => readJson(path)));
    const byPath = new Map<string, object>();
    uniquePaths.forEach((path, i) => {
      byPath.set(path, results[i]);
    });
    loaders.forEach(([key, path]) => {
      (this as any)[key] = byPath.get(path);
    });

    // RoguelikeConsts 不再从 data/rlv2.json 读取：由官方 RoguelikeTopicTable 派生
    // （outbuff/recruitGrps 直接来自官方 excel，modebuff 内嵌常量，见 roguelike_consts_gen）
    this.RoguelikeConsts = buildRoguelikeConsts(this.RoguelikeTopicTable);

    // 归一化掉落信息（occPercent/dropType 字符串 → 数字档位，供 dropReward 使用）
    normalizeStageDropInfo(this.StageTable);

    logger.info("Excel", `${loaders.length} excels loaded`);
    this.ShopTable = new ShopData();
    await this.ShopTable.init();
    logger.info("Excel", "10 shops loaded");
  }
}

/** Excel 数据表管理实例（具名供同文件合并工具引用；默认导出保持） */
const excel = new Excel();
export default excel;


export interface GachaDetailTable {
    details: { [key: string]: GachaDetailData} 
}

export interface GachaDetailData {
    gachaObjGroups: GachaObjGroup[] | null
    availCharInfo: GachaAvailChar
    upCharInfo: GachaUpChar | null
    limitedChar: string[] | null
    weightUpCharInfoList: GachaWeightUpChar[] | null
    gachaObjList: GachaObject[]
}

export interface GachaAvailChar {
    perAvailList: GachaPerAvail[]
}

export interface GachaPerAvail {
    rarityRank: number
    charIdList: string[]
    totalPercent: number
}

export interface GachaObjGroup {
    groupType: number
    startIndex: number
    endIndex: number
}

export interface GachaObject {
    gachaObject: string
    type: number
    imageType: number
    param: null | string
}

export interface GachaUpChar {
    perCharList: GachaPerChar[]
}

export interface GachaPerChar {
    rarityRank: number
    charIdList: string[]
    percent: number
    count: number
}

export interface GachaWeightUpChar {
    rarityRank: number
    charId: string
    weight: number
}

// ===== character_table.ts（合并）=====
export interface KeyFrame<TInput, TOutput> {
    level: number
    data: TInput
}
export type KeyFrames<TData> = KeyFrame<TData, TData>[]
export interface CharacterTable {
    [key: string]: CharacterData
}
export interface SkillLevelCost {
    unlockCond: UnlockCondition;
    lvlUpCost: ItemBundle[] | null;
}

export interface UnlockCondition {
    phase: string|number;
    level: number;
}

export interface AttributesData {
    maxHp: number;
    atk: number;
    def: number;
    magicResistance: number;
    cost: number;
    blockCnt: number;
    moveSpeed: number;
    attackSpeed: number;
    baseAttackTime: number;
    respawnTime: number;
    hpRecoveryPerSec: number;
    spRecoveryPerSec: number;
    maxDeployCount: number;
    maxDeckStackCnt: number;
    tauntLevel: number;
    massLevel: number;
    baseForceLevel: number;
    stunImmune: boolean;
    silenceImmune: boolean;
    sleepImmune: boolean;
    frozenImmune: boolean;
    levitateImmune: boolean;
    disarmedCombatImmune: boolean;
}

export interface PhaseData {
    characterPrefabKey: string;
    rangeId: null | string;
    maxLevel: number;
    attributesKeyFrames: KeyFrames<AttributesData>;
    evolveCost: ItemBundle[] | null;
}

export enum BuildableType {
    None = "NONE",
    Melee = "MELEE",
    Ranged = "RANGED",
    All = "ALL",
}

export interface PotentialRank {
    type: PotentialRankType;
    description: string;
    buff: ExternalBuff | null;
    equivalentCost: null;
}

export interface Attributes {
    abnormalFlags: null;
    abnormalImmunes: null;
    abnormalAntis: null;
    abnormalCombos: null;
    abnormalComboImmunes: null;
    attributeModifiers: AttributeModifier[];

}

export interface AttributeModifier {
    attributeType: AttributeType;
    formulaItem: string;
    value: number;
    loadFromBlackboard: boolean;
    fetchBaseValueFromSourceEntity: boolean;
}

export enum AttributeType {
    Atk = "ATK",
    AttackSpeed = "ATTACK_SPEED",
    Cost = "COST",
    Def = "DEF",
    MagicResistance = "MAGIC_RESISTANCE",
    MaxHP = "MAX_HP",
    RespawnTime = "RESPAWN_TIME",
}

export enum PotentialRankType {
    Buff = "BUFF",
    Custom = "CUSTOM",
}

export enum ProfessionCategory {
    Caster = "CASTER",
    Medic = "MEDIC",
    Pioneer = "PIONEER",
    Sniper = "SNIPER",
    Special = "SPECIAL",
    Support = "SUPPORT",
    Tank = "TANK",
    Token = "TOKEN",
    Trap = "TRAP",
    Warrior = "WARRIOR",
}

export enum RarityRank {
    Tier1 = "TIER_1",
    Tier2 = "TIER_2",
    Tier3 = "TIER_3",
    Tier4 = "TIER_4",
    Tier5 = "TIER_5",
    Tier6 = "TIER_6",
}

export interface MainSkill {
    skillId: null | string;
    overridePrefabKey: null | string;
    overrideTokenKey: null | string;
    levelUpCostCond: SpecializeLevelData[];
    unlockCond: UnlockCondition;
}

export interface SpecializeLevelData {
    unlockCond: UnlockCondition;
    lvlUpTime: number;
    levelUpCost: ItemBundle[] | null;
}

export interface EquipTalentDataBundle extends TalentDataBundle {
    candidates: EquipTalentData[] | null;
}
export interface TalentDataBundle {
    candidates: TalentData[] | null;
}

export interface BlackboardDataPair {
    key: string;
    value?: number;
    valueStr?: null | string;
}

export interface TraitDataBundle {
    candidates: TraitData[];
}

export interface TraitData {
    unlockCondition: UnlockCondition;
    requiredPotentialRank: number;
    blackboard: Blackboard;
    overrideDescripton: null | string;
    prefabKey: null | string;
    rangeId: null | string;
}
export interface EquipTraitDataBundle {
    candidates: EquipTraitData[]|null;
}

export interface EquipTraitData extends TraitData {
    additionalDescription: string;
}

// ===== item_table.ts（合并）=====
export type ItemTable = ServerItemTable;
export interface ServerItemTable {
  items: { [key: string]: ItemData };
  expItems: { [key: string]: ExpItemFeature };
  potentialItems: { [key: string]: { [key: string]: string } };
  apSupplies: { [key: string]: ApSupplyFeature };
  charVoucherItems: { [key: string]: CharVoucherItem };
  uniqueInfo: { [key: string]: number };
  itemTimeLimit: { [key: string]: number };
  uniCollectionInfo: { [key: string]: UniCollectionInfo };
  itemPackInfos: { [key: string]: ItemPackInfo };
  fullPotentialCharacters: { [key: string]: FullPotentialCharacterInfo };
  activityPotentialCharacters: {
    [key: string]: ActivityPotentialCharacterInfo;
  };
  favorCharacters: { [key: string]: FavorCharacterInfo };
}

export interface CharVoucherItem {
  id: string;
  displayType: string; //DisplayType;
}

export type DisplayType = "NONE" | "DIVIDE";

export namespace ItemData {
  export interface BuildingProductInfo {
    roomType: string; //BuildingData.RoomType
    formulaId: string;
  }

  export interface VoucherRelateInfo {
    voucherId: string;
    voucherItemType: string; //ItemType
  }

  export interface StageDropInfo {
    stageId: string;
    occPer: string; //OccPer;
  }
}

export interface PeriodInfo {
    missionGroupId: string;
    rewardGroupId:  string;
    period:         number[];
}


export interface ReturnV2PackageCheckInRewardData {
    groupId:            string;
    startTime:          number;
    endTime:            number;
    getTime:           number;
    bindGPGoodId:       string;
    iconId:             string;
    totalCheckInDay:    number;
    rewardDict:        { [key: string]: ReturnV2ItemData[] };
}
export interface ReturnV2ItemData extends ItemBundle{
    sortId: number;
}

export interface ReturnCheckinData {
    isImportant:        boolean;
    checkinRewardItems: ItemBundle[];
}

export interface ReturnConst {
    startTime:        number;
    systemTab_time:   number;
    afkDays:          number;
    unlockLv:         number;
    unlockLevel:      string;
    juniorClear:      boolean;
    ifvisitor:        boolean;
    permMission_time: number;
    needPoints:       number;
    defaultIntro:     string;
    pointId:          string;
}

export interface ReturnIntroData {
    sort:    number;
    pubTime: number;
    image:   string;
}

export interface ReturnDailyTaskData {
    groupId:     string;
    id:          string;
    groupSortId: number;
    taskSortId:  number;
    template:    string;
    param:       string[];
    desc:        string;
    rewards:     ItemBundle[];
    playPoint:   number;
}

export interface ReturnLongTermTaskData {
    id:        string;
    sortId:    number;
    template:  string;
    param:     string[];
    desc:      string;
    rewards:   ItemBundle[];
    playPoint: number;
}

export interface ReturnV2Data {
    constData:                ReturnV2Const;
    onceRewardData:           ReturnV2OnceRewardData[];
    checkInRewardData:        ReturnV2CheckInRewardData[];
    priceRewardData:          ReturnV2PriceRewardGroupData[];
    missionGroupData:         ReturnV2MissionGroupData[];
    dailySupplyData:          ReturnV2DailySupplyData[];
    packageCheckInRewardData: ReturnV2PackageCheckInRewardData[];
}

export interface ReturnV2CheckInRewardData {
    groupId:      string;
    startTime:    number;
    endTime:      number;
    rewardList:  ReturnV2CheckInRewardItemData[];
}
export interface ReturnV2PriceRewardGroupData {
    groupId:      string;
    startTime:    number;
    endTime:      number;
    contentList: ReturnV2PriceRewardData[];
}
export interface ReturnV2PriceRewardData {
    contentId:    string;
    sortId:       number;
    pointRequire: number;
    desc:         string;
    iconId:       string;
    topIconId:    string;
    rewardList:   ReturnV2ItemData[];
}

export interface ReturnV2CheckInRewardItemData {
    sortId:      number;
    isImportant: boolean;
    rewardList:  ItemBundle[];
}

export interface ReturnV2Const {
    startTime:       number;
    unlockLv:        number;
    unlockStage:     string;
    permMissionTime: number;
    pointId:         string;
    returnPriceDesc: string;
    dailySupplyDesc: string;
}

export interface ReturnV2OnceRewardData {
    groupId:    string;
    startTime:  number;
    endTime:    number;
    rewardList: ReturnV2ItemData[];
}
export interface ReturnV2DailySupplyData {
    groupId:    string;
    startTime:  number;
    endTime:    number;
    rewardList: ItemBundle[];
}
export interface ReturnV2MissionGroupData {
    groupId:          string;
    sortId:           number;
    tabTitle:         string;
    title:            string;
    desc:             string;
    diffMissionCount: number;
    startTime:        number;
    endTime:          number;
    imageId:          string;
    iconId:           string;
    missionList:      ReturnV2MissionItemData[];
}

export interface ReturnV2MissionItemData {
    missionId:  string;
    groupId:    string;
    sortId:     number;
    jumpType:   string;
    jumpParam:  null | string;
    desc:       string;
    rewardList: ItemBundle[];
}
export class ShopData {
  lowGoodList!: LowGoodList;
  skinGoodList!: SkinGoodList;
  cashGoodList!: CashGoodList;
  highGoodList!: HighGoodList;
  REPGoodList!: REPGoodList;
  LMTGSGoodList!: LMTGSGoodList;
  EPGSGoodList!: EPGSGoodList;
  classicGoodList!: ClassicGoodList;
  extraGoodList!: ExtraGoodList;
  GPGoodList!: GPGoodList;
  furniGoodList!: FurniGoodList;

  constructor() {}

  async init(): Promise<void> {
    this.lowGoodList = await readJson<LowGoodList>(
      "./data/shop/LowGoodList.json",
    );
    this.skinGoodList = await readJson<SkinGoodList>(
      "./data/shop/SkinGoodList.json",
    );
    this.cashGoodList = await readJson<CashGoodList>(
      "./data/shop/CashGoodList.json",
    );
    this.highGoodList = await readJson<HighGoodList>(
      "./data/shop/HighGoodList.json",
    );
    this.REPGoodList = await readJson<REPGoodList>(
      "./data/shop/RepGoodList.json",
    );
    this.LMTGSGoodList = await readJson<LMTGSGoodList>(
      "./data/shop/LMTGSGoodList.json",
    );
    this.EPGSGoodList = await readJson<EPGSGoodList>(
      "./data/shop/EPGSGoodList.json",
    );
    this.classicGoodList = await readJson<ClassicGoodList>(
      "./data/shop/ClassicGoodList.json",
    );
    this.extraGoodList = await readJson<ExtraGoodList>(
      "./data/shop/ExtraGoodList.json",
    );
    this.GPGoodList = await readJson<GPGoodList>("./data/shop/GPGoodList.json");
    this.furniGoodList = await readJson<FurniGoodList>(
      "./data/shop/FurniGoodList.json",
    );
  }
}

export interface QCObject {
  goodId: string;
  item: ItemBundle;
  progressGoodId: string;
  displayName: string;
  slotId: number;
  originPrice: number;
  price: number;
  availCount: number;
  discount: number;
  priority: number;
  number: number;
  groupId: string;
  goodStartTime: number;
  goodEndTime: number;
  goodType: string;
}

export interface LowGoodList {
  goodList: QCObject[];
  groups: string[];
  shopEndTime: number;
  newFlag: string[];
}

export interface SkinGoodList {
  goodList: ShopSkinItemViewModel[];
}

export interface ShopSkinItemViewModel {
  goodId: string;
  skinId: string;
  skinName: string;
  charId: string;
  currencyUnit: string;
  originPrice: number;
  price: number;
  discount: number;
  desc1: null | string;
  desc2: null | string;
  startDateTime: number;
  endDateTime: number;
  slotId: number;
  isRedeem: boolean;
}

export interface CashGoodList {
  goodList: CashShopObject[];
}

export interface CashShopObject {
  goodId: string;
  slotId: number;
  price: number;
  diamondNum: number;
  doubleCount: number;
  plusNum: number;
  desc: string;
}

export interface HighGoodList {
  goodList: QCObject[];
  progressGoodList: { [key: string]: QCProgressGoodItem[] };
  newFlag: string[];
}

export interface QCProgressGoodItem {
  order: number;
  price: number;
  displayName: string;
  item: ItemBundle;
}

export interface ClassicGoodList {
  goodList: QCObject[];
  progressGoodList: { [key: string]: QCProgressGoodItem[] };
  newFlag: string[];
}

export interface ExtraGoodList {
  goodList: ExtraQCObject[];
  lastClick: number;
  newFlag: string[];
}

export interface ExtraQCObject {
  goodId: string;
  item: ItemBundle;
  displayName: string;
  slotId: number;
  originPrice: number;
  price: number;
  availCount: number;
  discount: number;
  goodEndTime: number;
  shopType: string;
  newFlag: number;
}

export interface LMTGSGood {
  goodId: string;
  startTime: number;
  endTime: number;
  availCount: number;
  item: ItemBundle;
  price: ItemBundle;
  sortId: number;
}

export interface LMTGSGoodList {
  goodList: LMTGSGood[];
  newFlag: string[];
}

export interface EPGSGood {
  goodId: string;
  startTime: number;
  endTime: number;
  availCount: number;
  item: ItemBundle;
  price: number;
  sortId: number;
}

export interface EPGSGoodList {
  goodList: EPGSGood[];
  newFlag: string[];
}

export interface REPGood {
  goodId: string;
  startTime: number;
  endTime: number;
  availCount: number;
  item: ItemBundle;
  price: number;
  sortId: number;
}

export interface REPGoodList {
  goodList: REPGood[];
  newFlag: string[];
}

export interface SocialShopData {
  goodId: string;
  displayName: string;
  item: ItemBundle;
  price: number;
  availCount: number;
  slotItem: ShopSLot;
  discount: number;
  originPrice: number;
}

export interface ShopSLot {
  price: number;
  displayName: string;
  item: ItemBundle;
}

export interface SocialGoodList {
  goodList: SocialShopData[];
  /** 干员信物购买记录（charId → 已购信物数） */
  charPurchase: { [key: string]: number };
}

export interface MonthlySubItem extends NormalGPItem {
  cardId: string;
  dailyBonus: ItemBundle[];
  imgId: string;
  backId: string;
}

export interface LevelGPItem extends NormalGPItem {
  playerLevel: number;
}

export interface ChooseGPItem extends NormalGPItem {
  options: Array<ChooseGiftPackageShopOption>;
  desc: string;
  itemDisplayDesc: string;
  itemDisplayNum: number;
}

export interface ChooseGiftPackageShopOption {
  goodId: string;
  OptionId: string;
  orderNum: number;
  item: ItemBundle;
}

export interface NormalGPItem {
  goodId: string;
  giftPackageId: string;
  priority: number;
  displayName: string;
  currencyUnit: string;
  availCount: number;
  buyCount: number;
  price: number;
  originPrice: number;
  discount: number;
  items: ItemBundle[];
  specialItemInfos: Record<string, SpecialItemInfo>;
  startDateTime: number;
  endDateTime: number;
}

export interface SpecialItemInfo {
  showPreview: boolean;
  specialDesc: string;
  specialBtnText: string;
}

export interface PeriodicityGPItem extends NormalGPItem {
  groupId: string;
}

export interface PeriodicityGroup {
  groupId: string;
  startDateTime: number;
  endDateTime: number;
  packages: Record<string, PeriodicityGPItem>;
}

export interface CondTrigGPItem extends NormalGPItem {
  type: string;
}

export interface GPGoodList {
  weeklyGroup: PeriodicityGroup;
  monthlyGroup: PeriodicityGroup;
  monthlySub: Array<MonthlySubItem>;
  levelGP: Array<LevelGPItem>;
  oneTimeGP: Array<NormalGPItem>;
  chooseGroup: Array<ChooseGPItem>;
  conditionTriggerGroup?: Array<CondTrigGPItem>;
}

export interface FurniGoodList {
  goods: FurniGood[];
  groups: FurniGroup[];
}

export interface FurniGood {
  goodId: string;
  furniId: string;
  shopDisplay: number;
  displayName: string;
  priceCoin: number;
  priceDia: number;
  discount: number;
  originPriceCoin: number;
  originPriceDia: number;
  end: number;
  count: number;
  sequence: number;
}

export interface FurniGroup {
  packageId: string;
  icon: string;
  name: string;
  description: string;
  sequence: number;
  saleBegin: number;
  saleEnd: number;
  decoration: number;
  goodList: FurniGoodData[];
  eventGoodList: EventGoodData[];
  imageList: ImageDisplayData[];
}

export interface EventGoodData {
  name: string;
  count: number;
  furniId: string;
  set: string;
  sequence: number;
}

export interface FurniGoodData {
  goodId: string;
  count: number;
  set: string;
  sequence: number;
}

export interface ImageDisplayData {
  picId: string;
  index: number;
}

// ===== stage_table.ts（合并）=====
export interface TimeRange {
  startTs: number;
  endTs: number;
}

export interface StageDropInfo {
  firstPassRewards: null;
  firstCompleteRewards: null;
  passRewards: null;
  completeRewards: null;
  displayRewards: DisplayRewards[];
  displayDetailRewards: DisplayDetailRewards[];
}

export interface DisplayRewards {
  type: string;
  id: string;
  dropType: StageDropType;
}
export interface DisplayDetailRewards {
  occPercent: number;
  type: string;
  id: string;
  dropType: number;
}
export enum StageDropType {
  Additional = "ADDITIONAL",
  Complete = "COMPLETE",
  Normal = "NORMAL",
  Once = "ONCE",
  OverrideDrop = "OVERRIDE_DROP",
  Special = "SPECIAL",
}

export enum OccPercent {
  Almost = "ALMOST",
  Always = "ALWAYS",
  Often = "OFTEN",
  Sometimes = "SOMETIMES",
  Usual = "USUAL",
}

/** occPercent 字符串 → 数字档位（对应 dropReward 概率语义：0=必定, 1=75%, 2=40%, 3=15%, 4=3%） */
export const OCC_PERCENT_NUMERIC: { [key: string]: number } = {
  [OccPercent.Always]: 0,
  [OccPercent.Usual]: 1,
  [OccPercent.Often]: 2,
  [OccPercent.Sometimes]: 3,
  [OccPercent.Almost]: 4,
};

/** dropType 字符串 → 数字（1=首通, 2=普通, 3=特殊, 4=额外, 8=完成/条件） */
export const DROP_TYPE_NUMERIC: { [key: string]: number } = {
  [StageDropType.Once]: 1,
  [StageDropType.Normal]: 2,
  [StageDropType.Special]: 3,
  [StageDropType.Additional]: 4,
  [StageDropType.Complete]: 8,
  CONDITION_DROP: 8,
};

/**
 * 归一化掉落信息：将 displayDetailRewards 的 occPercent/dropType 从字符串映射为数字档位。
 * 原始 excel 数据为字符串（ALWAYS/NORMAL 等），dropReward 逻辑按数字档位判断。
 * 已在 excel 加载时调用（excel.init），幂等（数字值保持不变）。
 * @param table - StageTable 结构（stages 字段）
 */
export function normalizeStageDropInfo(table: {
  stages: { [key: string]: { stageDropInfo?: { displayDetailRewards?: any[] } | null } };
}): void {
  for (const stage of Object.values(table.stages)) {
    const drops = stage?.stageDropInfo?.displayDetailRewards;
    if (!drops) continue;
    for (const item of drops) {
      if (typeof item.occPercent === "string") {
        item.occPercent = OCC_PERCENT_NUMERIC[item.occPercent] ?? 0;
      } else if (item.occPercent === undefined || item.occPercent === null) {
        // 修复：无 occPercent 字段 = 必掉（官方协议缺省即 ALWAYS）——
        // 原实现保持 undefined，handleOccPercent 全部分支不匹配 → 必掉物品（1-7 糖等）
        // 从不发放
        item.occPercent = 0;
      }
      if (typeof item.dropType === "string") {
        item.dropType = DROP_TYPE_NUMERIC[item.dropType] ?? 2;
      }
    }
  }
}

export enum FogType {
  Stage = "STAGE",
  Zone = "ZONE",
}

export interface RequireChar {
  charId: string;
  evolvePhase: string;
}

export enum AppearanceStyle {
  HighDifficulty = "HIGH_DIFFICULTY",
  MainNormal = "MAIN_NORMAL",
  MainPredefined = "MAIN_PREDEFINED",
  MistOps = "MIST_OPS",
  SpecialStory = "SPECIAL_STORY",
  Sub = "SUB",
  Training = "TRAINING",
}

export enum StageDiffGroup {
  All = "ALL",
  Easy = "EASY",
  None = "NONE",
  Normal = "NORMAL",
  Tough = "TOUGH",
}

export enum Difficulty {
  FourStar = "FOUR_STAR",
  Normal = "NORMAL",
}

export interface ExtraConditionDesc {
  index: number;
  template: string;
  unlockParam: string[];
}

export interface SpecialStoryInfo {
  stageId: string;
  rewards: ItemBundle[];
  progressInfo: SpecialProgressInfo;
  imageId: string;
}

export interface SpecialProgressInfo {
  progressType: string;
  descList: { [key: string]: string } | null;
}

export enum PerformanceStageFlag {
  NormalStage = "NORMAL_STAGE",
  PerformanceStage = "PERFORMANCE_STAGE",
}

export enum StageType {
  Activity = "ACTIVITY",
  Campaign = "CAMPAIGN",
  ClimbTower = "CLIMB_TOWER",
  Daily = "DAILY",
  Guide = "GUIDE",
  Main = "MAIN",
  SpecialStory = "SPECIAL_STORY",
  Sub = "SUB",
}

export interface ConditionDesc {
  stageId: string;
  completeState: number;
}

export enum PlayerBattleRank {
  Complete = "COMPLETE",
  Pass = "PASS",
}

export type {
  RoguelikeGridZoneModuleData,
  RoguelikeWeatherModuleData,
  RoguelikeScrapModuleData,
};

export namespace RoguelikeTopicConst{
    export interface PredefinedChar {
    charId:      string;
    canBeFree:   boolean;
    uniEquipId:  null | string;
    recruitType: string;
}
}


/**
 * 主题自定义数据（官方 customizeData）。
 * rogue_1..3 用各自的 developments 结构；rogue_4..6 统一走 commonDevelopment
 * （CustomizeDataCommon）——实测 data/excel/roguelike_topic_table.json 六主题全在，
 * 原类型仅声明 rogue_1..4 导致 rogue_5/6 访问必须 as any。
 */
export interface CustomizeData {
    rogue_1: CustomizeDataRogue1;
    rogue_2: CustomizeDataRogue2;
    rogue_3: CustomizeDataRogue3;
    rogue_4: CustomizeDataRogue4;
    rogue_5: CustomizeDataCommon;
    rogue_6: CustomizeDataCommon;
}

export interface CustomizeDataRogue1 {
    developments:      { [key: string]: Rogue1_Development };
    developmentTokens: { [key: string]: DevelopmentToken };
    endingText:        Rogue1_EndingText;
}

export interface DevelopmentToken {
    sortId:      number;
    displayForm: string;
    tokenDesc:   string;
}

export interface Rogue1_Development {
    buffId:          string;
    sortId:          number;
    nodeType:        string;
    nextNodeId:      string[];
    frontNodeId:     string[];
    tokenCost:       number;
    buffName:        string;
    buffIconId:      string;
    buffTypeName:    string;
    buffDisplayInfo: BuffDisplayInfo[];
}

export interface BuffDisplayInfo {
    displayType: string;
    displayNum:  number;
    displayForm: string;
    tokenDesc:   string;
    sortId:      number;
}

export interface Rogue1_EndingText {
    summaryVariation:        string;
    summaryDefeatBoss:       string;
    summaryAccidentMeet:     string;
    summaryCapsule:          string;
    summaryActiveTool:       string;
    summaryActor:            string;
    summaryTop:              string;
    summaryZone:             string;
    summaryEnding:           string;
    summaryDifficultyZone:   null;
    summaryDifficultyEnding: null;
    summaryMode:             string;
    summaryGroup:            string;
    summarySupport:          string;
    summaryNormalRecruit:    string;
    summaryDirectRecruit:    string;
    summaryFriendRecruit:    string;
    summaryFreeRecruit:      string;
    summaryMonthRecruit:     string;
    summaryUpgrade:          string;
    summaryCompleteEnding:   string;
    summaryEachZone:         string;
    summaryPerfectBattle:    string;
    summaryMeetBattle:       string;
    summaryMeetEvent:        string;
    summaryMeetShop:         string;
    summaryMeetTreasure:     string;
    summaryBuy:              string;
    summaryInvest:           string;
    summaryGet:              string;
    summaryRelic:            string;
    summarySafeHouse:        string;
    summaryFailEnd:          string;
}

export interface CustomizeDataRogue2 {
    developments:            { [key: string]: Rogue2_Development };
    developmentTokens:       { [key: string]: DevelopmentToken };
    developmentRawTextGroup: DevelopmentRawTextGroup[];
    developmentLines:        DevelopmentLine[];
    endingText:              Rogue2_EndingText;
}

export interface DevelopmentLine {
    fromNode:  string;
    toNode:    string;
    fromNodeP: number;
    fromNodeR: number;
    toNodeP:   number;
    toNodeR:   number;
    enrollId:  null | string;
}

export interface DevelopmentRawTextGroup {
    nodeIdList:    string[];
    useLevelMark?: boolean;
    groupIconId:   string;
    useUpBreak?:   boolean;
    sortId:        number;
}

export interface Rogue2_Development {
    buffId:          string;
    nodeType:        string;
    frontNodeId:     string[];
    nextNodeId:      string[];
    positionP:       number;
    positionR:       number;
    tokenCost:       number;
    buffName:        string;
    buffIconId:      string;
    effectType:      string;
    rawDesc:         string;
    buffDisplayInfo: BuffDisplayInfo[];
    enrollId:        null | string;
}

export interface Rogue2_EndingText {
    summaryMutation:            string;
    summaryDice:                string;
    summaryDiceResultGood:      string;
    summaryDiceResultNormal:    string;
    summaryDiceResultBad:       string;
    summaryDiceResultDesc:      string;
    summaryCommuDesc:           string;
    summaryHiddenDesc:          string;
    summaryKnightDesc:          string;
    summaryGoldDesc:            string;
    summaryPracticeDesc:        string;
    summaryCommuEmptyDesc:      string;
    summaryCommuNotEmptyDesc:   string;
    summaryHiddenPassedDesc:    string;
    summaryHiddenNotPassedDesc: string;
    summaryKnightPassedDesc:    string;
    summaryKnightNotPassedDesc: string;
    summaryGoldThreshold:       number;
    summaryGoldHighDesc:        string;
    summaryGoldLowDesc:         string;
    summaryPracticeThreshold:   number;
    summaryPracticeHighDesc:    string;
    summaryPracticeLowDesc:     string;
}

export interface CustomizeDataRogue3 {
    developments:                    { [key: string]: Rogue3_Development };
    developmentsTokens:              { [key: string]: DevelopmentToken };
    developmentRawTextGroup:         DevelopmentRawTextGroup[];
    developmentsDifficultyNodeInfos: Rogue3_DevelopmentsDifficultyNodeInfos;
    endingText:                      Rogue3_EndingText;
    difficulties:                    PurpleDifficulty[];
}

export interface Rogue3_Development {
    buffId:          string;
    nodeType:        string;
    frontNodeId:     string[];
    nextNodeId:      string[];
    positionRow:     number;
    positionOrder:   number;
    tokenCost:       number;
    buffName:        string;
    buffIconId?:     string;
    effectType:      string;
    rawDesc:         string[];
    buffDisplayInfo: BuffDisplayInfo[];
    groupId:         string;
    enrollId:        null;
    activeIconId?:   string;
    inactiveIconId?: string;
    bottomIconId?:   string;
}

export interface Rogue3_DevelopmentsDifficultyNodeInfos {
    rogue_3_difficulty_1: Rogue3__Difficulty;
    rogue_3_difficulty_2: Rogue3__Difficulty;
    rogue_3_difficulty_3: Rogue3__Difficulty;
}

export interface Rogue3__Difficulty {
    buffId:      string;
    nodeMap:     Rogue3_Difficulty1_NodeMap[];
    enableGrade: number;
}

export interface Rogue3_Difficulty1_NodeMap {
    frontNode: string;
    nextNode:  string;
}

export interface PurpleDifficulty {
    modeDifficulty: string;
    grade:          number;
    totemProb:      number;
    relicDevLevel:  null | string;
    buffs:          string[] | null;
    buffDesc:       string[];
}

export interface Rogue3_EndingText {
    summaryGetTotem:         string;
    summaryDemoPointUp:      string;
    summaryDemoPointDown:    string;
    summaryDemoGradeUp:      string;
    summaryDemoGradeDown:    string;
    summaryVisionPointUp:    string;
    summaryVisionPointDown:  string;
    summaryVisionGradeUp:    string;
    summaryVisionGradeDown:  string;
    summaryMeetTrade:        string;
    summaryFightWin:         string;
    summaryFightFail:        string;
    summaryExchangeTotem:    string;
    summaryExchangeRelic:    string;
    summaryMeetSecretpath:   string;
    summaryUseTotem:         string;
    summaryVisionGrade:      string;
    summaryActor:            string;
    summaryTop:              string;
    summaryZone:             string;
    summaryEnding:           string;
    summaryDifficultyZone:   null;
    summaryDifficultyEnding: null;
    summaryMode:             string;
    summaryGroup:            string;
    summarySupport:          string;
    summaryNormalRecruit:    string;
    summaryDirectRecruit:    string;
    summaryFriendRecruit:    string;
    summaryFreeRecruit:      string;
    summaryMonthRecruit:     string;
    summaryUpgrade:          string;
    summaryCompleteEnding:   string;
    summaryEachZone:         string;
    summaryPerfectBattle:    string;
    summaryMeetBattle:       string;
    summaryMeetEvent:        string;
    summaryMeetShop:         string;
    summaryMeetTreasure:     string;
    summaryBuy:              string;
    summaryInvest:           string;
    summaryGet:              string;
    summaryRelic:            string;
    summarySafeHouse:        string;
    summaryFailEnd:          string;
}

export interface CustomizeDataRogue4 {
    commonDevelopment: CommonDevelopment;
    difficulties:      FluffyDifficulty[];
    endingText:        { [key: string]: string };
}

/**
 * rogue_4..6 共用的 customizeData 结构（commonDevelopment + difficulties + endingText）。
 * rogue_5 另有 specialShopDialog、rogue_6 另有 scrapShopDialogData/employShopDialogData
 * （商店对话文本，纯客户端展示）——以可选键描述，服务端不消费。
 */
export interface CustomizeDataCommon {
    commonDevelopment:      CommonDevelopment;
    difficulties:           FluffyDifficulty[];
    endingText:             { [key: string]: string };
    specialShopDialog?:     { [key: string]: unknown };
    scrapShopDialogData?:   { [key: string]: unknown };
    employShopDialogData?:  { [key: string]: unknown };
}

export interface CommonDevelopment {
    developments:                    { [key: string]: Rogue3_Development };
    developmentsTokens:              { [key: string]: DevelopmentToken };
    developmentRawTextGroup:         DevelopmentRawTextGroup[];
    developmentsDifficultyNodeInfos: CommonDevelopmentDevelopmentsDifficultyNodeInfos;
}

export interface CommonDevelopmentDevelopmentsDifficultyNodeInfos {
    rogue_4_difficulty_1: Rogue4__Difficulty;
    rogue_4_difficulty_2: Rogue4__Difficulty;
    rogue_4_difficulty_3: Rogue4__Difficulty;
}

export interface Rogue4__Difficulty {
    buffId:      string;
    nodeMap:     Rogue4_Difficulty1_NodeMap[];
    enableGrade: number;
    enableDesc:  string;
    lightId:     string;
    decoId:      null;
}

export interface Rogue4_Difficulty1_NodeMap {
    frontNodes: string[];
    nextNode:   string;
}

export interface FluffyDifficulty {
    modeDifficulty:        string;
    grade:                 number;
    leftDisasterDesc:      string;
    leftOverweightDesc:    string;
    relicDevLevel:         string;
    weightStatusLimitDesc: string;
    buffs:                 string[] | null;
    buffDesc:              string[];
}

export interface BandRef {
}

export interface DisplayData {
    type:                          string;
    costHintType:                  string;
    effectHintType:                string;
    funcIconId:                    null | string;
    itemId:                        null | string;
    difficultyUpgradeRelicGroupId: null;
    taskId:                        null;
}

export interface CharUpgradeData {
    evolvePhase:          string;
    skillLevel:           number;
    skillSpecializeLevel: number;
}

export interface PlayerLevelData {
    exp:               number;
    populationUp:      number;
    squadCapacityUp:   number;
    battleCharLimitUp: number;
    maxHpUp:           number;
}

export interface RuleDescReplacement {
    enrollId: string;
    ruleDesc: string;
}

export interface LevelIcon {
    level:  number;
    iconId: string;
}

export interface CheckCharBoxParam {
    valueProfessionMask: string;
    valueStrs:           string[] | null;
    valueInt:            number;
}

export interface PredefinedPlayerLevelData {
    levels: { [key: string]: PlayerLevelData };
}

export interface VisionChoiceConfig {
    value: number;
    type:  string;
}

export interface HomeEntryDisplayData {
    topicId:   string;
    displayId: string;
    startTs:   number;
    endTs:     number;
}


export interface RoguelikeConst {
  outbuff: { [key: string]: RoguelikeBuff[] };
  modebuff: { [key: string]: RoguelikeBuff[] };
  recruitGrps: { [key: string]: string[] };
}

// ===== excel-types.ts（合并）=====
/**
 * Excel 防腐层（业务层类型入口）
 *
 * 职责：作为业务层接触「由官方热更管线重新生成的权威类型」的唯一入口，
 * 业务代码不得直接 `import ... from "@excel/types_excel_gen"`（由架构守卫强制）。
 *
 * 收益：生成文件若发生类型改名/移动，只需在此处同步 re-export，业务层零感知，
 * 把「生成 schema 变更 → 波及全部业务文件」收敛为「仅波及本 seam」。
 * 采用 `export type` 保持与生成类型完全一致（不引入形状漂移）。
 *
 * 官方生成文件见 `scripts/generate-types.ts`（AGENTS.md 标注「never hand-edit」，
 * 本 seam 是对其的业务侧唯一可编辑入口）。
 */
export type { GachaPoolClientData } from "./types_excel_gen";
export type { UniEquipData } from "./types_excel_gen";
export type { MailArchiveItemData } from "./types_excel_gen";
export type { MissionData } from "./types_excel_gen";
export type { Act44SideData } from "./types_excel_gen";
export type {
  ActivityBossRushData,
  ActivityBossRushData_RelicLevelInfo,
} from "./types_excel_gen";




import { getManufactFormula, getWorkshopFormula, getRoomPhase, getGoldRate, getManufactPhase, getDormPhase, getBuildingConstant, getFurnitureInfo, getFurnitureThemeId, getRoomMaxLevel, getWorkshopFormulaType, getManufactFormulaType, getRoomElectricity, getClueExpiredDays, getMessageLeaveBoardConst, getMeetingPhase, getHirePhase } from "./building_excel";

// 生成类型 re-export（防腐层：业务经 @excel/excel 取类型，不直连 gen）
export {
  ChapterData,
  Blackboard,
  RoguelikeBuff,
  CharacterData,
  ItemBundle,
  ExternalBuff,
  EquipTalentData,
  TalentData,
  ActivityPotentialCharacterInfo,
  ApSupplyFeature,
  ExpItemFeature,
  FavorCharacterInfo,
  FullPotentialCharacterInfo,
  ItemPackInfo,
  ItemData,
  ItemClassifyType,
  ItemRarity,
  OccPer,
  UniCollectionInfo,
  MissionTable,
  CrossAppShareMissionConst,
  CrossAppShareMission,
  DailyMissionGroupInfo,
  MissionGroup,
  MissionDailyRewardConf,
  MissionWeeklyRewardConf,
  OpenServerSchedule,
  OpenServerConst,
  OpenServerData,
  TotalCheckinData,
  ChainLoginData,
  OpenServerItemData,
  NewbieCheckInPackageData,
  NewbieCheckInPackageRewardData,
  ReturnData,
  OpenServerScheduleItem,
  StageTable,
  ActCustomStageData,
  ApProtectZoneInfo,
  StageValidInfo,
  StageDiffGroupTable,
  WeeklyForceOpenTable,
  MapThemeData,
  OverrideDropInfo,
  SpecialBattleFinishStageData,
  StageFogInfo,
  StageStartCond,
  StageData,
  StoryStageShowGroup,
  TileAppendInfo,
  TimelyDropTimeInfo,
  TimelyDropInfo,
  OverrideUnlockInfo,
  RoguelikeTopicTable,
  RoguelikeTopicConst,
  RoguelikeTopicDetail,
  RoguelikeArchiveComponentData,
  ActArchiveBuffData,
  ActArchiveCapsuleData,
  ActArchiveCapsuleItemData,
  ActArchiveChatData,
  ActArchiveChatGroupData,
  ActArchiveChatItemData,
  ActArchiveEndbookData,
  ActArchiveRelicData,
  ActArchiveRelicItemData,
  ActArchiveTrapData,
  ActArchiveTrapItemData,
  RoguelikeArchiveUnlockCondData,
  RoguelikeArchiveEnroll,
  RoguelikeArchiveUnlockCondDesc,
  RoguelikeTopicBankReward,
  TipData,
  RoguelikeBattleSummeryDescriptionData,
  RoguelikeTopicCapsule,
  RoguelikeTopicChallenge,
  RoguelikeTopicChallengeTask,
  RoguelikeGameChoiceSceneData,
  RoguelikeGameChoiceData,
  RoguelikeTopicDetailConst,
  RoguelikeTopicDifficulty,
  RoguelikeEndingDetailText,
  RoguelikeGameEndingData,
  RoguelikeTopicEnroll,
  RoguelikeGameConst,
  RoguelikeTopicBPGrandPrize,
  RoguelikeGameInitData,
  RoguelikeGameItemData,
  RoguelikeTopicMilestoneUpdateData,
  RoguelikeTopicBP,
  RoguelikeTopicMonthMission,
  RoguelikeTopicMonthSquad,
  RoguelikeGameNodeTypeData,
  RoguelikeGameRecruitGrpData,
  RoguelikeGameRecruitTicketData,
  RoguelikeGameRelicParamData,
  RoguelikeGameRelicData,
  RoguelikeGameShopDialogData,
  RoguelikeGameShopDialogTypeData,
  RoguelikeGameShopDialogGroupData,
  RoguelikeGameStageData,
  RoguelikePredefinedConstStyleData,
  RoguelikeGameTrapData,
  RoguelikeGameExploreToolData,
  RoguelikeTopicUpdate,
  RoguelikeGameUpgradeTicketData,
  RoguelikeGameVariationData,
  RoguelikeGameCharBuffData,
  RoguelikeGameSquadBuffData,
  RoguelikeGameZoneData,
  ActArchiveBuffItemData,
  ActArchiveEndbookGroupData,
  ActArchiveEndbookItemData,
  RoguelikeBandRefData,
  RoguelikeGameCustomTicketData,
  RoguelikeTaskData,
  RoguelikeGameTreasureData,
  ActArchiveChaosData,
  ActArchiveChaosItemData,
  ActArchiveTotemData,
  ActArchiveTotemItemData,
  RoguelikeDifficultyUpgradeRelicGroupData,
  RoguelikeDifficultyUpgradeRelicData,
  RoguelikePredefinedStyleData,
  RoguelikeGameNodeSubTypeData,
  ActArchiveDisasterData,
  ActArchiveDisasterItemData,
  ActArchiveFragmentData,
  ActArchiveFragmentItemData,
  RoguelikeEndingRelicDetailText,
  RoguelikeRollNodeData,
  RoguelikeRollNodeGroupData,
  RoguelikeModule,
  RoguelikeChaosModuleData,
  RoguelikeChaosData,
  RoguelikeChaosRangeData,
  RoguelikeChaosPredefineLevelInfo,
  RoguelikeChaosModuleConsts,
  RoguelikeDiceModuleData,
  RoguelikeDiceData,
  RoguelikeDiceRuleData,
  RoguelikeDicePredefineData,
  RoguelikeDiceRuleGroupData,
  RoguelikeDisasterModuleData,
  RoguelikeDisasterData,
  RoguelikeFragmentModuleData,
  RoguelikeAlchemyData,
  RoguelikeAlchemyFormulationData,
  RoguelikeFragmentBuffData,
  RoguelikeFragmentData,
  RoguelikeFragmentLevelRelatedData,
  RoguelikeFragmentTypeData,
  RoguelikeFragmentModuleConsts,
  RoguelikeNodeUpgradeModuleData,
  RoguelikeNodeUpgradeData,
  RoguelikePermNodeUpgradeItemData,
  RoguelikeTempNodeUpgradeItemData,
  RoguelikeSanCheckModuleData,
  RoguelikeSanCheckConsts,
  RoguelikeSanRangeData,
  RoguelikeTotemBuffModuleData,
  RoguelikeTotemModuleConsts,
  RoguelikeTotemSubBuffData,
  RoguelikeTotemBuffData,
  RoguelikeTotemLinkedNodeTypeData,
  RoguelikeVisionModuleData,
  RoguelikeVisionModuleConsts,
  RoguelikeVisionData,
  RoguelikeTopicBasicData,
  RoguelikeTopicConfig,
  ItemType,
} from "./types_excel_gen";