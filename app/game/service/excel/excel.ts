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
} from "./types_excel_gen";


import { buildRoguelikeConsts } from "./roguelike_consts_gen";






export type ChapterData = any;

/**
 * Excel 数据表管理类
 * 
 * 聚合所有游戏配置数据表，提供统一的访问接口。
 */
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
export type Blackboard = BlackboardDataPair[];

/**
 * 肉鸽 buff（复用 CS 反编译的 buff 结构）
 *
 * 定义于 excel 数据层（而非 game 业务层），供 excel 表类型使用，
 * 避免 excel → game 的反向依赖；game 侧再从本处 re-export 复用。
 */
export interface RoguelikeBuff {
    key: string
    blackboard: Blackboard
}

export interface CharacterTable {
    [key: string]: CharacterData
}
export interface CharacterData {
  name: string;
  description: null | string;
  canUseGeneralPotentialItem: boolean;
  canUseActivityPotentialItem: boolean;
  potentialItemId: null | string;
  activityPotentialItemId: null | string;
  classicPotentialItemId: null | string;
  nationId: null | string;
  groupId: null | string;
  teamId: null | string;
  displayNumber: null | string;
  appellation: string;
  position: BuildableType;
  tagList: string[] | null;
  itemUsage: null | string;
  itemDesc: null | string;
  itemObtainApproach: string | null;
  isNotObtainable: boolean;
  isSpChar: boolean;
  maxPotentialLevel: number;
  rarity: number; //RarityRank;
  profession: ProfessionCategory;
  subProfessionId: string;
  trait: TraitDataBundle | null;
  phases: PhaseData[];
  skills: MainSkill[];
  displayTokenDict: { [key: string]: boolean } | null;
  talents: TalentDataBundle[] | null;
  potentialRanks: PotentialRank[];
  favorKeyFrames: KeyFrames<AttributesData> | null;
  allSkillLvlup: SkillLevelCost[];
}

export interface SkillLevelCost {
    unlockCond: UnlockCondition;
    lvlUpCost: ItemBundle[] | null;
}

export interface ItemBundle {
    id: string;
    count: number;
    type?: string;
    instId?: number;
}
export enum ItemType {
    NONE = 0,
    CHAR = 1,
    CARD_EXP = 2,
    MATERIAL = 3,
    GOLD = 4,
    EXP_PLAYER = 5,
    TKT_TRY = 6,
    TKT_RECRUIT = 7,
    TKT_INST_FIN = 8,
    TKT_GACHA = 9,
    ACTIVITY_COIN = 10,
    DIAMOND = 11,
    DIAMOND_SHD = 12,
    HGG_SHD = 13,
    LGG_SHD = 14,
    FURN = 15,
    AP_GAMEPLAY = 16,
    AP_BASE = 17,
    SOCIAL_PT = 18,
    CHAR_SKIN = 19,
    TKT_GACHA_10 = 20,
    TKT_GACHA_PRSV = 21,
    AP_ITEM = 22,
    AP_SUPPLY = 23,
    RENAMING_CARD = 24,
    RENAMING_CARD_2 = 25,
    ET_STAGE = 26,
    ACTIVITY_ITEM = 27,
    VOUCHER_PICK = 28,
    VOUCHER_CGACHA = 29,
    VOUCHER_MGACHA = 30,
    CRS_SHOP_COIN = 31,
    CRS_RUNE_COIN = 32,
    LMTGS_COIN = 33,
    EPGS_COIN = 34,
    LIMITED_TKT_GACHA_10 = 35,
    LIMITED_FREE_GACHA = 36,
    REP_COIN = 37,
    ROGUELIKE = 38,
    LINKAGE_TKT_GACHA_10 = 39,
    VOUCHER_ELITE_II_4 = 40,
    VOUCHER_ELITE_II_5 = 41,
    VOUCHER_ELITE_II_6 = 42,
    VOUCHER_SKIN = 43,
    RETRO_COIN = 44,
    PLAYER_AVATAR = 45,
    UNI_COLLECTION = 46,
    VOUCHER_FULL_POTENTIAL = 47,
    RL_COIN = 48,
    RETURN_CREDIT = 49,
    MEDAL = 50,
    CHARM = 51,
    HOME_BACKGROUND = 52,
    EXTERMINATION_AGENT = 53,
    OPTIONAL_VOUCHER_PICK = 54,
    ACT_CART_COMPONENT = 55,
    VOUCHER_LEVELMAX_6 = 56,
    VOUCHER_LEVELMAX_5 = 57,
    VOUCHER_LEVELMAX_4 = 58,
    VOUCHER_SKILL_SPECIALLEVELMAX_6 = 59,
    VOUCHER_SKILL_SPECIALLEVELMAX_5 = 60,
    VOUCHER_SKILL_SPECIALLEVELMAX_4 = 61,
    ACTIVITY_POTENTIAL = 62,
    ITEM_PACK = 63,
    SANDBOX = 64,
    FAVOR_ADD_ITEM = 65,
    CLASSIC_SHD = 66,
    CLASSIC_TKT_GACHA = 67,
    CLASSIC_TKT_GACHA_10 = 68,
    LIMITED_BUFF = 69,
    CLASSIC_FES_PICK_TIER_5 = 70,
    CLASSIC_FES_PICK_TIER_6 = 71,
    RETURN_PROGRESS = 72,
    NEW_PROGRESS = 73,
    MCARD_VOUCHER = 74,
    MATERIAL_ISSUE_VOUCHER = 75,
    CRS_SHOP_COIN_V2 = 76,
    HOME_THEME = 77,
    SANDBOX_PERM = 78,
    SANDBOX_TOKEN = 79,
    TEMPLATE_TRAP = 80,
    NAME_CARD_SKIN = 81,
    EXCLUSIVE_TKT_GACHA = 82,
    EXCLUSIVE_TKT_GACHA_10 = 83,
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

export interface ExternalBuff {
    attributes: Attributes;
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
export interface EquipTalentData extends TalentData {
    displayRangeId: boolean;
    talentIndex: number;
    upgradeDescription: string
}
export interface TalentDataBundle {
    candidates: TalentData[] | null;
}

export interface TalentData {
    unlockCondition: UnlockCondition;
    requiredPotentialRank: number;
    prefabKey: string;
    name: null | string;
    description: null | string;
    rangeId: null | string;
    blackboard: Blackboard;
    tokenKey?: null|string;
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

export interface ActivityPotentialCharacterInfo {
  charId: string;
}

export interface ApSupplyFeature {
  id: string;
  ap: number;
  hasTs: boolean;
}

export interface CharVoucherItem {
  id: string;
  displayType: string; //DisplayType;
}

export type DisplayType = "NONE" | "DIVIDE";

export interface ExpItemFeature {
  id: string;
  gainExp: number;
}

export interface FavorCharacterInfo {
  itemId: string;
  charId: string;
  favorAddAmt: number;
}

export interface FullPotentialCharacterInfo {
  itemId: string;
  ts: number;
}

export interface ItemPackInfo {
  packId: string;
  content: ItemBundle[];
}

export interface ItemData {
  itemId: string;
  name: string;
  description: null | string;
  rarity: number; //ItemRarity;
  iconId: string;
  overrideBkg: null | string;
  stackIconId: null | string;
  sortId: number;
  usage: null | string;
  obtainApproach: null | string;
  hideInItemGet: boolean;
  classifyType: string; //ItemClassifyType;
  itemType: string;
  stageDropList: ItemData.StageDropInfo[];
  buildingProductList: ItemData.BuildingProductInfo[];
  voucherRelateList: ItemData.VoucherRelateInfo[] | null;
}
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

export type ItemClassifyType = "MATERIAL" | "NORMAL" | "NONE" | "CONSUME";

export type ItemRarity =
  | "TIER_2"
  | "TIER_3"
  | "TIER_4"
  | "TIER_5"
  | "TIER_6"
  | "TIER_1";

export type OccPer = "ALWAYS" | "USUAL" | "ALMOST" | "OFTEN" | "SOMETIMES";

export interface UniCollectionInfo {
  uniCollectionItemId: string;
  uniqueItem: ItemBundle[];
}

// ===== mission_table.ts（合并）=====
export interface MissionTable {
    missions:                  { [key: string]: MissionData };
    missionGroups:             { [key: string]: MissionGroup };
    periodicalRewards:         { [key: string]: MissionDailyRewardConf };
    weeklyRewards:             { [key: string]: MissionWeeklyRewardConf };
    dailyMissionGroupInfo:     {};
    dailyMissionPeriodInfo:    DailyMissionGroupInfo[];
    crossAppShareMissions:     { [key: string]: CrossAppShareMission };
    crossAppShareMissionConst: CrossAppShareMissionConst;
}

export interface CrossAppShareMissionConst {
    nameCardShareMissionId: string;
}


export interface CrossAppShareMission {
    shareMissionId:   string;
    missionType:      string;
    relateActivityId: null | string;
    startTime:        number;
    endTime:          number;
    limitCount:       number;
    condTemplate:     null;
    condParam:        any[];
    rewardsList:      null;
}



export interface DailyMissionGroupInfo {
    startTime:  number;
    endTime:    number;
    tagState:   null|string;
    periodList: PeriodInfo[];
}

export interface PeriodInfo {
    missionGroupId: string;
    rewardGroupId:  string;
    period:         number[];
}


export interface MissionGroup {
    id:              string;
    title:           null | string;
    type:            string;
    preMissionGroup: null | string;
    period:          null;
    rewards:         ItemBundle[] | null;
    missionIds:      string[];
    startTs:         number;
    endTs:           number;
}






export interface MissionDailyRewardConf {
    groupId:             string;
    id:                  string;
    periodicalPointCost: number;
    type:                string;
    sortIndex:           number;
    rewards:             ItemBundle[];
    beginTime?:          number;
    endTime?:            number;
}
export interface MissionWeeklyRewardConf {
    groupId:             string;
    id:                  string;
    periodicalPointCost: number;
    type:                string;
    sortIndex:           number;
    rewards:             ItemBundle[];
    beginTime?:          number;
    endTime?:            number;
}

// ===== open_server_table.ts（合并）=====
export interface OpenServerSchedule {
    schedule:                 OpenServerScheduleItem[];
    dataMap:                  {[key: string]:OpenServerData};
    constant:                 OpenServerConst;
    playerReturn:             ReturnData;
    playerReturnV2:           ReturnV2Data;
    newbieCheckInPackageList: NewbieCheckInPackageData[];
}

export interface OpenServerConst {
    firstDiamondShardMailCount:     number;
    initApMailEndTs:                number;
    resFullOpenUnlockStageId:       string;
    resFullOpenDuration:            number;
    resFullOpenTitle:               string;
    resFullOpenDesc:                string;
    resFullOpenGuideGroupThreshold: string;
    resFullOpenStartTime:           number;
}



export interface OpenServerData {
    openServerMissionGroup: MissionGroup;
    openServerMissionData:  MissionData[];
    checkInData:            TotalCheckinData[];
    chainLoginData:         ChainLoginData[];
    totalCheckinCharData:   string[];
    chainLoginCharData:     string[];
}

export interface TotalCheckinData {
    order:   number;
    item:    OpenServerItemData;
    colorId: number;
}
export type ChainLoginData=TotalCheckinData
export interface OpenServerItemData {
    itemId:   string;
    itemType: string;
    count:    number;
    name:     null | string;
}

export interface NewbieCheckInPackageData {
    groupId:            string;
    startTime:          number;
    endTime:            number;
    bindGPGoodId:       string;
    checkInDuration:   number;
    totalCheckInDay:    number;
    iconId:             string;
    checkInRewardDict: { [key: string]: NewbieCheckInPackageRewardData[] };
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

export interface NewbieCheckInPackageRewardData {
    orderNum:   number;
    itemBundle: ItemBundle;
}

export interface ReturnData {
    constData:              ReturnConst;
    onceRewards:            ItemBundle[];
    intro:                  ReturnIntroData[];
    returnDailyTaskDic:     { [key: string]: ReturnDailyTaskData[] };
    returnLongTermTaskList: ReturnLongTermTaskData[];
    creditsList:            ItemBundle[];
    checkinRewardList:      ReturnCheckinData[];
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
export interface OpenServerScheduleItem {
    id:                    string;
    versionId:             string;
    startTs:               number;
    endTs:                 number;
    totalCheckinDescption: string;
    chainLoginDescription: string;
    charImg:               string;
}

// ===== shop.ts（合并）=====
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
export interface StageTable {
  stages: { [key: string]: StageData };
  runeStageGroups: {};
  mapThemes: { [key: string]: MapThemeData };
  tileInfo: { [key: string]: TileAppendInfo };
  forceOpenTable: { [key: string]: WeeklyForceOpenTable };
  timelyStageDropInfo: { [key: string]: TimelyDropTimeInfo };
  overrideDropInfo: { [key: string]: OverrideDropInfo };
  overrideUnlockInfo: { [key: string]: OverrideUnlockInfo };
  timelyTable: { [key: string]: TimelyDropInfo };
  stageValidInfo: { [key: string]: StageValidInfo };
  stageFogInfo: { [key: string]: StageFogInfo };
  stageStartConds: { [key: string]: StageStartCond };
  diffGroupTable: { [key: string]: StageDiffGroupTable };
  storyStageShowGroup: {
    [key: string]: { [key: string]: StoryStageShowGroup };
  };
  specialBattleFinishStageData: { [key: string]: SpecialBattleFinishStageData };
  recordRewardData: null;
  apProtectZoneInfo: { [key: string]: ApProtectZoneInfo };
  antiSpoilerDict: { [key: string]: string };
  actCustomStageDatas: { [key: string]: ActCustomStageData };
  spNormalStageIdFor4StarList: string[];
}

export interface ActCustomStageData {
  overrideGameMode: string;
}

export interface ApProtectZoneInfo {
  zoneId: string;
  timeRanges: TimeRange[];
}
export interface StageValidInfo {
  startTs: number;
  endTs: number;
}
export interface TimeRange {
  startTs: number;
  endTs: number;
}

export interface StageDiffGroupTable {
  normalId: string;
  toughId: null | string;
  easyId: string;
}

export interface WeeklyForceOpenTable {
  id: string;
  startTime: number;
  endTime: number;
  forceOpenList: string[];
}

export interface MapThemeData {
  themeId: string;
  unitColor: string;
  buildableColor: null | string;
  themeType: null | string;
  trapTintColor: null | string;
}

export interface OverrideDropInfo {
  itemId: string;
  startTs: number;
  endTs: number;
  zoneRange: string;
  times: number;
  name: string;
  egName: string;
  desc1: string;
  desc2: string;
  desc3: string;
  dropTag: string;
  dropTypeDesc: string;
  dropInfo: { [key: string]: StageDropInfo };
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

export interface SpecialBattleFinishStageData {
  stageId: string;
  skipAccomplishPerform: boolean;
}

export interface StageFogInfo {
  lockId: string;
  fogType: FogType;
  stageId: string;
  lockName: string;
  lockDesc: string;
  unlockItemId: string;
  unlockItemType: string;
  unlockItemNum: number;
  preposedStageId: string;
  preposedLockId: null | string;
}

export enum FogType {
  Stage = "STAGE",
  Zone = "ZONE",
}

export interface StageStartCond {
  requireChars: RequireChar[];
  excludeAssists: string[];
  isNotPass: boolean;
}

export interface RequireChar {
  charId: string;
  evolvePhase: string;
}

export interface StageData {
  stageType: StageType;
  difficulty: Difficulty;
  performanceStageFlag: PerformanceStageFlag;
  diffGroup: StageDiffGroup;
  unlockCondition: ConditionDesc[];
  stageId: string;
  levelId: null | string;
  zoneId: string;
  code: string;
  name: null | string;
  description: null | string;
  hardStagedId: null | string;
  dangerLevel: null | string;
  dangerPoint: number;
  loadingPicId: string;
  canPractice: boolean;
  canBattleReplay: boolean;
  apCost: number;
  apFailReturn: number;
  etItemId: null | string;
  etCost: number;
  etFailReturn: number;
  etButtonStyle: null | string;
  apProtectTimes: number;
  diamondOnceDrop: number;
  practiceTicketCost: number;
  dailyStageDifficulty: number;
  expGain: number;
  goldGain: number;
  loseExpGain: number;
  loseGoldGain: number;
  passFavor: number;
  completeFavor: number;
  slProgress: number;
  displayMainItem: null | string;
  hilightMark: boolean;
  bossMark: boolean;
  isPredefined: boolean;
  isHardPredefined: boolean;
  isSkillSelectablePredefined: boolean;
  isStoryOnly: boolean;
  appearanceStyle: AppearanceStyle;
  stageDropInfo: StageDropInfo;
  canUseCharm: boolean;
  canUseTech: boolean;
  canUseTrapTool: boolean;
  canUseBattlePerformance: boolean;
  canContinuousBattle: boolean;
  startButtonOverrideId: string | null;
  isStagePatch: boolean;
  mainStageId: null | string;
  extraCondition: ExtraConditionDesc[] | null;
  extraInfo: SpecialStoryInfo[] | null;
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

export interface StoryStageShowGroup {
  displayRecordId: string;
  stageId: string;
  accordingStageId: null | string;
  diffGroup: StageDiffGroup;
}

export interface TileAppendInfo {
  tileKey: string;
  name: string;
  description: string;
  isFunctional: boolean;
}

export interface TimelyDropTimeInfo {
  startTs: number;
  endTs: number;
  stagePic: null | string;
  dropPicId: null | string;
  stageUnlock: string;
  entranceDownPicId: null | string;
  entranceUpPicId: null | string;
  timelyGroupId: string;
  weeklyPicId: null | string;
  isReplace: boolean;
  apSupplyOutOfDateDict: { [key: string]: number };
}

export interface TimelyDropInfo {
  dropInfo: { [key: string]: StageDropInfo };
}
export interface OverrideUnlockInfo {
  groudId: string;
  startTime: number;
  endTime: number;
  unlockDict: { [key: string]: ConditionDesc[] };
}

// ===== roguelike_topic_table.ts（合并）=====
// 黑流树海（rogue_6）三模块数据类型复用 CS 反编译生成的权威定义
// （types_excel_gen.ts，由 scripts/generate-types.ts --excel 产出），避免手写重复。

export type {
  RoguelikeGridZoneModuleData,
  RoguelikeWeatherModuleData,
  RoguelikeScrapModuleData,
};

export interface RoguelikeTopicTable {
    topics:        {[key:string]:RoguelikeTopicBasicData};
    constant:      RoguelikeTopicConst;
    details:       {[key: string]:RoguelikeTopicDetail};
    modules:       {[key: string]:RoguelikeModule};
    customizeData: CustomizeData;
}

export interface RoguelikeTopicConst {
    milestoneTokenRatio:           number;
    outerBuffTokenRatio:           number;
    relicTokenRatio:               number;
    rogueSystemUnlockStage:        string;
    ordiModeReOpenCoolDown:        number;
    monthModeReOpenCoolDown:       number;
    monthlyTaskUncompletedTime:    number;
    monthlyTaskManualRefreshLimit: number;
    monthlyTeamUncompletedTime:    number;
    bpPurchaseSystemUnlockTime:    number;
    predefinedChars:               { [key: string]: RoguelikeTopicConst.PredefinedChar };
}
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

export interface RoguelikeTopicDetail {
    updates:                      RoguelikeTopicUpdate[];
    enrolls:                      {[key: string]: RoguelikeTopicEnroll};
    milestones:                   RoguelikeTopicBP[];
    milestoneUpdates:             RoguelikeTopicMilestoneUpdateData[];
    grandPrizes:                  RoguelikeTopicBPGrandPrize[];
    monthMission:                 RoguelikeTopicMonthMission[];
    monthSquad:                   {[key:string]:RoguelikeTopicMonthSquad};
    challenges:                   {[key:string]:RoguelikeTopicChallenge};
    difficulties:                 RoguelikeTopicDifficulty[];
    bankRewards:                  RoguelikeTopicBankReward[];
    archiveComp:                  RoguelikeArchiveComponentData;
    archiveUnlockCond:            RoguelikeArchiveUnlockCondData;
    detailConst:                  RoguelikeTopicDetailConst;
    init:                         RoguelikeGameInitData[];
    stages:                       { [key: string]: RoguelikeGameStageData };
    zones:                        {[key:string]:RoguelikeGameZoneData};
    variation:                    {[key:string]:{}};
    traps:                        {[key:string]:RoguelikeGameTrapData};
    recruitTickets:               {[key:string]:RoguelikeGameRecruitTicketData};
    upgradeTickets:               {[key:string]:RoguelikeGameUpgradeTicketData};
    customTickets:                {[key:string]:RoguelikeGameCustomTicketData};
    relics:                       { [key: string]: RoguelikeGameRelicData };
    relicParams:                  { [key: string]: RoguelikeGameRelicParamData };
    recruitGrps:                  {[key:string]:RoguelikeGameRecruitGrpData};
    choices:                      { [key: string]: RoguelikeGameChoiceData };
    choiceScenes:                 { [key: string]: RoguelikeGameChoiceSceneData };
    nodeTypeData:                 {[key:string]:RoguelikeGameNodeTypeData};
    subTypeData:                  RoguelikeGameNodeSubTypeData[];
    variationData:                {[key:string]:RoguelikeGameVariationData};
    charBuffData:                 {[key:string]:RoguelikeGameCharBuffData};
    squadBuffData:                {[key:string]:RoguelikeGameCharBuffData};
    taskData:                     {[key:string]:RoguelikeTaskData};
    gameConst:                    RoguelikeGameConst;
    shopDialogData:               RoguelikeGameShopDialogData;
    capsuleDict:                  { [key: string]: RoguelikeTopicCapsule }|null;
    endings:                      {[key:string]:RoguelikeGameEndingData};
    battleSummeryDescriptions:    {[key:string]:RoguelikeBattleSummeryDescriptionData};
    battleLoadingTips:            TipData[];
    items:                        { [key: string]: RoguelikeGameItemData };
    bandRef:                      {[key:string]:RoguelikeBandRefData};
    endingDetailList:             RoguelikeEndingDetailText[];
    endingRelicDetailList:        RoguelikeEndingRelicDetailText[];
    treasures:                    {[key:string]:RoguelikeGameTreasureData[]};
    difficultyUpgradeRelicGroups: {[key:string]:RoguelikeDifficultyUpgradeRelicGroupData};
    styles:                       {[key:string]:RoguelikePredefinedStyleData};
    styleConfig:                  RoguelikePredefinedConstStyleData;
    exploreTools:                 {[key: string]:RoguelikeGameExploreToolData};
    rollNodeData:                 { [key: string]: RoguelikeRollNodeData };
}

export interface RoguelikeArchiveComponentData {
    relic:    ActArchiveRelicData;
    capsule:  null|ActArchiveCapsuleData;
    trap:     ActArchiveTrapData;
    chat:     ActArchiveChatData;
    endbook:  ActArchiveEndbookData;
    buff:     ActArchiveBuffData;
    totem:    null|ActArchiveTotemData;
    chaos:    null|ActArchiveChaosData;
    fragment: null|ActArchiveFragmentData;
    disaster: null|ActArchiveDisasterData;
}

export interface ActArchiveBuffData {
    buff: {[key:string]:ActArchiveBuffItemData};
}

export interface BandRef {
}

export interface ActArchiveCapsuleData {
    capsule: { [key: string]: ActArchiveCapsuleItemData };
}

export interface ActArchiveCapsuleItemData {
    capsuleId:     string;
    capsuleSortId: number;
    englishName:   string;
    enrollId:      null|string;
}

export interface ActArchiveChatData {
    chat: {[key:string]:ActArchiveChatGroupData};
}



export interface ActArchiveChatGroupData {
    sortId:             number;
    numChat:            number;
    clientChatItemData: ActArchiveChatItemData[];
}

export interface ActArchiveChatItemData {
    chatFloor:   number;
    chatDesc:    null | string;
    chatStoryId: string;
}

export interface ActArchiveEndbookData {
    endbook: {[key:string]:ActArchiveEndbookGroupData};
}

export interface ActArchiveRelicData {
    relic: { [key: string]: ActArchiveRelicItemData };
}

export interface ActArchiveRelicItemData {
    relicId:      string;
    relicSortId:  number;
    relicGroupId: number;
    orderId:      string;
    isSpRelic:    boolean;
    enrollId:     null | string;
}

export interface ActArchiveTrapData {
    trap: {[key:string]:ActArchiveTrapItemData};
}


export interface ActArchiveTrapItemData {
    trapId:     string;
    trapSortId: number;
    orderId:    string;
    enrollId:   null|string;
}

export interface RoguelikeArchiveUnlockCondData {
    unlockCondDesc: { [key: string]: RoguelikeArchiveUnlockCondDesc };
    enroll:         { [key: string]: RoguelikeArchiveEnroll };
}

export interface RoguelikeArchiveEnroll {
    archiveType: string;
    enrollId:    null | string;
}

export interface RoguelikeArchiveUnlockCondDesc {
    archiveType: string;
    description: string;
}

export interface RoguelikeTopicBankReward {
    rewardId:      string;
    unlockGoldCnt: number;
    rewardType:    string;
    desc:          string;
}

export interface TipData {
    tip:      string;
    weight:   number;
    category: string;
}

export interface RoguelikeBattleSummeryDescriptionData {
    randomDescriptionList: string[];
}

export interface RoguelikeTopicCapsule {
    itemId:     string;
    maskType:   string;
    innerColor: string;
}



export interface RoguelikeTopicChallenge {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null|string;
    challengeUnlockDesc:      null|string;
    challengeUnlockToastDesc: null|string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           {[key:string]:RoguelikeTopicChallengeTask};
    defaultTaskId:            string;
    rewards:                  ItemBundle[];
    challengeStoryId:         null|string;
}
export interface RoguelikeTopicChallengeTask {
    taskId:           string;
    taskDes:          string;
    completionClass:  string;
    completionParams: string[];
}


export interface RoguelikeGameChoiceSceneData {
    id:             string;
    title:          string;
    description:    string;
    background:     null | string;
    titleIcon:      null | string;
    subTypeId:      number;
    useHiddenMusic: boolean;
}

export interface RoguelikeGameChoiceData {
    id:                     string;
    title:                  string;
    description:            null | string;
    lockedCoverDesc:        null | string;
    type:                   string;
    leftDecoType:           string;
    nextSceneId:            null | string;
    icon:                   null | string;
    displayData:            DisplayData;
    forceShowWhenOnlyLeave: boolean;
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

export interface RoguelikeTopicDetailConst {
    playerLevelTable:                  { [key: string]: PlayerLevelData };
    charUpgradeTable:                  { [key: string]: CharUpgradeData };
    difficultyUpgradeRelicDescTable:   { [key: string]: string };
    predefinedLevelTable:              { [key: string]: PredefinedPlayerLevelData };
    tokenBpId:                         string;
    tokenOuterBuffId:                  string;
    previewedRewardsAccordingUpdateId: string;
    tipButtonName:                     string;
    collectButtonName:                 string;
    bpSystemName:                      string;
    autoSetKV:                         string;
    bpPurchaseActiveEnroll:            string|null;
    defaultSacrificeDesc:              null | string;
    defaultExpeditionSelectDesc:       null | string;
    gotCharBuffToast:                  null | string;
    gotSquadBuffToast:                 null | string;
    loseCharBuffToast:                 null | string;
    monthTeamSystemName:               string;
    battlePassUpdateName:              string;
    monthCharCardTagName:              string;
    monthTeamDescTagName:              string;
    outerBuffCompleteText:             string;
    outerProgressTextColor:            string;
    challengeTaskTargetName:           string;
    challengeTaskConditionName:        string;
    challengeTaskRewardName:           string;
    challengeTaskModeName:             string;
    challengeTaskName:                 string;
    outerBuffTokenSum:                 number;
    needAllFrontNode:                  boolean;
    showBlurBack:                      boolean;
    endingIconBorderDifficulty:        number;
    endingIconBorderCount:             number;
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

export interface RoguelikeTopicDifficulty {
    modeDifficulty:       string;
    grade:                number;
    name:                 string;
    subName:              null | string;
    enrollId:             null | string;
    haveInitialRelicIcon: boolean;
    scoreFactor:          number;
    canUnlockItem:        boolean;
    doMonthTask:          boolean;
    ruleDesc:             string;
    ruleDescReplacements: RuleDescReplacement[] | null;
    failTitle:            string;
    failImageId:          string;
    failForceDesc:        string;
    sortId:               number;
    equivalentGrade:      number;
    color:                null | string;
    bpValue:              number;
    bossValue:            number;
    addDesc:              null | string;
    isHard:               boolean;
    unlockText:           null | string;
    displayIconId:        null | string;
    hideEndingStory:      boolean;
}

export interface RuleDescReplacement {
    enrollId: string;
    ruleDesc: string;
}

export interface RoguelikeEndingDetailText {
    textId:        string;
    text:          string;
    eventType:     string;
    showType:      string;
    choiceSceneId: null | string;
    paramList:     string[];
    otherPara1:    null|string;
}

export interface RoguelikeGameEndingData {
    id:               string;
    familyId:         number;
    name:             string;
    desc:             string;
    bgId:             string;
    icons:            LevelIcon[];
    priority:         number;
    changeEndingDesc: null | string;
    bossIconId:       null | string;
}

export interface LevelIcon {
    level:  number;
    iconId: string;
}

export interface RoguelikeTopicEnroll {
    enrollId:   string;
    enrollTime: number;
}

export interface RoguelikeGameConst {
    initSceneName:                     string;
    failSceneName:                     string;
    hpItemId:                          string;
    goldItemId:                        string;
    populationItemId:                  string;
    squadCapacityItemId:               string;
    expItemId:                         string;
    initialBandShowGradeFlag:          boolean;
    bankMaxGold:                       number;
    bankCostId:                        null | string;
    bankDrawCount:                     number;
    bankDrawLimit:                     number;
    mimicEnemyIds:                     string[];
    bossIds:                           string[];
    goldChestTrapId:                   string;
    normBoxTrapId:                     null | string;
    rareBoxTrapId:                     null | string;
    badBoxTrapId:                      null | string;
    maxHpItemId:                       null | string;
    shieldItemId:                      null | string;
    keyItemId:                         null | string;
    chestKeyCnt:                       number;
    chestKeyItemId:                    null | string;
    keyColorId:                        null | string;
    onceNodeTypeList:                  string[];
    gpScoreRatio:                      number;
    overflowUsageSquadBuff:            null | string;
    specialTrapId:                     null | string;
    trapRewardRelicId:                 null | string;
    unlockRouteItemId:                 null | string;
    unlockRouteItemCount:              number;
    hideBattleNodeName:                null| string;
    hideBattleNodeDescription:         null| string;
    hideNonBattleNodeName:             null| string;
    hideNonBattleNodeDescription:      null| string;
    charSelectExpeditionConflictToast: null | string;
    itemDropTagDict:                   {[key:string]:string};
    expeditionReturnDescCureUpgrade:   null | string;
    expeditionReturnDescUpgrade:       null | string;
    expeditionReturnDescCure:          null | string;
    expeditionReturnDesc:              null | string;
    expeditionSelectDescFormat:        null| string;
    expeditionReturnDescItem:          null | string;
    expeditionReturnRewardBlackList:   string[];
    travelLeaveToastFormat:            null| string;
    charSelectTravelConflictToast:     null| string;
    travelReturnDescUpgrade:           null| string;
    travelReturnDesc:                  null| string;
    travelReturnDescItem:              null| string;
    traderReturnTitle:                 null| string;
    traderReturnDesc:                  null| string;
    gainBuffDiffGrade:                 number;
    dsPredictTips:                     null| string;
    dsBuffActiveTips:                  null| string;
    totemDesc:                         null| string;
    relicDesc:                         null| string;
    buffDesc:                          null| string;
    refreshNodeItemId:                 null| string;
    portalZones:                       string[];
    exploreExpOnKill:                  null| string;
}

export interface RoguelikeTopicBPGrandPrize {
    grandPrizeDisplayId: string;
    sortId:              number;
    displayUnlockYear:   number;
    displayUnlockMonth:  number;
    acquireTitle:        string;
    purchaseTitle:       string;
    displayName:         string;
    displayDiscription:  string;
    bpLevelId:           string;
    itemBundle:          ItemBundle | null;
    detailAnnounceTime:  null | string;
    picIdAftrerUnlock:   null | string;
}

export interface RoguelikeGameInitData {
    modeId:               string;
    modeGrade:            number;
    predefinedId:         null | string;
    predefinedStyle:      null | string;
    initialBandRelic:     string[];
    initialRecruitGroup:  string[] | null;
    initialHp:            number;
    initialPopulation:    number;
    initialGold:          number;
    initialSquadCapacity: number;
    initialShield:        number;
    initialMaxHp:         number;
    initialKey:           number;
}

export interface RoguelikeGameItemData {
    id:             string;
    name:           string;
    description:    null | string;
    usage:          string;
    obtainApproach: string;
    iconId:         string;
    type:           string;
    subType:        string;
    rarity:         string;
    value:          number;
    sortId:         number;
    canSacrifice:   boolean;
    unlockCondDesc: null | string;
}

export interface RoguelikeTopicMilestoneUpdateData {
    updateTime:        number;
    endTime:           number;
    maxBpLevel:        number;
    maxBpCount:        number;
    maxDisplayBpCount: number;
}

export interface RoguelikeTopicBP {
    id:           string;
    level:        number;
    tokenNum:     number;
    nextTokenNum: number;
    itemID:       string;
    itemType:     string;
    itemCount:    number;
    isGoodPrize:  boolean;
    isGrandPrize: boolean;
}

export interface RoguelikeTopicMonthMission {
    id:               string;
    taskName:         string;
    taskClass:        string;
    innerClassWeight: number;
    template:         string;
    paramList:        string[];
    desc:             string;
    tokenRewardNum:   number;
}

export interface RoguelikeTopicMonthSquad {
  id: string;
  teamName: string;
  teamSubName: null | string;
  teamFlavorDesc: null | string;
  teamDes: string;
  teamColor: string;
  teamMonth: string;
  teamYear: string;
  teamIndex: null | string;
  teamChars: string[];
  zoneId: null | string;
  chatId: string;
  tokenRewardNum: number;
  items: ItemBundle[];
  startTime: number;
  endTime: number;
  taskDes: null | string;
}


export interface RoguelikeGameNodeTypeData {
    name:        string;
    description: string;
}

export interface RoguelikeGameRecruitGrpData {
    id:         string;
    iconId:     string;
    name:       string;
    desc:       string;
    unlockDesc: null | string;
}


export interface RoguelikeGameRecruitTicketData {
    id:              string;
    profession:      string|number;
    rarity:          string|number;
    professionList:  string[];
  rarityList: number[];
    extraEliteNum?:   number;
    extraFreeRarity?: string[];
    extraCharIds?:    string[];
}

export interface RoguelikeGameRelicParamData {
    id:                 string;
    checkCharBoxTypes:  string[];
    checkCharBoxParams: CheckCharBoxParam[];
}

export interface CheckCharBoxParam {
    valueProfessionMask: string;
    valueStrs:           string[] | null;
    valueInt:            number;
}

export interface RoguelikeGameRelicData {
    id:    string;
    buffs: RoguelikeBuff[];
}

export interface RoguelikeGameShopDialogData {
    types: {[key:string]:RoguelikeGameShopDialogTypeData};
}


export interface RoguelikeGameShopDialogTypeData {
    groups: {[key:string]:RoguelikeGameShopDialogGroupData};
}

export interface RoguelikeGameShopDialogGroupData {
    content: string[];
}

export interface RoguelikeGameStageData {
    id:            string;
    linkedStageId: string;
    levelId:       string;
    code:          string;
    name:          string;
    loadingPicId:  string;
    description:   string;
    eliteDesc:     null | string;
    isBoss:        number;
    isElite:       number;
    difficulty:    string;
    capsulePool:   null | string;
    capsuleProb:   number;
    vutresProb:    number[];
    boxProb:       number[];
    specialNodeId: null | string;
}

export interface RoguelikePredefinedConstStyleData {
    expStyleConfig: null;
}


export interface RoguelikeGameTrapData {
    itemId:   string;
    trapId:   string;
    trapDesc: string;
}
export type RoguelikeGameExploreToolData=RoguelikeGameTrapData
export interface RoguelikeTopicUpdate {
    updateId:        string;
    topicUpdateTime: number;
    topicEndTime:    number;
}

export interface RoguelikeGameUpgradeTicketData {
    id:             string;
    profession:     number|string;
    rarity:         number|string;
    professionList: string[];
    rarityList:     string[];
}


export interface RoguelikeGameVariationData {
    id:           string;
    type:        string;
    outerName:    string;
    innerName:    string;
    functionDesc: string;
    desc:         string;
    iconId:       null | string;
    sound:       null | string;
}
export interface RoguelikeGameCharBuffData {
    id:           string;
    outerName:    string;
    innerName:    string;
    functionDesc: string;
    desc:         string;
    iconId:       null | string;
    buffs:       RoguelikeBuff[];
}
export type RoguelikeGameSquadBuffData=RoguelikeGameCharBuffData;
export interface RoguelikeGameZoneData {
    id:                string;
    name:              string;
    clockPerformance:  null | string;
    displayTime:       null | string;
    description:       string;
    buffDescription:   null | string;
    endingDescription: string;
    backgroundId:      string;
    zoneIconId:        string;
    isHiddenZone:      boolean;
}

export interface ActArchiveBuffItemData {
    buffId:         string;
    buffGroupIndex: number;
    innerSortId:    number;
    name:           string;
    iconId:         string;
    usage:          string;
    desc:           string;
    color:          string;
}

export interface ActArchiveEndbookGroupData {
    endId:                  string;
    endingId:               string;
    sortId:                 number;
    title:                  string;
    cgId:                   string;
    backBlurId:             string;
    cardId:                 string;
    hasAvg:                 boolean;
    avgId:                  string;
    clientEndbookItemDatas: ActArchiveEndbookItemData[];
}

export interface ActArchiveEndbookItemData {
    endBookId:   string;
    sortId:      number;
    enrollId:    null | string;
    isLast:      boolean;
    endbookName: string;
    unlockDesc:  string;
    textId:      string;
}

export interface RoguelikeBandRefData {
    itemId:       string;
    iconId:       string;
    description:  string;
    bandLevel:    number;
    normalBandId: string;
}


export interface RoguelikeGameCustomTicketData {
    id:          string;
    subType:     string;
    discardText: string;
}

export interface RoguelikeTaskData {
    taskId:        string;
    taskName:      string;
    taskDesc:      string;
    rewardSceneId: string;
    taskRarity:    string;
}

export interface RoguelikeGameTreasureData {
    treasureId: string;
    groupId:    string;
    subIndex:   number;
    name:       string;
    usage:      string;
}
export interface ActArchiveChaosData {
    chaos: { [key: string]: ActArchiveChaosItemData };
}

export interface ActArchiveChaosItemData {
    id:       string;
    isHidden: boolean;
    enrollId: null|string;
    sortId:   number;
}

export interface ActArchiveTotemData {
    totem: { [key: string]: ActArchiveTotemItemData };
}

export interface ActArchiveTotemItemData {
    id:                string;
    type:              string;
    enrollConditionId: null | string;
    sortId:            number;
}

export interface PredefinedPlayerLevelData {
    levels: { [key: string]: PlayerLevelData };
}

export interface RoguelikeDifficultyUpgradeRelicGroupData {
    relicData: RoguelikeDifficultyUpgradeRelicData[];
}

export interface RoguelikeDifficultyUpgradeRelicData {
    relicId:         string;
    equivalentGrade: number;
}


export interface RoguelikePredefinedStyleData {
    styleId:     string;
    styleConfig: number;
}

export interface RoguelikeGameNodeSubTypeData {
    eventType:   string;
    subTypeId:   number;
    iconId:      string;
    name:        null;
    description: string;
}


export interface ActArchiveDisasterData {
    disasters: { [key: string]: ActArchiveDisasterItemData };
}

export interface ActArchiveDisasterItemData {
    disasterId:        string;
    sortId:            number;
    enrollConditionId: null|string;
    picSmallId:        string;
    picBigActiveId:    string;
    picBigInactiveId:  string;
}



export interface ActArchiveFragmentData {
    fragment: { [key: string]: ActArchiveFragmentItemData };
}

export interface ActArchiveFragmentItemData {
    fragmentId:        string;
    sortId:            number;
    enrollConditionId: null|string;
}


export interface RoguelikeEndingRelicDetailText {
    relicId:          string;
    summaryEventText: string;
}


export interface RoguelikeRollNodeData {
    zoneId: string;
    groups: {[key:string]:RoguelikeRollNodeGroupData};
}
export interface RoguelikeRollNodeGroupData {
    nodeType: string;
}


/**
 * 主题模块数据（官方 modules[theme]）。
 * moduleTypes 决定 RoguelikeModuleManager 实例化哪些管理器；各模块数据键为 null 表示
 * 该主题不启用。gridZone/scrap/weather 为黑流树海（rogue_6）三模块——实测
 * data/excel/roguelike_topic_table.json 的 modules.rogue_6 键名为小驼峰
 * `gridZone`/`scrap`/`weather`（moduleTypes = ["GRID_ZONE","WEATHER","SCRAP"]）。
 */
export interface RoguelikeModule {
    moduleTypes: string[];
    sanCheck:    RoguelikeSanCheckModuleData | null;
    dice:        RoguelikeDiceModuleData | null;
    chaos:       RoguelikeChaosModuleData | null;
    totemBuff:   RoguelikeTotemBuffModuleData | null;
    vision:      RoguelikeVisionModuleData | null;
    fragment:    RoguelikeFragmentModuleData | null;
    disaster:    RoguelikeDisasterModuleData | null;
    nodeUpgrade: RoguelikeNodeUpgradeModuleData | null;
    gridZone?:   RoguelikeGridZoneModuleData | null;
    weather?:    RoguelikeWeatherModuleData | null;
    scrap?:      RoguelikeScrapModuleData | null;
}

export interface RoguelikeChaosModuleData {
    chaosDatas:    { [key: string]: RoguelikeChaosData };
    chaosRanges:   RoguelikeChaosRangeData[];
    levelInfoDict: {[key:string]:{ [key: string]: RoguelikeChaosPredefineLevelInfo }};
    moduleConsts:  RoguelikeChaosModuleConsts;
}

export interface RoguelikeChaosData {
    chaosId:      string;
    level:        number;
    nextChaosId:  null | string;
    prevChaosId:  null | string;
    iconId:       string;
    name:         string;
    functionDesc: string;
    desc:         string;
    sound:        string;
    sortId:       number;
}

export interface RoguelikeChaosRangeData {
    chaosMax:           number;
    chaosDungeonEffect: string;
}

export interface RoguelikeChaosPredefineLevelInfo {
    chaosLevelBeginNum: number;
    chaosLevelEndNum:   number;
}

export interface RoguelikeChaosModuleConsts {
    maxChaosLevel:           number;
    maxChaosSlot:            number;
    chaosNotMaxDescription:  string;
    chaosMaxDescription:     string;
    chaosPredictDescription: string;
}

export interface RoguelikeDiceModuleData {
    dice:           { [key: string]: RoguelikeDiceData };
    diceEvents:     { [key: string]: RoguelikeDiceRuleData };
    diceChoices:    { [key: string]: string };
    diceRuleGroups: { [key: string]: RoguelikeDiceRuleGroupData };
    dicePredefines: RoguelikeDicePredefineData[];
}

export interface RoguelikeDiceData {
    diceId:        string;
    description:   string;
    isUpgradeDice: number;
    upgradeDiceId: null | string;
    diceFaceCount: number;
    battleDiceId:  string;
}


export interface RoguelikeDiceRuleData {
    dicePointMax:    number;
    diceResultClass: string;
    diceGroupId:     string;
    diceEventId:     string;
    resultDesc:      string;
    showType:        string;
    canReroll:       boolean;
    diceEndingScene: string;
    diceEndingDesc:  string;
    sound:           string;
}

export interface RoguelikeDicePredefineData {
    modeId:           string;
    modeGrade:        number;
    predefinedId:     null | string;
    initialDiceCount: number;
}

export interface RoguelikeDiceRuleGroupData {
    ruleGroupId: string;
    minGoodNum:  number;
}

export interface RoguelikeDisasterModuleData {
    disasterData: { [key: string]: RoguelikeDisasterData };
}

export interface RoguelikeDisasterData {
    id:           string;
    iconId:       string;
    toastIconId:  string;
    level:        number;
    name:         string;
    levelName:    string;
    type:         string;
    functionDesc: string;
    desc:         string;
    sound:        null;
}

export interface RoguelikeFragmentModuleData {
    fragmentData:       { [key: string]: RoguelikeFragmentData };
    fragmentTypeData:   {[key:string]:RoguelikeFragmentTypeData};
    moduleConsts:       RoguelikeFragmentModuleConsts;
    fragmentBuffData:   { [key: string]: RoguelikeFragmentBuffData };
    alchemyData:        { [key: string]: RoguelikeAlchemyData };
    alchemyFormulaData: { [key: string]: RoguelikeAlchemyFormulationData };
    fragmentLevelData:  { [key: string]: RoguelikeFragmentLevelRelatedData };
}

export interface RoguelikeAlchemyData {
    fragmentTypeList:  string[];
    fragmentSquareSum: number;
    poolRarity:        string;
    relicProp:         number;
    shieldProp:        number;
    populationProp:    number;
}

export interface RoguelikeAlchemyFormulationData {
    fragmentIds:    string[];
    rewardId:       string;
    rewardCount:    number;
    rewardItemType: string;
}

export interface RoguelikeFragmentBuffData {
    itemId:   string;
    maskType: string;
    desc:     null | string;
}

export interface RoguelikeFragmentData {
    id:     string;
    type:   string;
    value:  number;
    weight: number;
}

export interface RoguelikeFragmentLevelRelatedData {
    weightUp: number;
}



export interface RoguelikeFragmentTypeData {
    type:       string;
    typeName:   string;
    typeDesc:   string;
    typeIconId: string;
}

export interface RoguelikeFragmentModuleConsts {
    weightStatusSafeDesc:            string;
    weightStatusLimitDesc:           string;
    weightStatusOverweightDesc:      string;
    charWeightSlot:                  number;
    limitWeightThresholdValue:       number;
    overWeightThresholdValue:        number;
    maxAlchemyField:                 number;
    maxAlchemyCount:                 number;
    fragmentBagWeightLimitTips:      string;
    fragmentBagWeightOverWeightTips: string;
    weightUpgradeToastFormat:        string;
}

export interface RoguelikeNodeUpgradeModuleData {
    nodeUpgradeDataMap: {[key:string]:RoguelikeNodeUpgradeData};
}


export interface RoguelikeNodeUpgradeData {
    nodeType:     string;
    sortId:       number;
    permItemList: RoguelikePermNodeUpgradeItemData[];
    tempItemList: RoguelikeTempNodeUpgradeItemData[];
}

export interface RoguelikePermNodeUpgradeItemData {
    upgradeId:     string;
    nodeType:      string;
    nodeLevel:     number;
    costItemId:    string;
    costItemCount: number;
    desc:          string;
    nodeName:      string;
}

export interface RoguelikeTempNodeUpgradeItemData {
    upgradeId:     string;
    nodeType:      string;
    sortId:        number;
    costItemId:    string;
    costItemCount: number;
    desc:          string;
}

export interface RoguelikeSanCheckModuleData {
    sanRanges:    RoguelikeSanRangeData[];
    moduleConsts: RoguelikeSanCheckConsts;
}

export interface RoguelikeSanCheckConsts {
    sanDecreaseToast: string;
}

export interface RoguelikeSanRangeData {
    sanMax:           number;
    diceGroupId:      string;
    description:      string;
    sanDungeonEffect: string;
    sanEffectRank:    string;
    sanEndingDesc:    null|string;
}

export interface RoguelikeTotemBuffModuleData {
    totemBuffDatas: { [key: string]: RoguelikeTotemBuffData };
    subBuffs:       { [key: string]: RoguelikeTotemSubBuffData };
    moduleConsts:   RoguelikeTotemModuleConsts;
}

export interface RoguelikeTotemModuleConsts {
    totemPredictDescription:    string;
    colorCombineDesc:           { [key: string]: string };
    bossCombineDesc:            string;
    battleNoPredictDescription: string;
    shopNoGoodsDescription:     string;
}

export interface RoguelikeTotemSubBuffData {
    subBuffId:    string;
    name:         string;
    desc:         string;
    combinedDesc: string;
    info:         string;
}

export interface RoguelikeTotemBuffData {
    totemId:                  string;
    color:                    string;
    pos:                      string;
    rhythm:                   string;
    normalDesc:               string;
    synergyDesc:              string;
    archiveDesc:              string;
    combineGroupName:         string;
    bgIconId:                 string;
    isManual:                 boolean;
    linkedNodeTypeData:       RoguelikeTotemLinkedNodeTypeData;
    distanceMin:              number;
    distanceMax:              number;
    vertPassable:             boolean;
    expandLength:             number;
    onlyForVert:              boolean;
    portalLinkedNodeTypeData: RoguelikeTotemLinkedNodeTypeData;
}

export interface RoguelikeTotemLinkedNodeTypeData {
    effectiveNodeTypes: string[];
    blurNodeTypes:      string[];
}

export interface RoguelikeVisionModuleData {
    visionDatas:   { [key: string]: RoguelikeVisionData };
    visionChoices: { [key: string]: VisionChoiceConfig };
    moduleConsts:  RoguelikeVisionModuleConsts;
}

export interface RoguelikeVisionModuleConsts {
    maxVision:              number;
    totemBottomDescription: string;
    chestBottomDescription: string;
    goodsBottomDescription: string;
}

export interface VisionChoiceConfig {
    value: number;
    type:  string;
}

export interface RoguelikeVisionData {
    sightNum:   number;
    level:      number;
    canForesee: boolean;
    dividedDis: number;
    status:     string;
    clr:        string;
    desc1:      string;
    desc2:      string;
    icon:       string;
}

export interface RoguelikeTopicBasicData {
    id:                        string;
    name:                      string;
    startTime:                 number;
    disappearTimeOnMainScreen: number;
    sort:                      number;
    showMedalId:               string;
    medalGroupId:              string;
    fullStoredTime:            number;
    lineText:                  string;
    homeEntryDisplayData:      HomeEntryDisplayData[];
    moduleTypes:               string[];
    config:                    RoguelikeTopicConfig;
}

export interface RoguelikeTopicConfig {
    loadCharCardPlugin:        boolean;
    webBusType:                string;
    monthChatTrigType:         string;
    loadRewardHpDecoPlugin:    boolean;
    loadRewardExtraInfoPlugin: boolean;
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
