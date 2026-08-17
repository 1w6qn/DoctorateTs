/**
 * Excel 数据表管理模块
 * 
 * 负责加载和管理所有游戏配置数据表（Excel 数据），包括角色、关卡、物品、抽卡等数据。
 * 所有数据表在服务器启动时加载，运行时只读访问。
 */

import { readJson, readJsonSync } from "@utils/file";
import { logger } from "@utils/logger";
import { normalizeStageDropInfo } from "./stage_table";
import {
  ActivityTable,
  BattleEquipPack,
  BuildingData,
  CampaignTable,
  CharacterData,
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
  MissionTable,
  OpenServerSchedule,
  PlayerAvatarData,
  RangeData,
  ReplicateTable,
  RetroStageTable,
  RoguelikeActivityTable,
  RoguelikeTopicTable,
  SandboxPermItemData,
  SandboxPermTable,
  ShopClientData,
  SkillDataBundle,
  SkinTable,
  SpecialOperatorTable,
  StageTable,
  StoryData,
  StoryReviewGroupClientData,
  StoryReviewMetaTable,
  UniEquipData,
  UniEquipTable,
  ZoneTable,
} from "./types_excel_gen";
import { ServerItemTable } from "./item_table";
import { GachaDetailTable } from "./gacha_detail_table";
import { RoguelikeConst } from "@excel/roguelike_consts";
import { ShopData } from "@excel/shop";

export type ChapterData = any;

/**
 * Excel 数据表管理类
 * 
 * 聚合所有游戏配置数据表，提供统一的访问接口。
 */
export class Excel {
  BattleEquipTable!: BattleEquipPack;
  BuildingData!: BuildingData;
  CharacterTable!: CharacterData;
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
      ["RoguelikeConsts", "./data/rlv2.json"],
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

    // 归一化掉落信息（occPercent/dropType 字符串 → 数字档位，供 dropReward 使用）
    normalizeStageDropInfo(this.StageTable);

    logger.info("Excel", `${loaders.length} excels loaded`);
    this.ShopTable = new ShopData();
    await this.ShopTable.init();
    logger.info("Excel", "10 shops loaded");
  }
}

/** Excel 数据表管理实例 */
export default new Excel();