/**
 * Excel 数据表管理模块
 * 
 * 负责加载和管理所有游戏配置数据表（Excel 数据），包括角色、关卡、物品、抽卡等数据。
 * 所有数据表在服务器启动时加载，运行时只读访问。
 */

import { readJson } from "@utils/file";
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
  CrisisV2AppraiseWrap,
  CrisisV2ConstData,
  CrisisV2SeasonInfo,
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
  SandboxActTable,
  SandboxBaseConstTable,
  SandboxMapConstTable,
  SandboxPermTable,
  SandboxTable,
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
} from "./types_auto_gen";
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
  HandbookInfoTable!: HandbookInfoTable;
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
  CharWordTable!: CharWordTable;
  CharmTable!: CharmData;
  ClimbTowerTable!: ClimbTowerTable;
  CrisisTable!: CrisisClientData;
  CrisisV2AppraiseWrap!: CrisisV2AppraiseWrap;
  CrisisV2ConstData!: CrisisV2ConstData;
  CrisisV2SeasonInfo!: CrisisV2SeasonInfo;
  CrisisV2SharedData!: CrisisV2SharedData;
  DisplayMetaTable!: DisplayMetaData;
  EnemyDatabase!: EnemyDatabase;
  EnemyHandbookLevelInfoTable!: EnemyHandbookLevelInfoData;
  EnemyHandbookRaceTable!: EnemyHandbookRaceData;
  EpBreakBuffData!: EPBreakBuffData;
  ExtraBattleLogData!: ExtraBattleLogData;
  HandbookTeamTable!: HandbookTeamData;
  HotUpdateMetaTable!: HotUpdateMetaTable;
  MetaUIDisplayTable!: MetaUIDisplayTable;
  PlayerAvatarTable!: PlayerAvatarData;
  RangeTable!: RangeData;
  ReplicateTable!: ReplicateTable;
  RoguelikeActivityTable!: RoguelikeActivityTable;
  SandboxActTable!: SandboxActTable;
  SandboxBaseConstTable!: SandboxBaseConstTable;
  SandboxMapConstTable!: SandboxMapConstTable;
  SandboxPermTable!: SandboxPermTable;
  SandboxTable!: SandboxTable;
  ShopClientTable!: ShopClientData;
  SkillDataBundle!: SkillDataBundle;
  SpecialOperatorTable!: SpecialOperatorTable;
  StoryData!: StoryData;
  UniEquipData!: UniEquipData;
  ZoneTable!: ZoneTable;
  ArkventTable!: any;

  constructor() {}

  /**
   * 初始化所有 Excel 数据表
   *
   * 从 data/excel/ 目录下批量并行加载所有 JSON 格式的数据表文件
   * （Promise.all 并发读文件 + parse，避免串行 IO），并初始化商店数据。
   * 同一文件被多个 key 引用时先去重，仅读取/解析一次，各 key 共享同一对象引用。
   */
  async init(): Promise<void> {
    const loaders: [keyof Excel, string][] = [
      ["MissionTable", "./data/excel/mission_table.json"],
      ["BattleEquipTable", "./data/excel/battle_equip_table.json"],
      ["BuildingData", "./data/excel/building_data.json"],
      ["CharacterTable", "./data/excel/character_table.json"],
      ["GameDataConst", "./data/excel/gamedata_const.json"],
      ["ItemTable", "./data/excel/item_table.json"],
      ["StageTable", "./data/excel/stage_table.json"],
      ["HandbookInfoTable", "./data/excel/handbook_info_table.json"],
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
      ["CharWordTable", "./data/excel/charword_table.json"],
      ["CharmTable", "./data/excel/charm_table.json"],
      ["ClimbTowerTable", "./data/excel/climb_tower_table.json"],
      ["CrisisTable", "./data/excel/crisis_table.json"],
      ["CrisisV2AppraiseWrap", "./data/excel/crisis_v2_table.json"],
      ["CrisisV2ConstData", "./data/excel/crisis_v2_table.json"],
      ["CrisisV2SeasonInfo", "./data/excel/crisis_v2_table.json"],
      ["CrisisV2SharedData", "./data/excel/crisis_v2_table.json"],
      ["DisplayMetaTable", "./data/excel/display_meta_table.json"],
      ["EnemyDatabase", "./data/excel/enemy_database.json"],
      ["EnemyHandbookLevelInfoTable", "./data/excel/enemy_handbook_table.json"],
      ["EnemyHandbookRaceTable", "./data/excel/enemy_handbook_table.json"],
      ["EpBreakBuffData", "./data/excel/ep_breakbuff_table.json"],
      ["ExtraBattleLogData", "./data/excel/extra_battlelog_table.json"],
      ["HandbookTeamTable", "./data/excel/handbook_team_table.json"],
      ["HotUpdateMetaTable", "./data/excel/hotupdate_meta_table.json"],
      ["MetaUIDisplayTable", "./data/excel/meta_ui_table.json"],
      ["PlayerAvatarTable", "./data/excel/player_avatar_table.json"],
      ["RangeTable", "./data/excel/range_table.json"],
      ["ReplicateTable", "./data/excel/replicate_table.json"],
      ["RoguelikeActivityTable", "./data/excel/roguelike_table.json"],
      ["SandboxActTable", "./data/excel/sandbox_table.json"],
      ["SandboxBaseConstTable", "./data/excel/sandbox_table.json"],
      ["SandboxMapConstTable", "./data/excel/sandbox_table.json"],
      ["SandboxPermTable", "./data/excel/sandbox_perm_table.json"],
      ["SandboxTable", "./data/excel/sandbox_table.json"],
      ["ShopClientTable", "./data/excel/shop_client_table.json"],
      ["SkillDataBundle", "./data/excel/skill_table.json"],
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