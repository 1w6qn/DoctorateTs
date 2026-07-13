/**
 * Excel 数据表管理模块
 * 
 * 负责加载和管理所有游戏配置数据表（Excel 数据），包括角色、关卡、物品、抽卡等数据。
 * 所有数据表在服务器启动时加载，运行时只读访问。
 */

import { readJson } from "@utils/file";
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

  constructor() {}

  /**
   * 初始化所有 Excel 数据表
   * 
   * 从 data/excel/ 目录下加载所有 JSON 格式的数据表文件，
   * 并初始化商店数据。
   */
  async init(): Promise<void> {
    console.time("[excel][loaded]");
    this.MissionTable = await readJson<MissionTable>(
      "./data/excel/mission_table.json",
    );
    this.BattleEquipTable = await readJson<BattleEquipPack>(
      "./data/excel/battle_equip_table.json",
    );
    this.BuildingData = await readJson<BuildingData>(
      "./data/excel/building_data.json",
    );
    this.CharacterTable = await readJson<CharacterData>(
      "./data/excel/character_table.json",
    );
    this.GameDataConst = await readJson<GameDataConsts>(
      "./data/excel/gamedata_const.json",
    );
    this.ItemTable = await readJson<ServerItemTable>(
      "./data/excel/item_table.json",
    );
    this.StageTable = await readJson<StageTable>(
      "./data/excel/stage_table.json",
    );
    this.HandbookInfoTable = await readJson<HandbookInfoTable>(
      "./data/excel/handbook_info_table.json",
    );
    this.CheckinTable = await readJson<CheckInTable>(
      "./data/excel/checkin_table.json",
    );
    this.StoryReviewMetaTable = await readJson<StoryReviewMetaTable>(
      "./data/excel/story_review_meta_table.json",
    );
    this.GachaTable = await readJson<GachaData>(
      "./data/excel/gacha_table.json",
    );
    this.RoguelikeTopicTable = await readJson<RoguelikeTopicTable>(
      "./data/excel/roguelike_topic_table.json",
    );
    this.UniequipTable = await readJson<UniEquipTable>(
      "./data/excel/uniequip_table.json",
    );
    this.FavorTable = await readJson<FavorTable>(
      "./data/excel/favor_table.json",
    );
    this.StoryReviewTable = await readJson<StoryReviewGroupClientData>(
      "./data/excel/story_review_table.json",
    );
    this.MedalTable = await readJson<MedalData>(
      "./data/excel/medal_table.json",
    );
    this.CharMetaTable = await readJson<CharMetaTable>(
      "./data/excel/char_meta_table.json",
    );
    this.SkinTable = await readJson<SkinTable>("./data/excel/skin_table.json");
    this.OpenServerTable = await readJson<OpenServerSchedule>(
      "./data/excel/open_server_table.json",
    );
    this.RetroTable = await readJson<RetroStageTable>(
      "./data/excel/retro_table.json",
    );
    this.GachaDetailTable = await readJson<GachaDetailTable>(
      "./data/gacha_detail_table.json",
    );
    this.ActivityTable = await readJson<ActivityTable>(
      "./data/excel/activity_table.json",
    );
    this.CampaignTable = await readJson<CampaignTable>(
      "./data/excel/campaign_table.json",
    );
    this.ChapterTable = await readJson<{ [key: string]: ChapterData }>(
      "./data/excel/chapter_table.json",
    );
    this.CharMasterTable = await readJson<{ [key: string]: CharMasterBasicData }>(
      "./data/excel/char_master_table.json",
    );
    this.CharPatchTable = await readJson<CharPatchData>(
      "./data/excel/char_patch_table.json",
    );
    this.CharWordTable = await readJson<CharWordTable>(
      "./data/excel/charword_table.json",
    );
    this.CharmTable = await readJson<CharmData>(
      "./data/excel/charm_table.json",
    );
    this.ClimbTowerTable = await readJson<ClimbTowerTable>(
      "./data/excel/climb_tower_table.json",
    );
    this.CrisisTable = await readJson<CrisisClientData>(
      "./data/excel/crisis_table.json",
    );
    this.CrisisV2AppraiseWrap = await readJson<CrisisV2AppraiseWrap>(
      "./data/excel/crisis_v2_table.json",
    );
    this.CrisisV2ConstData = await readJson<CrisisV2ConstData>(
      "./data/excel/crisis_v2_table.json",
    );
    this.CrisisV2SeasonInfo = await readJson<CrisisV2SeasonInfo>(
      "./data/excel/crisis_v2_table.json",
    );
    this.CrisisV2SharedData = await readJson<CrisisV2SharedData>(
      "./data/excel/crisis_v2_table.json",
    );
    this.DisplayMetaTable = await readJson<DisplayMetaData>(
      "./data/excel/display_meta_table.json",
    );
    this.EnemyDatabase = await readJson<EnemyDatabase>(
      "./data/excel/enemy_database.json",
    );
    this.EnemyHandbookLevelInfoTable = await readJson<EnemyHandbookLevelInfoData>(
      "./data/excel/enemy_handbook_table.json",
    );
    this.EnemyHandbookRaceTable = await readJson<EnemyHandbookRaceData>(
      "./data/excel/enemy_handbook_table.json",
    );
    this.EpBreakBuffData = await readJson<EPBreakBuffData>(
      "./data/excel/ep_breakbuff_table.json",
    );
    this.ExtraBattleLogData = await readJson<ExtraBattleLogData>(
      "./data/excel/extra_battlelog_table.json",
    );
    this.HandbookTeamTable = await readJson<HandbookTeamData>(
      "./data/excel/handbook_team_table.json",
    );
    this.HotUpdateMetaTable = await readJson<HotUpdateMetaTable>(
      "./data/excel/hotupdate_meta_table.json",
    );
    this.MetaUIDisplayTable = await readJson<MetaUIDisplayTable>(
      "./data/excel/meta_ui_table.json",
    );
    this.PlayerAvatarTable = await readJson<PlayerAvatarData>(
      "./data/excel/player_avatar_table.json",
    );
    this.RangeTable = await readJson<RangeData>(
      "./data/excel/range_table.json",
    );
    this.ReplicateTable = await readJson<ReplicateTable>(
      "./data/excel/replicate_table.json",
    );
    this.RoguelikeActivityTable = await readJson<RoguelikeActivityTable>(
      "./data/excel/roguelike_table.json",
    );
    this.SandboxActTable = await readJson<SandboxActTable>(
      "./data/excel/sandbox_table.json",
    );
    this.SandboxBaseConstTable = await readJson<SandboxBaseConstTable>(
      "./data/excel/sandbox_table.json",
    );
    this.SandboxMapConstTable = await readJson<SandboxMapConstTable>(
      "./data/excel/sandbox_table.json",
    );
    this.SandboxPermTable = await readJson<SandboxPermTable>(
      "./data/excel/sandbox_perm_table.json",
    );
    this.SandboxTable = await readJson<SandboxTable>(
      "./data/excel/sandbox_table.json",
    );
    this.ShopClientTable = await readJson<ShopClientData>(
      "./data/excel/shop_client_table.json",
    );
    this.SkillDataBundle = await readJson<SkillDataBundle>(
      "./data/excel/skill_table.json",
    );
    this.SpecialOperatorTable = await readJson<SpecialOperatorTable>(
      "./data/excel/special_operator_table.json",
    );
    this.StoryData = await readJson<StoryData>(
      "./data/excel/story_table.json",
    );
    this.UniEquipData = await readJson<UniEquipData>(
      "./data/excel/uniequip_data.json",
    );
    this.ZoneTable = await readJson<ZoneTable>(
      "./data/excel/zone_table.json",
    );
    this.RoguelikeConsts = await readJson<{ [key: string]: RoguelikeConst }>(
      "./data/rlv2.json",
    );
    console.timeEnd("[excel][loaded]");
    console.log("[excel] 44 excels loaded");
    this.ShopTable = new ShopData();
    await this.ShopTable.init();
    console.time("[excel][shop][loaded]");
    console.log("[excel][shop] 10 shops loaded");
    console.timeEnd("[excel][shop][loaded]");
  }
}

/** Excel 数据表管理实例 */
export default new Excel();