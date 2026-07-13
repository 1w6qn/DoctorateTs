/**
 * Excel 数据表管理模块
 * 
 * 负责加载和管理所有游戏配置数据表（Excel 数据），包括角色、关卡、物品、抽卡等数据。
 * 所有数据表在服务器启动时加载，运行时只读访问。
 */

import { CharacterTable } from "./character_table";
import { BattleEquipTable } from "./battle_equip_table";
import { BuildingData } from "./building_data";
import { GameDataConsts } from "./gamedata_const";
import { ServerItemTable } from "./item_table";
import { StageTable } from "./stage_table";
import { HandbookInfoTable } from "./handbook_info_table";
import { CheckinTable } from "./checkin_table";
import { StoryReviewMetaTable } from "./story_review_meta_table";
import { GachaData } from "./gacha_table";
import { MissionTable } from "./mission_table";
import { RoguelikeTopicTable } from "./roguelike_topic_table";
import { UniEquipTable } from "./uniequip_table";
import { FavorTable } from "./favor_table";
import { StoryReviewTable } from "./story_review_table";
import { MedalData } from "./medal_table";
import { GachaDetailTable } from "./gacha_detail_table";
import { CharMetaTable } from "./char_meta_table";
import { SkinTable } from "./skin_table";
import { OpenServerSchedule } from "./open_server_table";
import { readJson } from "@utils/file";
import { RoguelikeConst } from "@excel/roguelike_consts";
import { ShopData } from "@excel/shop";
import { RetroStageTable } from "@excel/retro_table";

/**
 * Excel 数据表管理类
 * 
 * 聚合所有游戏配置数据表，提供统一的访问接口。
 */
export class Excel {
  /** 战斗装备数据表 */
  BattleEquipTable!: BattleEquipTable;
  /** 基建数据表 */
  BuildingData!: BuildingData;
  /** 角色数据表 */
  CharacterTable!: CharacterTable;
  /** 游戏常量数据表 */
  GameDataConst!: GameDataConsts;
  /** 物品数据表 */
  ItemTable!: ServerItemTable;
  /** 关卡数据表 */
  StageTable!: StageTable;
  /** 图鉴信息数据表 */
  HandbookInfoTable!: HandbookInfoTable;
  /** 签到数据表 */
  CheckinTable!: CheckinTable;
  /** 故事回顾元数据表 */
  StoryReviewMetaTable!: StoryReviewMetaTable;
  /** 抽卡数据表 */
  GachaTable!: GachaData;
  /** 任务数据表 */
  MissionTable!: MissionTable;
  /** 肉鸽主题数据表 */
  RoguelikeTopicTable!: RoguelikeTopicTable;
  /** 模组数据表 */
  UniequipTable!: UniEquipTable;
  /** 故事回顾数据表 */
  StoryReviewTable!: StoryReviewTable;
  /** 信赖度数据表 */
  FavorTable!: FavorTable;
  /** 勋章数据表 */
  MedalTable!: MedalData;
  /** 抽卡详情数据表 */
  GachaDetailTable!: GachaDetailTable;
  /** 角色元数据表 */
  CharMetaTable!: CharMetaTable;
  /** 皮肤数据表 */
  SkinTable!: SkinTable;
  /** 开服活动数据表 */
  OpenServerTable!: OpenServerSchedule;
  /** 复刻关卡数据表 */
  RetroTable!: RetroStageTable;
  /** 肉鸽常量配置 */
  RoguelikeConsts!: { [key: string]: RoguelikeConst };
  /** 商店数据表 */
  ShopTable!: ShopData;

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
    this.BattleEquipTable = await readJson<BattleEquipTable>(
      "./data/excel/battle_equip_table.json",
    );
    this.BuildingData = await readJson<BuildingData>(
      "./data/excel/building_data.json",
    );
    this.CharacterTable = await readJson<CharacterTable>(
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
    this.CheckinTable = await readJson<CheckinTable>(
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
    this.StoryReviewTable = await readJson<StoryReviewTable>(
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
    this.RoguelikeConsts = await readJson<{ [key: string]: RoguelikeConst }>(
      "./data/rlv2.json",
    );
    console.timeEnd("[excel][loaded]");
    console.log("[excel] 21 excels loaded");
    this.ShopTable = new ShopData();
    await this.ShopTable.init();
    console.time("[excel][shop][loaded]");
    console.log("[excel][shop] 10 shops loaded");
    console.timeEnd("[excel][shop][loaded]");
  }
}

/** Excel 数据表管理实例 */
export default new Excel();