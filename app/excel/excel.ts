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

export class Excel {
  BattleEquipTable!: BattleEquipTable;
  BuildingData!: BuildingData;
  CharacterTable!: CharacterTable;
  GameDataConst!: GameDataConsts;
  ItemTable!: ServerItemTable;
  StageTable!: StageTable;
  HandbookInfoTable!: HandbookInfoTable;
  CheckinTable!: CheckinTable;
  StoryReviewMetaTable!: StoryReviewMetaTable;
  GachaTable!: GachaData;
  MissionTable!: MissionTable;
  RoguelikeTopicTable!: RoguelikeTopicTable;
  UniequipTable!: UniEquipTable;
  StoryReviewTable!: StoryReviewTable;
  FavorTable!: FavorTable;
  MedalTable!: MedalData;
  GachaDetailTable!: GachaDetailTable;
  CharMetaTable!: CharMetaTable;
  SkinTable!: SkinTable;
  OpenServerTable!: OpenServerSchedule;

  constructor() {}

  async init(): Promise<void> {
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
    this.GachaDetailTable = await readJson("./data/gacha_detail_table.json");
  }
}

export default new Excel();
