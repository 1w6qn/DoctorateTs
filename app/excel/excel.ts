
import { CharacterData } from "./character_table";
import { BattleEquipPack } from "./battle_equip_table";
import { BuildingData } from "./building_data";
import { GameDataConsts } from "./gamedata_const";
import { ServerItemTable } from "./item_table";
import { StageTable } from "./stage_table";
import { HandbookInfoTable } from './handbook_info_table';
import { CheckinTable } from "./checkin_table";
import { StoryReviewMetaTable } from "./story_review_meta_table";
import { GachaData } from "./gacha_table";
export class Excel {
    BattleEquipTable!: { [key: string]: BattleEquipPack; };
    BuildingData!: BuildingData;
    CharacterTable!: { [key: string]: CharacterData; };
    GameDataConst!: GameDataConsts;
    ItemTable!: ServerItemTable;
    StageTable!: StageTable;
    HandbookInfoTable!: HandbookInfoTable;
    CheckinTable!: CheckinTable;
    StoryReviewMetaTable!: StoryReviewMetaTable;
    GachaTable!: GachaData;
    constructor() {
        this.init()
    }
    async init():Promise<void> {
        this.BattleEquipTable=(await import("../../data/excel/battle_equip_table.json")).default as {[key:string]:BattleEquipPack}
        this.BuildingData=await import("../../data/excel/building_data.json") as BuildingData
        this.CharacterTable=(await import("../../data/excel/character_table.json")).default as {[key:string]:CharacterData}
        this.GameDataConst=await import("../../data/excel/gamedata_const.json")
        this.ItemTable=await import("../../data/excel/item_table.json")
        this.StageTable=(await import("../../data/excel/stage_table.json")).default as StageTable
        this.HandbookInfoTable=await import('../../data/excel/handbook_info_table.json')
        this.CheckinTable=await import("../../data/excel/checkin_table.json")
        this.StoryReviewMetaTable=await import("../../data/excel/story_review_meta_table.json")
        this.GachaTable=await import("../../data/excel/gacha_table.json")
    }
}
export default new Excel()
