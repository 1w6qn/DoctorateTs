
import { CharacterData } from "./character_table";
import CharacterTable from "../../data/excel/character_table.json"
import { BattleEquipPack } from "./battle_equip_table";
import BattleEquipTable from "../../data/excel/battle_equip_table.json"
import BuildingDataJson from "../../data/excel/building_data.json"
import { BuildingData } from "./building_data";
import { GameDataConsts } from "./gamedata_const";
import GameDataConst from "../../data/excel/gamedata_const.json"
import { ServerItemTable } from "./item_table";
import ServerItemTableJson from "../../data/excel/item_table.json"
import { StageTable } from "./stage_table";
import StageTableJson from "../../data/excel/stage_table.json"
import { HandbookInfoTable } from './handbook_info_table';
import HandbookInfoTableJson from '../../data/excel/handbook_info_table.json';
import { CheckinTable } from "./checkin_table";
import CheckinTableJson from "../../data/excel/checkin_table.json"
import { StoryReviewMetaTable } from "./story_review_meta_table";
import StoryReviewMetaTableJson from "../../data/excel/story_review_meta_table.json"
export class Excel {
    //AudioData:AudioData
    BattleEquipTable:{[key:string]:BattleEquipPack}
    BuildingData:BuildingData
    CharacterTable: {[key: string]: CharacterData}
    GameDataConst:GameDataConsts
    ItemTable:ServerItemTable
    StageTable:StageTable
    HandbookInfoTable:HandbookInfoTable
    CheckinTable:CheckinTable
    StoryReviewMetaTable:StoryReviewMetaTable
    constructor() {
        //this.AudioData=AudioDataJson as AudioData
        this.BattleEquipTable=BattleEquipTable as {[key:string]:BattleEquipPack}
        this.BuildingData=BuildingDataJson as BuildingData
        this.CharacterTable=CharacterTable as {[key: string]: CharacterData}
        this.GameDataConst=GameDataConst
        this.ItemTable=ServerItemTableJson
        this.StageTable=StageTableJson as StageTable
        this.HandbookInfoTable=HandbookInfoTableJson 
        this.CheckinTable=CheckinTableJson
        this.StoryReviewMetaTable=StoryReviewMetaTableJson
    }
}
export default new Excel()
