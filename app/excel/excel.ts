
import { CharacterData } from "./character_table";
import CharacterTable from "../../data/excel/character_table.json"
import { BattleEquipPack } from "./battle_equip_table";
import BattleEquipTable from "../../data/excel/battle_equip_table.json"
import BuildingDataJson from "../../data/excel/building_data.json"
import { BuildingData } from "./building_data";
export class Excel {
    //AudioData:AudioData
    BattleEquipTable:{[key:string]:BattleEquipPack}
    BuildingData:BuildingData
    CharacterTable: {[key: string]: CharacterData}

    constructor() {
        //this.AudioData=AudioDataJson as AudioData
        this.BattleEquipTable=BattleEquipTable as {[key:string]:BattleEquipPack}
        this.BuildingData=BuildingDataJson as BuildingData
        this.CharacterTable=CharacterTable as {[key: string]: CharacterData}
    }
}
