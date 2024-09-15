import excel from "@excel/excel";
import EventEmitter from "events";
import {PlayerCharacter, PlayerCharEquipInfo, PlayerCharPatch, PlayerCharSkill} from "@game/model/character";
import {CharacterData} from "@excel/character_table";

export class Character{
    _data:PlayerCharacter
    _info!:CharacterData
    _trigger:EventEmitter;
    constructor(data:PlayerCharacter,_trigger:EventEmitter){
        this._data = data;
        this._trigger = _trigger;
        this.init();
    }
    async init(){
        await excel.initPromise;
        this._info = excel.CharacterTable[this._data.charId];
        this._trigger.on("evolveChar",(destEvolvePhase:number)=>{
            excel.SkinTable.buildinEvolveMap
            this.evolve(destEvolvePhase)
        })
    }
    evolve(destEvolvePhase:number){
        this._data.evolvePhase = destEvolvePhase;

    }
    toJSON():PlayerCharacter{
        return this._data
    }
}