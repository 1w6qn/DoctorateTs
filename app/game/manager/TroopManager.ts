import EventEmitter from "events";
import { PlayerCharacter } from "../model/character";
import excel from "app/excel/excel";

export class TroopManager {
    chars: PlayerCharacter[]
    get curCharInstId(): number {
        return this.chars.length;
    }
    _trigger: EventEmitter
    constructor(chars: {[key:string]:PlayerCharacter},trigger:EventEmitter) {
        this.chars = Object.values(chars);
        
        this._trigger = trigger;
        this._trigger.on("gainNewChar", this.gainNewCharacter.bind(this))
    }

    getCharacterByCharId(charId: string): PlayerCharacter {
        return this.chars.find(char => char.charId === charId) as PlayerCharacter;
    }
    getCharacterByInstId(instId: number): PlayerCharacter {
        return this.chars.at(instId-1) as PlayerCharacter;
    }
    gainNewCharacter(charId: string): void {
        this.chars.push({
            "instId": this.curCharInstId,
            "charId": charId,
            "favorPoint": 0,
            "potentialRank": 0,
            "mainSkillLvl": 1,
            "skin": `${charId}#1`,
            "level": 1,
            "exp": 0,
            "evolvePhase": 0,
            "defaultSkillIndex": -1,
            "gainTime": new Date().getTime(),
            "skills": [],
            "currentEquip": null,
            "equip": {},
            "voiceLan": "CN_MANDARIN"
        } as PlayerCharacter)
        this._trigger.emit("gainNewChar", charId)
    }
    upgradeCharacter(instId: number, expMats: {id: string, count: number}[]): void {
        let char = this.getCharacterByInstId(instId);
        let expMap=excel.GameDataConst.characterExpMap;
        const m = {"2001": 200, "2002": 400, "2003": 1000, "2004": 2000};
        let exp = 0, gold_ = 0;
        const charId = char.charId;
        const evolvePhase = char.evolvePhase;
        const rarity = parseInt(excel.CharacterTable[charId].rarity.slice(-1));
        //TODO
        this._trigger.emit("costItems", expMats)
        this._trigger.emit("costGold", expMats)
    }
    evolveCharacter(instId: number): void {
        let char = this.getCharacterByInstId(instId);
        //TODO
    }
    boostPotential(instId: number, itemId:string){
        this._trigger.emit("costItems", [{id:itemId, count:1}])
        this.chars[instId-1].potentialRank += 1;
    }
    toJson():{[key:string]:PlayerCharacter} {
        let sorted = Object.values(this.chars).sort((a, b) => a.instId - b.instId)
        return Object.assign({}, ...sorted);
    }

}