import EventEmitter from "events";
import { PlayerCharacter, PlayerSquad } from "../model/character";
import excel from "app/excel/excel";
import { ItemBundle } from "app/excel/character_table";

export class TroopManager {
    chars: PlayerCharacter[]
    squads:PlayerSquad[]
    get curCharInstId(): number {
        return this.chars.length;
    }
    _trigger: EventEmitter
    constructor(
        chars: {[key:string]:PlayerCharacter},
        squads:{ [key: string]: PlayerSquad },
        trigger:EventEmitter
    ) {
        this.chars = Object.values(chars);
        this.squads = Object.values(squads);
        this._trigger = trigger;
        this._trigger.on("gainNewChar", this.gainNewCharacter.bind(this))
    }

    getCharacterByCharId(charId: string): PlayerCharacter {
        return this.chars.find(char => char.charId === charId) as PlayerCharacter;
    }
    getCharacterByInstId(instId: number): PlayerCharacter {
        return this.chars.at(instId-1) as PlayerCharacter;
    }
    gainChar(charId: string,...args: any[]):void {
        if (this.chars.some(char => char.charId === charId)) {
            let potentId=excel.CharacterTable[charId].potentialItemId as string;
            this._trigger.emit("gainItems", [{id:potentId, count:1}])
        }else{
            this.gainNewCharacter(charId);
        }
        
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
        
    }
    upgradeCharacter(instId: number, expMats: ItemBundle[]): void {
        let char = this.getCharacterByInstId(instId);
        const expMap=excel.GameDataConst.characterExpMap;
        const goldMap=excel.GameDataConst.characterUpgradeCostMap;
        const expItemMap:{[key:string]:number} = {"2001": 200, "2002": 400, "2003": 1000, "2004": 2000};
        let expTotal = 0,exp=0,gold=0;
        const charId = char.charId;
        const evolvePhase = char.evolvePhase;
        const rarity = parseInt(excel.CharacterTable[charId].rarity.slice(-1));
        const maxLevel = excel.GameDataConst.maxLevel[rarity-1][evolvePhase];
        for (let i = 0; i < expMats.length; i++) {
            expTotal += expItemMap[expMats[i].id];
        }
        for (let i = char.level-1; i < maxLevel; i++) {
            if (exp+expMap[evolvePhase][i] > expTotal) {
                break;
            }
            exp+=expMap[evolvePhase][i];
            gold+=goldMap[evolvePhase][i]
        }
        //TODO
        this._trigger.emit("useItems", expMats.concat([{id: "4001", count: gold}as ItemBundle]))
    }
    evolveCharacter(instId: number): void {
        let char = this.getCharacterByInstId(instId);
        //TODO
    }
    boostPotential(instId: number, itemId:string): void {
        this._trigger.emit("gainItems", [{id:itemId, count:1}])
        this.chars[instId-1].potentialRank += 1;
        //TODO 触发事件
    }
    toJson():{[key:string]:PlayerCharacter} {
        let sorted = Object.values(this.chars).sort((a, b) => a.instId - b.instId)
        return Object.assign({}, ...sorted);
    }

}