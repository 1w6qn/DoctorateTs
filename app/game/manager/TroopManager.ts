import EventEmitter from "events";
import { PlayerCharacter, PlayerSquad, PlayerTroop } from "../model/character";
import excel from "../../excel/excel";
import { ItemBundle } from "app/excel/character_table";

export class TroopManager {
    chars: PlayerCharacter[]
    squads: PlayerSquad[]
    get curCharInstId(): number {
        return this.chars.length;
    }
    _trigger: EventEmitter
    constructor(
        troop: PlayerTroop,
        trigger: EventEmitter
    ) {
        this.chars = Object.values(troop.chars);
        this.squads = Object.values(troop.squads);
        this._trigger = trigger;
        this._trigger.on("gainNewChar", this.gainNewCharacter.bind(this))
    }

    getCharacterByCharId(charId: string): PlayerCharacter {
        return this.chars.find(char => char.charId === charId) as PlayerCharacter;
    }
    getCharacterByInstId(instId: number): PlayerCharacter {
        return this.chars.at(instId - 1) as PlayerCharacter;
    }
    gainChar(charId: string, ...args: any[]): void {
        if (this.chars.some(char => char.charId === charId)) {
            let potentId = excel.CharacterTable[charId].potentialItemId as string;
            this._trigger.emit("gainItems", [{ id: potentId, count: 1 }])
        } else {
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
        const expMap = excel.GameDataConst.characterExpMap;
        const goldMap = excel.GameDataConst.characterUpgradeCostMap;
        const expItems=excel.ItemTable.expItems;
        let expTotal = 0, exp = 0, gold = 0;
        const charId = char.charId;
        const evolvePhase = char.evolvePhase;
        const rarity = parseInt(excel.CharacterTable[charId].rarity.slice(-1));
        const maxLevel = excel.GameDataConst.maxLevel[rarity - 1][evolvePhase];
        for (let i = 0; i < expMats.length; i++) {
            expTotal += expItems[expMats[i].id].gainExp;
        }
        for (let i = char.level - 1; i < maxLevel; i++) {
            if (exp + expMap[evolvePhase][i] > expTotal) {
                break;
            }
            exp += expMap[evolvePhase][i];
            gold += goldMap[evolvePhase][i]
        }
        //TODO
        this._trigger.emit("useItems", expMats.concat([{ id: "4001", count: gold } as ItemBundle]))
    }
    evolveCharacter(instId: number,destEvolvePhase:number): void {
        let char = this.getCharacterByInstId(instId);
        const evolveCost=excel.CharacterTable[char.charId].phases[destEvolvePhase].evolveCost as ItemBundle[];
        const rarity = parseInt(excel.CharacterTable[char.charId].rarity.slice(-1));
        const goldCost=excel.GameDataConst.evolveGoldCost[rarity][destEvolvePhase];
        this._trigger.emit("useItems", evolveCost.concat([{ id: "4001", count: goldCost } as ItemBundle]))
        //TODO
        if(destEvolvePhase==2){
            this.chars[instId - 1].skinId=char.charId+"#2";
        }
        this._trigger.emit("CharEvolved",{instId:instId,destEvolvePhase:destEvolvePhase})
    }
    boostPotential(instId: number, itemId: string,targetRank: number): void {
        this._trigger.emit("useItems", [{ id: itemId, count: 1 }])
        this.chars[instId - 1].potentialRank=targetRank;
        //TODO 触发事件
    }
    setDefaultSkill(instId: number, defaultSkillIndex: number): void {
        this.chars[instId - 1].defaultSkillIndex = defaultSkillIndex;
    }
    changeCharSkin(instId: number, skinId: string): void {
        this.chars[instId - 1].skinId = skinId;
    }
    setEquipment(instId: number, equipId: string): void {
        this.chars[instId - 1].currentEquip = equipId;
    }
    changeCharTemplate(instId: number, templateId: string): void {
        this.chars[instId - 1].currentTmpl = templateId;
    }
    batchSetCharVoiceLan(voiceLan: string): void {
        this.chars.forEach(char => char.voiceLan = voiceLan);
    }
    upgradeSkill(instId: number, targetLevel: number): void {
        let char = this.getCharacterByInstId(instId);
        this._trigger.emit("useItems", excel.CharacterTable[char.charId].allSkillLvlup[targetLevel - 2].lvlUpCost as ItemBundle[])
        char.mainSkillLvl =targetLevel;
    }
    toJson(): { [key: string]: PlayerCharacter } {
        let sorted = Object.values(this.chars).sort((a, b) => a.instId - b.instId)
        return Object.assign({}, ...sorted);
    }

}