import EventEmitter from "events";
import { PlayerCharacter, PlayerSquad, PlayerSquadItem, PlayerTroop } from "../model/character";
import excel from "../../excel/excel";
import { ItemBundle } from "app/excel/character_table";

export class TroopManager {
    
    
    chars: PlayerCharacter[]
    squads: PlayerSquad[]
    get curCharInstId(): number {
        return this.chars.length+1;
    }
    get curSquadCount(): number {
        return this.squads.length;
    }
    _trigger: EventEmitter
    _troop: PlayerTroop
    constructor(
        troop: PlayerTroop,
        trigger: EventEmitter
    ) {
        this._troop=troop;
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
    upgradeChar(instId: number, expMats: ItemBundle[]): void {
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
            expTotal += expItems[expMats[i].id].gainExp*expMats[i].count;
        }
        char.exp += expTotal;
        while(true){
            if (char.exp >= expMap[evolvePhase][char.level-1]){
                char.exp -= expMap[evolvePhase][char.level-1];
                char.level += 1;
                gold += goldMap[evolvePhase][char.level-1]
                if (char.level >= maxLevel) {
                    char.level = maxLevel;
                    char.exp=0
                    break;
                }
            }else{
                break;
            }
        }
        //TODO
        this._trigger.emit("useItems", expMats.concat([{ id: "4001", count: gold } as ItemBundle]))
    }
    evolveChar(instId: number,destEvolvePhase:number): void {
        let char = this.getCharacterByInstId(instId);
        const evolveCost=excel.CharacterTable[char.charId].phases[destEvolvePhase].evolveCost as ItemBundle[];
        const rarity = parseInt(excel.CharacterTable[char.charId].rarity.slice(-1));
        const goldCost=excel.GameDataConst.evolveGoldCost[rarity][destEvolvePhase];
        this._trigger.emit("useItems", evolveCost.concat([{ id: "4001", count: goldCost } as ItemBundle]))
        char.evolvePhase=destEvolvePhase;
        char.level=1;
        char.exp=0;
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
    squadFormation(squadId: number, slots: PlayerSquadItem[]): void {
        this.squads[squadId].slots = slots;
    }
    changeSquadName(squadId: number, name: string): void {
        this.squads[squadId].name = name;
    }
    changeMarkStar(chrIdDict: {[key:string]:number}) {
        //TODO
    }
    changeSecretary(charInstId: number, skinId: string) {
        let charId=this.getCharacterByInstId(charInstId).charId;
        this._trigger.emit("status:change:secretary",charId,skinId)
    }
    decomposePotentialItem(charInstIdList:string[]):ItemBundle[]{
        let costs:ItemBundle[]=[]
        let items:ItemBundle[]=charInstIdList.reduce((acc,charInstId)=>{
            let char=this.getCharacterByInstId(parseInt(charInstId));
            let rarity=parseInt(excel.CharacterTable[char.charId].rarity.slice(-1))
            let potentialItemId=excel.CharacterTable[char.charId].potentialItemId as string
            costs.push({id:potentialItemId,count:-1})
            acc.push(excel.GachaTable.potentialMaterialConverter.items[`${rarity-1}`])
            return acc
        },[] as ItemBundle[])
        this._trigger.emit("useItems",costs)
        this._trigger.emit("gainItems",items)
        return items
    }
    decomposeClassicPotentialItem(charInstIdList:string[]):ItemBundle[]{
        let costs:ItemBundle[]=[]
        let items:ItemBundle[]=charInstIdList.reduce((acc,charInstId)=>{
            let char=this.getCharacterByInstId(parseInt(charInstId));
            let rarity=parseInt(excel.CharacterTable[char.charId].rarity.slice(-1))
            let potentialItemId=excel.CharacterTable[char.charId].potentialItemId as string
            costs.push({id:potentialItemId,count:-1})
            acc.push(excel.GachaTable.classicPotentialMaterialConverter.items[`${rarity-1}`])
            return acc
        },[] as ItemBundle[])
        this._trigger.emit("useItems",costs)
        this._trigger.emit("gainItems",items)
        return items
    }
    toJSON(): PlayerTroop {
        return {
            curCharInstId:this.curCharInstId,
            curSquadCount:this.curSquadCount,
            chars: this.chars.reduce((acc, char) => {
                acc[char.instId.toString()] = char;
                return acc;
              },{} as {[key:string]:PlayerCharacter}),
            squads:this.squads.reduce((acc, squad) => {
                acc[squad.squadId.toString()] = squad;
                return acc;
              },{} as {[key:string]:PlayerSquad}),
            addon:this._troop.addon,
            charMission:this._troop.charMission,
            charGroup:this.chars.reduce((acc, char) => {
                acc[char.charId] = {favorPoint:char.favorPoint}
                return acc
            },{} as {[key:string]:{favorPoint:number}}),
        };
    }

}