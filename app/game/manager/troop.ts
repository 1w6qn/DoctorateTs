import EventEmitter from "events";
import { PlayerCharacter, PlayerHandBookAddon, PlayerSquad, PlayerSquadItem, PlayerTroop } from "../model/character";
import excel from "../../excel/excel";
import { ItemBundle } from "app/excel/character_table";
import { PlayerDataModel } from "../model/playerdata";
import { GachaResult } from "../model/gacha";
import { pick } from "lodash";
import { now } from "@utils/time";

export class TroopManager {


    chars: { [key: string]: PlayerCharacter }
    squads: { [key: string]: PlayerSquad }
    addon:{[key:string]:PlayerHandBookAddon}
    charMission: { [key: string]: {[key:string]:number} }
    
    get curCharInstId(): number {
        return Object.keys(this.chars).length + 1;
    }
    get curSquadCount(): number {
        return Object.keys(this.squads).length;
    }
    _trigger: EventEmitter
    _playerdata: PlayerDataModel;
    constructor(playerdata: PlayerDataModel,trigger: EventEmitter) {
        this._playerdata = playerdata;
        this.chars = playerdata.troop.chars; 
        this.squads = playerdata.troop.squads;
        this.addon = playerdata.troop.addon;
        this.charMission = playerdata.troop.charMission;
        this._trigger = trigger;
        this._trigger.on("char:get", this.gainChar.bind(this))
        this._trigger.on("game:fix", this.fix.bind(this))
    }

    getCharacterByCharId(charId: string): PlayerCharacter {
        return Object.values(this.chars).find(char => char.charId === charId) as PlayerCharacter;
    }
    getCharacterByInstId(instId: number): PlayerCharacter {
        return this.chars[instId] as PlayerCharacter;
    }
    gainChar(charId: string, args: { from: string, extraItem?: ItemBundle } = { from: "NORMAL" }): GachaResult {
        let isNew = Object.values(this.chars).some(char => char.charId === charId) ? 0 : 1
        let charInstId = 0
        let items: ItemBundle[] = []
        let info = excel.CharacterTable[charId]
        console.log(`[TroopManager] 获得${info.rarity.slice(-1)}星干员 ${info.name} ${isNew} ${args.from}`)
        if (!isNew) {
            charInstId = this.getCharacterByCharId(charId).instId
            let potentId = excel.CharacterTable[charId].potentialItemId as string;
            items.push({ id: potentId, count: 1, type: "MATERIAL" })
            let t = false
            if (this._playerdata.dexNav.character[charId]) {
                t = this._playerdata.dexNav.character[charId].count > 6
            }
            if (args.from == "CLASSIC") {
                switch (excel.CharacterTable[charId].rarity) {
                    case "TIER_6":
                        items.push({ id: "classic_normal_ticket", count: 100 })
                        break;
                    case "TIER_5":
                        items.push({ id: "classic_normal_ticket", count: 50 })
                        break;
                    case "TIER_4":
                        items.push({ id: "classic_normal_ticket", count: 5 })
                        break;
                    case "TIER_3":
                        items.push({ id: "classic_normal_ticket", count: 1 })
                        break;
                    default:
                        break;
                }
            } else {
                switch (excel.CharacterTable[charId].rarity) {
                    case "TIER_6":
                        items.push({ id: "4004", count: t ? 15 : 10 })
                        break;
                    case "TIER_5":
                        items.push({ id: "4004", count: t ? 8 : 5 })
                        break;
                    case "TIER_4":
                        items.push({ id: "4005", count: 30 })
                        break;
                    case "TIER_3":
                        items.push({ id: "4005", count: 5 })
                        break;
                    case "TIER_2":
                        items.push({ id: "4005", count: 1 })
                        break;
                    case "TIER_1":
                        items.push({ id: "4005", count: 1 })
                        break;
                    default:
                        break;
                }
            }

        }
        else {
            charInstId = this.curCharInstId
            this.chars[this.curCharInstId] = {
                "instId": charInstId,
                "charId": charId,
                "favorPoint": 0,
                "potentialRank": 0,
                "mainSkillLvl": 1,
                "skinId": `${charId}#1`,
                "level": 1,
                "exp": 0,
                "evolvePhase": 0,
                "defaultSkillIndex": -1,
                "gainTime": now(),
                "skills": [],
                "currentEquip": null,
                "equip": {},
                "voiceLan": "CN_MANDARIN"
            }
            this._trigger.emit("char:init", this.getCharacterByCharId(charId))
            if (args.from == "CLASSIC") {
                items.push({ id: "classic_normal_ticket", count: 10 })
            } else {
                items.push({ id: "4004", count: 1, type: "HGG_SHD" })
            }
            if (args.extraItem) {
                items.push(args.extraItem)
            }
            this._trigger.emit("game:fix")

        }
        this._trigger.emit("gainItems", items)
        return {
            charInstId: charInstId,
            charId: charId,
            isNew: isNew,
            itemGet: items
        }
    }
    upgradeChar(instId: number, expMats: ItemBundle[]): void {
        let char = this.getCharacterByInstId(instId);
        const expMap = excel.GameDataConst.characterExpMap;
        const goldMap = excel.GameDataConst.characterUpgradeCostMap;
        const expItems = excel.ItemTable.expItems;
        let expTotal = 0, gold = 0;
        const charId = char.charId;
        const evolvePhase = char.evolvePhase;
        const rarity = parseInt(excel.CharacterTable[charId].rarity.slice(-1));
        const maxLevel = excel.GameDataConst.maxLevel[rarity - 1][evolvePhase];
        for (let i = 0; i < expMats.length; i++) {
            expTotal += expItems[expMats[i].id].gainExp * expMats[i].count;
        }
        char.exp += expTotal;
        while (true) {
            if (char.exp >= expMap[evolvePhase][char.level - 1]) {
                char.exp -= expMap[evolvePhase][char.level - 1];
                char.level += 1;
                gold += goldMap[evolvePhase][char.level - 1]
                if (char.level >= maxLevel) {
                    char.level = maxLevel;
                    char.exp = 0
                    break;
                }
            } else {
                break;
            }
        }
        //TODO
        this._trigger.emit("useItems", expMats.push({ id: "4001", count: gold }))
        this._trigger.emit("UpgradeChar", {})
    }
    evolveChar(args:{instId: number, destEvolvePhase: number}): void {
        let char = this.getCharacterByInstId(args.instId);
        const evolveCost = excel.CharacterTable[char.charId].phases[args.destEvolvePhase].evolveCost as ItemBundle[];
        const rarity = parseInt(excel.CharacterTable[char.charId].rarity.slice(-1));
        const goldCost = excel.GameDataConst.evolveGoldCost[rarity][args.destEvolvePhase];
        this._trigger.emit("useItems", evolveCost.concat([{ id: "4001", count: goldCost } as ItemBundle]))
        char.evolvePhase = args.destEvolvePhase;
        char.level = 1;
        char.exp = 0;
        //TODO
        if (args.destEvolvePhase == 2) {
            this.chars[args.instId].skinId = char.charId + "#2";
        }
        this._trigger.emit("EvolveChar", args)
    }
    boostPotential(instId: number, itemId: string, targetRank: number): void {
        this._trigger.emit("useItems", [{ id: itemId, count: 1 }])
        this.chars[instId].potentialRank = targetRank;
        this._trigger.emit("BoostPotential", { targetRank: targetRank })
    }
    setDefaultSkill(instId: number, defaultSkillIndex: number): void {
        this.chars[instId].defaultSkillIndex = defaultSkillIndex;
    }
    upgradeSkill(instId: number, targetLevel: number): void {
        let char = this.getCharacterByInstId(instId);
        this._trigger.emit("useItems", excel.CharacterTable[char.charId].allSkillLvlup[targetLevel - 2].lvlUpCost as ItemBundle[])
        char.mainSkillLvl = targetLevel;
        this._trigger.emit("BoostPotential", { targetLevel: targetLevel })
    }

    changeCharSkin(instId: number, skinId: string): void {
        this.chars[instId].skinId = skinId;
    }
    
    changeCharTemplate(instId: number, templateId: string): void {
        this.chars[instId].currentTmpl = templateId;
    }

    batchSetCharVoiceLan(voiceLan: string): void {
        Object.values(this.chars).forEach(char => char.voiceLan = voiceLan);
    }
    setCharVoiceLan(charList:number[],voiceLan:string){
        charList.forEach(charInstId=>{
            let char = this.getCharacterByInstId(charInstId)
            char.voiceLan=voiceLan
        })
    }
    setEquipment(args: { charInstId: number, templateId: string, equipId: string }): void {
        let char = this.getCharacterByInstId(args.charInstId);
        if (args.templateId) {
            char.tmpl![args.templateId].currentEquip=args.equipId
        }else{
            char.currentEquip=args.equipId
        }
    }
    unlockEquipment(args: { charInstId: number, templateId: string, equipId: string }) {
        let char = this.getCharacterByInstId(args.charInstId);
        if (args.templateId) {
            char.tmpl![args.templateId].equip[args.equipId].hide=0
            char.tmpl![args.templateId].equip[args.equipId].locked=0
        }else{
            char.equip![args.equipId].hide=0
            char.equip![args.equipId].locked=0
        }
        this._trigger.emit("useItems",excel.UniequipTable.equipDict[args.equipId].itemCost!["1"])
        this._trigger.emit("HasEquipmemt",{...char,...args})
    }
    upgradeEquipment(args: { charInstId: number, templateId: string, equipId: string ,targetLevel:number }) {
        let char = this.getCharacterByInstId(args.charInstId);
        let items: ItemBundle[] = []
        if (args.templateId) {
            char.tmpl![args.templateId].equip[args.equipId].level=args.targetLevel
        }else{
            char.equip![args.equipId].level=args.targetLevel
        }
        for (let i = char.equip![args.equipId].level; i < args.targetLevel+1; i++) {
            items.push(...excel.UniequipTable.equipDict[args.equipId].itemCost![i])
        }
        this._trigger.emit("useItems", items)
        this._trigger.emit("HasEquipmemt",{...char,...args})
    }

    changeMarkStar(args:{chrIdDict: { [key: string]: number }}) {
        Object.entries(args.chrIdDict).forEach(([charId, mark]) => {
            let char = this.getCharacterByCharId(charId);
            char.starMark = mark;
        })
    }
    lockChar(){}
    sellChar(){}
    upgradeSpecialization(args: { charInstId: number, skillIndex: number ,targetLevel:number }){

    }
    completeUpgradeSpecialization(args: { charInstId: number, skillIndex: number ,targetLevel:number }){
        //TODO
        let char = this.getCharacterByInstId(args.charInstId)
        char.skills![args.skillIndex].completeUpgradeTime=-1
        char.skills![args.skillIndex].specializeLevel=args.targetLevel
        this._trigger.emit("UpgradeSpecialization",args)
    }
    getSpCharMissionReward(args: { charId: string, missionId: string }): ItemBundle[] {
        let items:ItemBundle[] = excel.CharMetaTable.spCharMissions[args.charId][args.missionId].rewards
        this.charMission[args.charId][args.missionId] = 2
        this._trigger.emit("gainItems", items)
        return items
    }
    evolveCharUseItem(args: { charInstId: number, itemId: string ,instId:number }){
        let char = this.getCharacterByInstId(args.charInstId)
        char.evolvePhase=2
        char.level=1
        char.exp=0
        this.chars[args.instId].skinId = char.charId + "#2";
        this._trigger.emit("useItems",[{id:args.itemId,count:1,instId:args.instId}])
    }
    upgradeCharLevelMaxUseItem(args: { charInstId: number, itemId: string ,instId:number }){
        let char = this.getCharacterByInstId(args.charInstId)
        const rarity=parseInt(excel.CharacterTable[char.charId].rarity.slice(-1))
        const maxLevel=excel.GameDataConst.maxLevel[rarity-1][char.evolvePhase]
        char.level=maxLevel
        char.exp=0
        this._trigger.emit("useItems",[{id:args.itemId,count:1,instId:args.instId}])
    }
    upgradeSpecializedSkillUseItem(args: { charInstId: number,skillIndex:number, itemId: string ,instId:number }){
        let char = this.getCharacterByInstId(args.charInstId)
        char.skills![args.skillIndex].specializeLevel=3
        this._trigger.emit("useItems",[{id:args.itemId,count:1,instId:args.instId}])
    }


    squadFormation(squadId: number, slots: PlayerSquadItem[]): void {
        this.squads[squadId].slots = slots;
        this._trigger.emit("SquadFormation",this.squads[squadId])
    }
    changeSquadName(args:{squadId: number, name: string}): void {
        this.squads[args.squadId].name = args.name;
        this._trigger.emit("ChangeSquadName")
    }


    decomposePotentialItem(charInstIdList: string[]): ItemBundle[] {
        let costs: ItemBundle[] = []
        let items: ItemBundle[] = charInstIdList.reduce((acc, charInstId) => {
            let char = this.getCharacterByInstId(parseInt(charInstId));
            let rarity = parseInt(excel.CharacterTable[char.charId].rarity.slice(-1))
            let potentialItemId = excel.CharacterTable[char.charId].potentialItemId!
            let count = this._playerdata.inventory[potentialItemId]
            costs.push({ id: potentialItemId, count: count })
            let item = excel.GachaTable.potentialMaterialConverter.items[rarity - 1]
            acc.push({ id: item.id, count: item.count * count })
            return acc
        }, [] as ItemBundle[])
        this._trigger.emit("useItems", costs)
        this._trigger.emit("gainItems", items)
        return items
    }
    decomposeClassicPotentialItem(charInstIdList: string[]): ItemBundle[] {
        let costs: ItemBundle[] = []
        let items: ItemBundle[] = charInstIdList.reduce((acc, charInstId) => {
            let char = this.getCharacterByInstId(parseInt(charInstId));
            let rarity = parseInt(excel.CharacterTable[char.charId].rarity.slice(-1))
            let potentialItemId = excel.CharacterTable[char.charId].classicPotentialItemId!
            let count = this._playerdata.inventory[potentialItemId]
            costs.push({ id: potentialItemId, count: count })
            let item = excel.GachaTable.classicPotentialMaterialConverter.items[rarity - 1]
            acc.push({ id: item.id, count: item.count * count })
            return acc
        }, [] as ItemBundle[])
        this._trigger.emit("useItems", costs)
        this._trigger.emit("gainItems", items)
        return items
    }
    
    addonStoryUnlock(args: { charId: string, storyId: string }){
        if(!this.addon[args.charId].story){
            this.addon[args.charId].story = {}
        }
        this.addon[args.charId].story![args.storyId] = {
            fts:now(),
            rts:now()
        }
    }
    addonStageBattleStart(args: { charId: string, stageId: string ,squad:PlayerSquad,stageType:string}){
        //TODO
    }
    addonStageBattleFinish(){

    }
    
    async fix(): Promise<void> {
        await excel.initPromise
        Object.values(this.chars).forEach(char => {
            if (char.charId == "char_002_amiya") {
                //TODO
                return
            }
            let skills = excel.CharacterTable[char.charId].skills
            skills.forEach(skill => {
                if (!char.skills?.some(s => s.skillId == skill.skillId)) {
                    char.skills?.push({
                        skillId: skill.skillId!,
                        unlock: (char.evolvePhase >= parseInt(skill.unlockCond.phase.toString().slice(-1)) && char.level >= skill.unlockCond.level) ? 1 : 0,
                        state: 0,
                        specializeLevel: 0,
                        completeUpgradeTime: -1
                    })
                }else{
                    char.skills!.find(s => s.skillId == skill.skillId)!.unlock = (char.evolvePhase >= parseInt(skill.unlockCond.phase.toString().slice(-1)) && char.level >= skill.unlockCond.level) ? 1 : 0
                }
            })
            char.defaultSkillIndex=skills?(char.defaultSkillIndex!=-1?char.defaultSkillIndex:0):-1
            let equips = excel.UniequipTable.equipDict
            Object.values(equips).filter(equip => equip.charId == char.charId).forEach(equip => {
                char.equip = char.equip || {}
                char.equip[equip.uniEquipId] = char.equip[equip.uniEquipId] || {
                    hide: 1,
                    locked: 1,
                    level: 1
                }
            })
            if (char.evolvePhase == 2 && char.equip) {
                char.currentEquip = char.currentEquip || Object.keys(char.equip)[0]!
            }

        })
    }
    toJSON(): PlayerTroop {
        return {
            curCharInstId: this.curCharInstId,
            curSquadCount: this.curSquadCount,
            chars: this.chars,
            squads: this.squads,
            addon: this.addon,
            charMission: this.charMission,
            charGroup: pick(this.chars, ["favorPoint"]),
        };
    }
}