import { EventEmitter } from "events"
import { PlayerRoguelikeV2 } from "../../model/rlv2"
import { Blackboard } from "../../../excel/character_table"
import excel from "../../../excel/excel"
import { TroopManager } from "../../manager/TroopManager"


export class RoguelikeInventoryManager {
    _inventory: PlayerRoguelikeV2.CurrentData.Inventory
    _player: PlayerRoguelikeV2.CurrentData
    _trigger: EventEmitter
    [key: string]: any
    gainRelic(id: string, count: number): void {
        let buffs = excel.RoguelikeTopicTable.details.rogue_4.relics[id].buffs
        this.applyBuffs(...buffs)
        this._inventory.relic[id] = {
            index: `r_${this.index}`,
            id: id,
            count: count,
            ts: parseInt((new Date().getTime() / 1000).toString())
        }
    }
    constructor(player: PlayerRoguelikeV2.CurrentData, troop: TroopManager, _trigger: EventEmitter) {
        this.index = 0
        this._inventory = {
            relic: new RoguelikeRelicManager(player, _trigger),
            recruit: {},
            trap: null,
            consumable: {},
            exploreTool: {}
        }
        this._player = player
        this._trigger = _trigger
    }


    toJSON(): PlayerRoguelikeV2.CurrentData.Inventory {
        return this._inventory
    }
}
export class RoguelikeRelicManager {
    index: number
    _relic: { [key: string]: PlayerRoguelikeV2.CurrentData.Relic }
    _player: PlayerRoguelikeV2.CurrentData
    _trigger: EventEmitter
    [key: string]: any

    applyBuffs(...args: { key: string, blackboard: Blackboard }[]) {
        args.forEach(arg => {
            this[arg.key](arg.blackboard)
        })
    }
    gain(id: string, count: number): void {
        let buffs = excel.RoguelikeTopicTable.details.rogue_4.relics[id].buffs
        this.applyBuffs(...buffs)
        this._relic[id] = {
            index: `r_${this.index}`,
            id: id,
            count: count,
            ts: parseInt((new Date().getTime() / 1000).toString())
        }
    }
    constructor(player: PlayerRoguelikeV2.CurrentData, _trigger: EventEmitter) {
        this.index = 0
        this._relic = {}
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:relic:gain", this.gain.bind(this))
    }
    immediate_reward(blackboard: Blackboard) {
        switch (blackboard[0].valueStr) {
            case "rogue_4_gold":
                this._player.player!.property.gold += blackboard[1].value
                break;
            case "rogue_4_population":
                this._player.player!.property.population.max += blackboard[1].value
                break;
            default:
                break;
        }
    }


    toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Relic } {
        return this._relic
    }
}
export class RoguelikeRecruitManager {
    index: number
    _recruit: { [key: string]: PlayerRoguelikeV2.CurrentData.Recruit }
    _troop: TroopManager
    _player: PlayerRoguelikeV2.CurrentData
    _trigger: EventEmitter
    active(id: string) {
        this._recruit[id].state = 1
        let ticketInfo = excel.RoguelikeTopicTable.details.rogue_4.recruitTickets[id]
        let chars: PlayerRoguelikeV2.CurrentData.RecruitChar[] = this._troop.chars.reduce((acc, char) => {
            let data = excel.CharacterTable[char.charId]
            if (ticketInfo.professionList.some(p => data.profession.includes(p)) == false) {
                return acc
            }
            if (ticketInfo.rarityList.some(r => data.rarity == r) == false) {
                return acc;
            }
            let population=0

            let levelPatch={}
            if(char.evolvePhase==2){
                const rarity = parseInt(excel.CharacterTable[char.charId].rarity.slice(-1));
                const maxLevel = excel.GameDataConst.maxLevel[rarity - 1][1];
                levelPatch={
                    evolvePhase:1,
                    level:maxLevel,
                    exp:0,
                }
            }
            return [...acc,Object.assign(char, {
                type: "NORMAL",
                upgradePhase: 0,
                upgradeLimited: true,
                population: 0,
                isCure:false,
                charBuff:[],
                isUpgrade: false,
                troopInstId: 0,
            },levelPatch)]
        }, [] as PlayerRoguelikeV2.CurrentData.RecruitChar[])
        this._recruit[id].list = chars
    }
    done(id: string, optionId: string) {
        this._recruit[id].state = 2
        this._recruit[id].result = this._recruit[id].list.find(item => item.instId == parseInt(optionId)) as PlayerRoguelikeV2.CurrentData.RecruitChar

    }
    gain(id: string, from: string, mustExtra: number): void {
        this._recruit[id] = {
            index: `t_${this.index}`,
            id: id,
            state: 0,
            list: [],
            result: null,
            from: from,
            mustExtra: mustExtra,
            needAssist: from == "initial",
            ts: parseInt((new Date().getTime() / 1000).toString())
        }
    }
    constructor(player: PlayerRoguelikeV2.CurrentData, _troop: TroopManager, _trigger: EventEmitter) {
        this.index = 0
        this._recruit = {}
        this._troop = _troop
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:recruit:gain", this.gain.bind(this))
    }


    toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Recruit } {
        return this._recruit
    }
}