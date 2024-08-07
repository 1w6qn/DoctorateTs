import EventEmitter from "events"
import excel from "@excel/excel"
import { TroopManager } from "../../manager/troop"
import { PlayerRoguelikeV2 } from "../../model/rlv2"
import { RoguelikeV2Controller } from "../RoguelikeV2Controller"
import { now } from "@utils/time"

export class RoguelikeRecruitManager {
    _index: number
    tickets: { [key: string]: PlayerRoguelikeV2.CurrentData.Recruit }
    _troop: TroopManager
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    get index(): string {
        return `t_${this._index}`
    }
    active(id: string) {
        const theme = this._player.current.game!.theme
        this.tickets[id].state = 1
        let ticketInfo = excel.RoguelikeTopicTable.details[theme].recruitTickets[this.tickets[id].id]
        let chars: PlayerRoguelikeV2.CurrentData.RecruitChar[] = Object.values(this._troop.chars).reduce((acc, char) => {
            let data = excel.CharacterTable[char.charId]

            if (ticketInfo.professionList.some(p => data.profession.includes(p)) == false) {
                return acc
            }
            if (ticketInfo.rarityList.some(r => data.rarity == r) == false) {
                return acc;
            }
            let isUpgraded=false
            let rarity = parseInt(data.rarity.slice(-1));
            let population = [0, 0, 0, 0, 2, 6][rarity - 1]//TODO other theme
            for (let buff of this._player._buff.filterBuffs("recruit_cost")) {
                if (buff.blackboard[0].valueStr?.includes(data.rarity) && buff.blackboard[1].valueStr?.includes(data.profession)) {
                    population += buff.blackboard[2].value!;
                }
            }
            for (let buff of this._player._buff.filterBuffs("limited_direct_upgrade")) {
                
                if (buff.blackboard[0].valueStr?.includes(data.rarity) && buff.blackboard[1].valueStr?.includes(data.profession)) {
                    isUpgraded=Math.random()<=buff.blackboard[3].value!;
                }
            }
            
            if (char.charId == "char_4151_tinman") {
                population -= char.evolvePhase > 0 ? 2 : 1

            }
            let levelPatch = {}
            if (char.evolvePhase == 2 && isUpgraded == false ) {

                const maxLevel = excel.GameDataConst.maxLevel[rarity - 1][1];
                levelPatch = {
                    evolvePhase: 1,
                    level: maxLevel,
                    exp: 0,
                    skills: char.skills?.map(s => {
                        return Object.assign({}, s, { specializeLevel: 0 })
                    })
                }
            }
            return [...acc, Object.assign({}, char, {
                instId: acc.length,
                type: "NORMAL",
                upgradePhase: isUpgraded?1:0,
                upgradeLimited: !isUpgraded,
                population: population >= 0 ? population : 0,
                isCure: false,
                charBuff: [],
                isUpgrade: false,
                troopInstId: Object.keys(this._player.troop.chars).length,
            }, levelPatch)]
        }, [] as PlayerRoguelikeV2.CurrentData.RecruitChar[])
        //TODO free & thirdlow
        this.tickets[id].list = chars
    }
    done(id: string, optionId: string) {
        this.tickets[id].state = 2
        this.tickets[id].result = this.tickets[id].list.find(item => item.instId == parseInt(optionId)) as PlayerRoguelikeV2.CurrentData.RecruitChar

        this._trigger.emit("rlv2:char:get", this.tickets[id].result)
        this._trigger.emit("rlv2:get:items", [{ id: "", count: -this.tickets[id].result.population, type: "POPULATION" }])
        this.tickets[id].list = []
    }
    gain(id: string, from: string, mustExtra: number): void {
        this.tickets[this.index] = {
            index: this.index,
            id: id,
            state: 0,
            list: [],
            result: null,
            from: from,
            mustExtra: mustExtra,
            needAssist: from == "initial",
            ts: now()
        }
        this._index++
    }
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._index = 0
        this.tickets = player.current.inventory?.recruit || {}
        this._troop = player._troop
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:init", () => {
            this.tickets = {}
        })
        this._trigger.on("rlv2:create", () => {
            this.tickets = {}
        })
        this._trigger.on("rlv2:recruit:gain", this.gain.bind(this))
        this._trigger.on("rlv2:recruit:active", this.active.bind(this))
        this._trigger.on("rlv2:recruit:done", this.done.bind(this))
        this._trigger.on("rlv2:create", () => {
            this.tickets = {}
        })
    }


    toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Recruit } {
        return this.tickets
    }
}