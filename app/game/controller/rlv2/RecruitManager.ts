import EventEmitter from "events"
import excel from "../../../excel/excel"
import { TroopManager } from "../../manager/TroopManager"
import { PlayerRoguelikeV2 } from "../../model/rlv2"
import { RoguelikeV2Controller } from "../RoguelikeV2Controller"

export class RoguelikeRecruitManager {
    index: number
    _recruit: { [key: string]: PlayerRoguelikeV2.CurrentData.Recruit }
    _troop: TroopManager
    _player: RoguelikeV2Controller
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
            let buffs = this._player._buff.filterBuffs("recruit_cost");
            let rarity = parseInt(data.rarity.slice(-1));
            let population = [0, 0, 0, 0, 2, 6][rarity - 1]//TODO other theme
            for (let buff of buffs) {
                if (buff.blackboard[0].valueStr?.includes(data.rarity) && buff.blackboard[1].valueStr?.includes(data.profession)) {
                    population -= buff.blackboard[2].value;
                }
                if (char.charId == "char_4151_tinman") {
                    population -= char.evolvePhase>0?2:1

                }
            }
            //TODO skill&uniequip
            let levelPatch = {}
            if (char.evolvePhase == 2) {

                const maxLevel = excel.GameDataConst.maxLevel[rarity - 1][1];
                levelPatch = {
                    evolvePhase: 1,
                    level: maxLevel,
                    exp: 0,
                }
            }
            return [...acc, Object.assign(char, {
                type: "NORMAL",
                upgradePhase: 0,
                upgradeLimited: true,
                population: population>=0?population:0,
                isCure: false,
                charBuff: [],
                isUpgrade: false,
                troopInstId: 0,
            }, levelPatch)]
        }, [] as PlayerRoguelikeV2.CurrentData.RecruitChar[])
        //TODO free & thirdlow
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
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this.index = 0
        this._recruit = player.current.inventory?.recruit || {}
        this._troop = player._troop
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:recruit:gain", this.gain.bind(this))
    }


    toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Recruit } {
        return this._recruit
    }
}