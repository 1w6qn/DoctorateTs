import excel from "../../../excel/excel"
import { PlayerRoguelikeV2 } from "../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';

export class RoguelikeRelicManager {
    index: number
    _relic: { [key: string]: PlayerRoguelikeV2.CurrentData.Relic }
    _player: RoguelikeV2Controller
    _trigger: EventEmitter


    use(id: string): void {
        
    }
    gain(id: string, count: number): void {
        let buffs = excel.RoguelikeTopicTable.details.rogue_4.relics[id].buffs
        this._trigger.emit("rlv2:buff:apply", buffs)
        this._relic[id] = {
            index: `r_${this.index}`,
            id: id,
            count: count,
            ts: parseInt((new Date().getTime() / 1000).toString())
        }
    }
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this.index = 0
        this._relic = player.current.inventory?.relic||{}
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:relic:gain", this.gain.bind(this))
    }
    


    toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Relic } {
        return this._relic
    }
}