import excel from "@excel/excel"
import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';
import { now } from "@utils/time";

export class RoguelikeRelicManager {
    
    relics: { [key: string]: PlayerRoguelikeV2.CurrentData.Relic }
    _index: number
    _player: RoguelikeV2Controller
    _trigger: EventEmitter


    get index(): string {
        return `r_${this._index}`
    }

    use(id: string): void {
        
    }
    async gain(relic:RoguelikeItemBundle): Promise<void> {
        await excel.initPromise
        let buffs = excel.RoguelikeTopicTable.details.rogue_4.relics[relic.id].buffs
        console.log(relic.id, buffs)
        this._trigger.emit("rlv2:buff:apply", ...buffs)
        this.relics[relic.id] = {
            index: this.index,
            id: relic.id,
            count: relic.count,
            ts: now()
        }
    }
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._index = 0
        this.relics = player.current.inventory?.relic||{}
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:relic:gain", this.gain.bind(this))
    }
    


    toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Relic } {
        return this.relics
    }
}