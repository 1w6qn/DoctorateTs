import excel from "@excel/excel"
import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../rlv2';
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
        const theme = this._player.current.game!.theme
        let buffs = excel.RoguelikeTopicTable.details[theme].relics[relic.id].buffs
        console.log(relic.id, buffs)
        this._trigger.emit("rlv2:buff:apply", ...buffs)
        this.relics[relic.id] = {
            index: this.index,
            id: relic.id,
            count: relic.count,
            ts: now()
        }
        this._index++
    }
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._index = 0
        this.relics = player.current.inventory?.relic||{}
        this._player = player
        this._trigger = _trigger
        this._trigger.on("rlv2:relic:gain", this.gain.bind(this))
        this._trigger.on("rlv2:init",()=>{
            this.relics = {}
        })
        this._trigger.on("rlv2:create",()=>{
            this.relics = {}
        })
    }
    


    toJSON(): { [key: string]: PlayerRoguelikeV2.CurrentData.Relic } {
        return this.relics
    }
}