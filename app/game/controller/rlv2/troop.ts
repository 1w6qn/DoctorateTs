import excel from "@excel/excel"
import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';
import { now } from "@utils/time";

export class RoguelikeTroopManager {
    
    _player: RoguelikeV2Controller
    _trigger: EventEmitter


    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        
        this._player = player
        this._trigger = _trigger
        //this._trigger.on("rlv2:relic:gain", this.gain.bind(this))
    }
    


    toJSON(): {} {
        return {}
    }
}