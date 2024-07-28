import { EventEmitter } from "events"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';



export class RoguelikeBattleManager {

    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        
        this._player = player
        this._trigger = _trigger
    }
    
}

