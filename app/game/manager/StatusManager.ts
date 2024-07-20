import EventEmitter from "events"
import { PlayerStatus } from "../model/playerdata"

export class StatusManager {
    
    _trigger: EventEmitter
    constructor(status: PlayerStatus, _trigger: EventEmitter) {
        this._trigger = _trigger
    }
}