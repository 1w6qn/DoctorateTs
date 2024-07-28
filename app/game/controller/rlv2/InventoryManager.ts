import { EventEmitter } from "events"
import { PlayerRoguelikeV2 } from "../../model/rlv2"
import { RoguelikeRelicManager } from "./RelicManager"
import { RoguelikeRecruitManager } from "./RecruitManager"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';



export class RoguelikeInventoryManager {
    relic: RoguelikeRelicManager
    recruit: RoguelikeRecruitManager
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this.relic=new RoguelikeRelicManager(player, _trigger)
        this.recruit=new RoguelikeRecruitManager(player, _trigger)
        this._player = player
        this._trigger = _trigger
    }


    toJSON(): PlayerRoguelikeV2.CurrentData.Inventory {
        return {
            relic: this.relic.toJSON(),
            recruit: this.recruit.toJSON(),
            trap: null,
            consumable: {},
            exploreTool: {}
        }
    }
}

