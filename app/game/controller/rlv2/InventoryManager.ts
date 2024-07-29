import { EventEmitter } from "events"
import { PlayerRoguelikeV2 } from "../../model/rlv2"
import { RoguelikeRelicManager } from "./RelicManager"
import { RoguelikeRecruitManager } from "./RecruitManager"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';



export class RoguelikeInventoryManager implements PlayerRoguelikeV2.CurrentData.Inventory {
    _relic: RoguelikeRelicManager
    _recruit: RoguelikeRecruitManager
    trap:null
    consumable:{}
    exploreTool:{}
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    get relic(){
        return this._relic.relics
    }
    get recruit(){
        return this._recruit.tickets
    }
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._relic=new RoguelikeRelicManager(player, _trigger)
        this._recruit=new RoguelikeRecruitManager(player, _trigger)
        this.trap=null
        this.consumable={}
        this.exploreTool={}
        this._player = player
        this._trigger = _trigger
    }


    toJSON(): PlayerRoguelikeV2.CurrentData.Inventory {
        return {
            relic: this._relic.relics,
            recruit: this._recruit.tickets,
            trap: this.trap,
            consumable: this.consumable,
            exploreTool: this.exploreTool
        }
    }
}

