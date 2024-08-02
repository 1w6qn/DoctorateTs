import { EventEmitter } from "events"
import { PlayerRoguelikeV2, PlayerRoguelikeV2Dungeon, PlayerRoguelikeV2Zone, RoguelikeItemBundle } from "../../model/rlv2"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';
import excel from "@excel/excel";



export class RoguelikeMapManager implements PlayerRoguelikeV2Dungeon {
    zones:{ [key: string]: PlayerRoguelikeV2Zone }
    _player: RoguelikeV2Controller
    _trigger: EventEmitter

    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this.zones = {}
        this._player = player
        this._trigger = _trigger
        this._trigger.on('rlv2:init', this.init.bind(this))
        this._trigger.on("rlv2:create", this.create.bind(this))
        this._trigger.on("rlv2:zone:new", this.generate.bind(this))
        
    }
    init(){
        this.zones = {}
    }
    create(){
        this.zones = {}
    }
    generate(id:number){
        //TODO: generate zone
    }
    toJSON(): PlayerRoguelikeV2Dungeon {
        return {
            zones:this.zones
        }
    }
}

