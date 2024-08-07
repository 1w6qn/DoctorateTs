import { PlayerRoguelikeV2 } from "../../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../../rlv2';
import excel from "@excel/excel";
import { randomChoice } from "@utils/random";

export class RoguelikeTotemManager {
    _totemPiece:PlayerRoguelikeV2.CurrentData.Module.InventoryTotem[]
    _predictTotemId:string|undefined
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._player = player
        this._totemPiece=[]
        this._trigger = _trigger
        this._trigger.on("rlv2:init", this.init.bind(this))
        this._trigger.on("rlv2:continue", this.continue.bind(this))
        
    }
    use(totoemIndex:[string,string],nodeIndex:string[]){
        //TODO
        this._trigger.emit("rlv2:node:attach",nodeIndex,[])
    }
    init() {
        const theme = this._player.current.game!.theme
        this._totemPiece=[]
    }
    continue() {
        this._totemPiece=this._player.current.module!.totem!.totemPiece
        this._predictTotemId=this._player.current.module!.totem!.predictTotemId
    }
    toJSON():PlayerRoguelikeV2.CurrentData.Module.Totem  {
        return {
            totemPiece:this._totemPiece,
            predictTotemId:this._predictTotemId
        }
    }
}