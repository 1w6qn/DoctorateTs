import { EventEmitter } from "events"
import { PlayerRoguelikeV2 } from "../../model/rlv2"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';



export class RoguelikeNodeUpgradeManager {
    _info: {[key:string]:PlayerRoguelikeV2.CurrentData.Module.NodeUpgradeInfo}
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._player = player
        this._info = Object.fromEntries(Object.entries(this._player.outer[this._player.current.game!.theme].collect.nodeUpgrade).map(([k,v])=>{
            return [k,{
                tempUpgrade:"",
                currUpgradeIndex:v.unlockList.length-1,
                upgradeList:v.unlockList
            }]
        }))
        this._trigger = _trigger
    }


    toJSON(): PlayerRoguelikeV2.CurrentData.Module.NodeUpgrade {
        return {
            nodeTypeInfoMap:this._info
        }
    }
}