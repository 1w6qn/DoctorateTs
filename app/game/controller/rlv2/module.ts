import { PlayerRoguelikeV2 } from "../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../rlv2';
import excel from "@excel/excel";
import { RoguelikeFragmentManager } from "./modules/fragment";
import { RoguelikeDisasterManager } from "./modules/disaster";
import { RoguelikeNodeUpgradeManager } from "./modules/node_upgrade";
import { toCamelCase } from "@utils/string";

export class RoguelikeModuleManager {
    _modules:{[key:string]:any}
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        
        this._player = player
        this._modules = []
        this._trigger = _trigger
        this._trigger.on("rlv2:init", this.init.bind(this))
        this._trigger.on("rlv2:create", this.create.bind(this))
        this._trigger.on("rlv2:continue", this.continue.bind(this))
    }
    init(){
        this._modules = []
        
    }
    create() {
        const theme = this._player.current.game!.theme
        let moduleHandler:{[key:string]:()=>any}={
            FRAGMENT:()=>new RoguelikeFragmentManager(this._player, this._trigger),
            DISASTER:()=>new RoguelikeDisasterManager(this._player, this._trigger),
            NODE_UPGRADE:()=>new RoguelikeNodeUpgradeManager(this._player, this._trigger)
        }
        for(let moduleName of excel.RoguelikeTopicTable.modules[theme].moduleTypes){
            if(moduleName in moduleHandler){
                this._modules[moduleName]=moduleHandler[moduleName]()
            }
        }
        this._trigger.emit("rlv2:module:init")
    }
    continue() {
        
    }
    toJSON(): PlayerRoguelikeV2.CurrentData.Module {
        return Object.entries(this._modules).reduce((acc, [k,v]) => {
            acc[toCamelCase(k)] = v.toJSON()
            return acc
        },{} as PlayerRoguelikeV2.CurrentData.Module)
    }
}