import { PlayerRoguelikeV2 } from "../../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from '../../RoguelikeV2Controller';
import excel from "@excel/excel";
import { randomChoice } from "@utils/random";

export class RoguelikeNodeUpgradeManager {
    _curDisaster: string|null
    _disperseStep:number
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._player = player
        this._curDisaster=null
        this._disperseStep=0
        this._trigger = _trigger
        this._trigger.on("rlv2:init", this.init.bind(this))
        this._trigger.on("rlv2:continue", this.continue.bind(this))
        this._trigger.on("rlv2:disaster:generate", this.generate.bind(this))
        this._trigger.on("rlv2:move", ()=>{
            if(this._curDisaster){
                this._disperseStep-=1
            }else if(Math.random()<0.7){
                this._trigger.emit("rlv2:disaster:generate")
            }
        })
    }
    init() {
        this._curDisaster=null
        this._disperseStep=0
    }
    continue() {
        this._curDisaster=this._player.current.module!.disaster!.curDisaster
        this._disperseStep=this._player.current.module!.disaster!.disperseStep
    }
    generate(steps:number=5){
        const theme = this._player.current.game!.theme
        const modeGrade=this._player.current.game!.modeGrade
        const level=modeGrade>=12?3:modeGrade>=6?2:1
        let disasters=Object.values(excel.RoguelikeTopicTable.modules[theme].disaster!.disasterData).filter(d=>d.level==level)
        this._curDisaster=randomChoice(Object.keys(disasters))
        this._disperseStep=steps
    }
    toJSON(): PlayerRoguelikeV2.CurrentData.Module.Disaster {
        return {
            curDisaster: this._curDisaster,
            disperseStep: this._disperseStep
        }
    }
}