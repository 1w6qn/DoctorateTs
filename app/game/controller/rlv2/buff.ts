import { RoguelikeGameItemData } from "@excel/roguelike_topic_table"
import { Blackboard, ItemBundle } from "@excel/character_table"
import excel from "@excel/excel"
import { RoguelikeBuff, RoguelikeItemBundle } from "../../model/rlv2"
import EventEmitter from "events"
import { RoguelikeV2Controller } from "../RoguelikeV2Controller"
import { RoguelikePlayerStatusManager } from "./status"

export class RoguelikeBuffManager {
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    _buffs!: RoguelikeBuff[]
    _status:RoguelikePlayerStatusManager
    [key: string]: any
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._player = player
        this._status = this._player._status
        this._trigger = _trigger
        this._trigger.on("rlv2:buff:apply", this.applyBuffs.bind(this))
        this._trigger.on("rlv2:init", this.init.bind(this))
    }
    async init(){
        await excel.initPromise
        this._buffs = Object.values(this._player.inventory!.relic).reduce((acc, relic) => {
            let buffs = excel.RoguelikeTopicTable.details.rogue_4.relics[relic.id].buffs.filter(buff => buff.key != "immediate_reward")
            return [...acc, ...buffs]
        }, [] as RoguelikeBuff[])
    }
    applyBuffs(...args: RoguelikeBuff[]) {
        args.forEach(arg => {
            if (arg.key == "immediate_reward") {
                this.immediate_reward(arg.blackboard)
            } else {
                this._buffs.push(arg)
            }
        })
    }
    filterBuffs(key: string): RoguelikeBuff[] {
        return this._buffs.filter(buff => buff.key == key)
    }
    generateBuff(key:string,id:string,value:number):RoguelikeBuff{
        switch(key){
            case "immediate_reward":
                return {key:key,blackboard:[{key: "id",value: 0.0,valueStr: id},{key: "count",value: value,valueStr: null}]}
                break
        }
        return {key:key,blackboard:[]}
    }
    immediate_reward(blackboard: Blackboard) {
        let item: RoguelikeItemBundle={id:blackboard[0].valueStr!,count:blackboard[1].value!,sub:0}
        this._trigger.emit("rlv2:get:items", [item])
    }
}