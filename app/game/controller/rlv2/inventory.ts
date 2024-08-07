import { EventEmitter } from "events"
import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../model/rlv2"
import { RoguelikeRelicManager } from "./relic"
import { RoguelikeRecruitManager } from "./recruit"
import { RoguelikeV2Controller } from '../RoguelikeV2Controller';
import excel from "@excel/excel";



export class RoguelikeInventoryManager implements PlayerRoguelikeV2.CurrentData.Inventory {
    _relic: RoguelikeRelicManager
    _recruit: RoguelikeRecruitManager
    trap: null
    consumable: {}
    exploreTool: {}
    _player: RoguelikeV2Controller
    _trigger: EventEmitter
    get relic() {
        return this._relic.relics
    }
    get recruit() {
        return this._recruit.tickets
    }
    constructor(player: RoguelikeV2Controller, _trigger: EventEmitter) {
        this._relic = new RoguelikeRelicManager(player, _trigger)
        this._recruit = new RoguelikeRecruitManager(player, _trigger)
        this.trap = null
        this.consumable = {}
        this.exploreTool = {}
        this._player = player
        this._trigger = _trigger
        this._trigger.on('rlv2:init', this.init.bind(this))
        this._trigger.on("rlv2:create", this.create.bind(this))
        this._trigger.on('rlv2:get:items', (items: RoguelikeItemBundle[]) => items.forEach(item => this.getItem(item)))
    }
    init(){
        this.trap = null
        this.consumable = {}
        this.exploreTool = {}
    }
    create(){
        this.trap = null
        this.consumable = {}
        this.exploreTool = {}
    }
    getItem(item: RoguelikeItemBundle) {
        const theme = this._player.current.game!.theme
        const type = item.type||excel.RoguelikeTopicTable.details[theme].items[item.id].type||"POOL"
        console.log(`[RLV2] 获得 ${item.id||item.type} * ${item.count}`)
        switch (type) {
            case "RECRUIT_TICKET":
                this._trigger.emit("rlv2:recruit:gain", item.id,"battle",0)
                let ticket=Object.values(this.recruit).slice(-1)[0].index
                this._trigger.emit("rlv2:recruit:active",ticket)
                this._trigger.emit("rlv2:event:create","RECRUIT",{
                    ticket:ticket
                })
                
                break
            case "UPGRADE_TICKET":
                this._trigger.emit("rlv2:recruit:gain", item.id,"battle",0)
                ticket=Object.values(this.recruit).slice(-1)[0].index
                this._trigger.emit("rlv2:recruit:active",ticket)
                this._trigger.emit("rlv2:event:create","RECRUIT",{
                    ticket:ticket
                })
                break
            case "MAX_WEIGHT":
                this._trigger.emit("rlv2:fragment:max_weight:add", item.count)
                break
            case "FRAGMENT":
                this._trigger.emit("rlv2:fragment:gain", item.id)
                break
            case "POOL":
                let ro=this._player._pool.get(item.id,item.id.includes("fragment"))
                this._trigger.emit("rlv2:get:items", ro.id)
                //this._trigger.emit("rlv2:pool:gain", item.id)
                break
            default:
                console.log(type)
                break;
        }
    }

    toJSON(): PlayerRoguelikeV2.CurrentData.Inventory {
        return {
            relic: this.relic,
            recruit: this.recruit,
            trap: this.trap,
            consumable: this.consumable,
            exploreTool: this.exploreTool
        }
    }
}

