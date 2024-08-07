import { EventEmitter } from "events"
import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../model/rlv2"
import { RoguelikeRelicManager } from "./relic"
import { RoguelikeRecruitManager } from "./recruit"
import { RoguelikeV2Controller } from '../rlv2';
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
    init() {
        this.trap = null
        this.consumable = {}
        this.exploreTool = {}
    }
    create() {
        this.trap = null
        this.consumable = {}
        this.exploreTool = {}
    }
    getItem(item: RoguelikeItemBundle) {
        const theme = this._player.current.game!.theme
        const type = item.type || excel.RoguelikeTopicTable.details[theme].items[item.id].type || "POOL"
        console.log(`[RLV2] 获得 ${item.id || item.type} * ${item.count}`)
        const funcs: { [key: string]: (item: RoguelikeItemBundle) => void } = {
            "NONE":(item:RoguelikeItemBundle)=>{},
            "HP":(item: RoguelikeItemBundle)=>{
                this._player._status.property.hp.current += item.count
                if (this._player._status.property.hp.current > this._player._status.property.hp.max) {
                    this._player._status.property.hp.current = this._player._status.property.hp.max
                }
            },
            "HPMAX":(item: RoguelikeItemBundle)=>{
                this._player._status.property.hp.current += item.count
                this._player._status.property.hp.max += item.count
            },
            "GOLD":(item: RoguelikeItemBundle)=>this._player._status.property.gold += item.count,
            "POPULATION":(item: RoguelikeItemBundle)=>{
                if(item.count>=0){
                    this._player._status.property.population.max += item.count
                }else{
                    this._player._status.property.population.cost -= item.count
                }
            },
            "EXP":(item: RoguelikeItemBundle)=>{
                this._player._status.property.exp += item.count
                let map=excel.RoguelikeTopicTable.details[theme].detailConst.playerLevelTable
                while(this._player._status.property.exp >= map[this._player._status.property.level+1].exp){
                    this._player._status.property.level += 1
                    this._player._status.property.exp -= map[this._player._status.property.level+1].exp
                    this._trigger.emit("rlv2:levelup",this._player._status.property.level)
                    this._player._status.property.population.max += map[this._player._status.property.level+1].populationUp
                    this._player._status.property.capacity += map[this._player._status.property.level+1].squadCapacityUp
                    this._player._status.property.hp.max += map[this._player._status.property.level+1].maxHpUp
                    this._player._status.property.hp.current += map[this._player._status.property.level+1].populationUp
                    
                }
            },
            "SQUAD_CAPACITY":(item: RoguelikeItemBundle)=>this._player._status.property.capacity += item.count,
            "RECRUIT_TICKET": (item: RoguelikeItemBundle) => {
                this._trigger.emit("rlv2:recruit:gain", item.id, "battle", 0)
                let ticket = Object.values(this.recruit).slice(-1)[0].index
                this._trigger.emit("rlv2:recruit:active", ticket)
                this._trigger.emit("rlv2:event:create", "RECRUIT", {
                    ticket: ticket
                })
            },
            "UPGRADE_TICKET": (item: RoguelikeItemBundle) => {
                this._trigger.emit("rlv2:recruit:gain", item.id, "battle", 0)
                let ticket = Object.values(this.recruit).slice(-1)[0].index
                this._trigger.emit("rlv2:recruit:active", ticket)
                this._trigger.emit("rlv2:event:create", "RECRUIT", {
                    ticket: ticket
                })
            },
            "RELIC":(item:RoguelikeItemBundle)=>{},
            "BP_POINT":(item:RoguelikeItemBundle)=>{},
            "GROW_POINT":(item:RoguelikeItemBundle)=>{},
            "BAND":(item:RoguelikeItemBundle)=>{},
            "ACTIVE_TOOL":(item:RoguelikeItemBundle)=>{},
            "CAPSULE":(item:RoguelikeItemBundle)=>{},
            "POOL": (item: RoguelikeItemBundle) => {
                let ro = this._player._pool.get(item.id, item.id.includes("fragment"))
                this._trigger.emit("rlv2:get:items", ro.id)
                //this._trigger.emit("rlv2:pool:gain", item.id)
            },
            "RL_BP":(item:RoguelikeItemBundle)=>{},
            "RL_GP":(item:RoguelikeItemBundle)=>{},
            "KEY_POINT":(item:RoguelikeItemBundle)=>{},
            "SAN_POINT":(item:RoguelikeItemBundle)=>{},
            "DICE_POINT":(item:RoguelikeItemBundle)=>{},
            "DICE_TYPE":(item:RoguelikeItemBundle)=>{},
            "SHIELD":(item: RoguelikeItemBundle)=>this._player._status.property.shield += item.count,

            "LOCKED_TREASURE":(item:RoguelikeItemBundle)=>{},
            "CUSTOM_TICKET":(item:RoguelikeItemBundle)=>{},
            "TOTEM":(item:RoguelikeItemBundle)=>{},
            "TOTEM_EFFECT":(item:RoguelikeItemBundle)=>{},
            "FEATURE":(item:RoguelikeItemBundle)=>{},
            "VISION":(item:RoguelikeItemBundle)=>{},
            "CHAOS":(item:RoguelikeItemBundle)=>{},
            "CHAOS_PURIFY":(item:RoguelikeItemBundle)=>{},
            "CHAOS_LEVEL":(item:RoguelikeItemBundle)=>{},
            "EXPLORE_TOOL":(item:RoguelikeItemBundle)=>{},
            "FRAGMENT": (item: RoguelikeItemBundle) => {
                this._trigger.emit("rlv2:fragment:gain", item.id)
            },
            "MAX_WEIGHT": (item: RoguelikeItemBundle) => {
                this._trigger.emit("rlv2:fragment:max_weight:add", item.count)
            },
            "DISASTER":(item:RoguelikeItemBundle)=>{},
            "DISASTER_TYPE":(item:RoguelikeItemBundle)=>{
                
            },
            "ABSTRACT_DISASTER":(item:RoguelikeItemBundle)=>{
                this._trigger.emit("rlv2:disaster:abstract")
            },
        }
        funcs[type](item)
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

