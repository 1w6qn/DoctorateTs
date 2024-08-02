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
        this._trigger.on('rlv2:get:items', (items: RoguelikeItemBundle[]) => items.forEach(item => this.getItem(item)))
    }
    getItem(item: RoguelikeItemBundle) {
        const type = excel.RoguelikeTopicTable.details.rogue_4.items[item.id].type
        console.log(`[RLV2] 获得 ${item.id} * ${item.count}`)
        switch (type) {
            case "RECRUIT_TICKET":
                break
            case "UPGRADE_TICKET":
                break
            case "MAX_WEIGHT":
                this._trigger.emit("rlv2:fragment:max_weight:add", item.count)
                break
            default:
                console.log(type)
                break;
        }
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

