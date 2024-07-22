import { ItemBundle } from "app/excel/character_table";
import excel from "../../excel/excel";
import EventEmitter from "events";
import { PlayerStatus } from "../model/playerdata";

export class InventoryManager {
    items: { [itemId: string]: number }
    _trigger: EventEmitter
    constructor(items: { [itemId: string]: number },status:PlayerStatus, _trigger: EventEmitter) {
        this.items = items
        this.items["4001"]=status.gold
        this.items["4003"]=status.diamondShard
        this.items["5001"]=status.exp
        this.items["SOCIAL_PT"]=status.socialPoint
        this.items["7003"]=status.gachaTicket
        this.items["7004"]=status.tenGachaTicket
        this.items["7002"]=status.instantFinishTicket
        this.items["7001"]=status.recruitLicense
        this.items["AP_GAMEPLAY"]=status.ap
        this.items["4002"]=status.iosDiamond
        this.items["4002"]=status.androidDiamond
        this.items["6001"]=status.practiceTicket
        this.items["4004"]=status.hggShard
        this.items["4005"]=status.lggShard
        this.items["classic_normal_ticket"]=status.classicShard
        this.items["classic_gacha"]=status.classicGachaTicket
        this.items["classic_gacha_10"]=status.classicTenGachaTicket
        this._trigger = _trigger
        this._trigger.on("useItems", this.useItems.bind(this))
        this._trigger.on("gainItems", this.gainItems.bind(this))
    }
    _useItem(item: ItemBundle): void {
        if (!item.type) {
            item.type = excel.ItemTable.items[item.id].itemType as string
        }
        switch (item.type) {
            case "CARD_EXP":
                this.items[item.id] -= item.count
                break;

            default:
                this._gainItem({id: item.id,count: -item.count})
                break;
        }
    }
    useItems(items: ItemBundle[]): void {
        for (const item of items) {
            this._useItem(item)
        }
    }
    _gainItem(item: ItemBundle): void {
        if (!item.type) {
            item.type = excel.ItemTable.items[item.id].itemType as string
        }
        switch (item.type) {
            case "CHAR":
                this._trigger.emit("gainChar", item.id)
                break;
            case "GOLD":
                this._trigger.emit("status:refresh",this)
            case "DIAMOND":
                this._trigger.emit("status:refresh",this)
            case "EXP_PLAYER":
                this._trigger.emit("status:refresh",this)
            case "DIAMOND_SHD":
                this._trigger.emit("status:refresh",this)
            case "TKT_TRY":
                this._trigger.emit("status:refresh",this)
            case "TKT_RECRUIT":
                this._trigger.emit("status:refresh",this)
            case "TKT_INST_FIN":
                this._trigger.emit("status:refresh",this)
            case "TKT_GACHA":
                this._trigger.emit("status:refresh",this)
            case "TKT_GACHA_10":
                this._trigger.emit("status:refresh",this)
            case "RETURN_PROGRESS":
                this._trigger.emit("status:refresh",this)
            case "NEW_PROGRESS":
                this._trigger.emit("status:refresh",this)
            case "AP_GAMEPLAY":
                this._trigger.emit("status:refresh",this)
            case "HGG_SHD":
                this._trigger.emit("status:refresh",this)
            case "LGG_SHD":
                this._trigger.emit("status:refresh",this)
            default:
                this.items[item.id] = (this.items[item.id] || 0) + item.count
                break;
        }
    }
    gainItems(items: ItemBundle[]): void {
        for (const item of items) {
            this._gainItem(item)
        }
    }
    toJSON(){
        return this.items
    }

}