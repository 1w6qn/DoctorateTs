import { ItemBundle } from "app/excel/character_table";
import excel from "../../excel/excel";
import EventEmitter from "events";
import { PlayerDataModel } from "../model/playerdata";

export class InventoryManager {
    items: { [itemId: string]: number }
    _playerdata:PlayerDataModel
    _trigger: EventEmitter
    constructor(items: { [itemId: string]: number },_playerdata:PlayerDataModel, _trigger: EventEmitter) {
        this.items = items
        this._playerdata = _playerdata
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
                this._playerdata.status.gold+=item.count
                break
            case "DIAMOND":
                this._playerdata.status.iosDiamond+=item.count
                this._playerdata.status.androidDiamond+=item.count
                break
            case "EXP_PLAYER":
                this._playerdata.status.exp+=item.count
                break
            case "DIAMOND_SHD":
                this._playerdata.status.diamondShard+=item.count
                break
            case "TKT_TRY":
                this._playerdata.status.practiceTicket+=item.count
                break
            case "TKT_RECRUIT":
                this._playerdata.status.recruitLicense+=item.count
                break
            case "TKT_INST_FIN":
                this._playerdata.status.instantFinishTicket+=item.count
                break
            case "TKT_GACHA":
                this._playerdata.status.gachaTicket+=item.count
                break
            case "TKT_GACHA_10":
                this._playerdata.status.tenGachaTicket+=item.count
                break
            case "RETURN_PROGRESS":
                //this._playerdata.status.recruitLicense+=item.count
                break
            case "NEW_PROGRESS":
                //this._playerdata.status.recruitLicense+=item.count
                break
            case "AP_GAMEPLAY":
                this._playerdata.status.ap+=item.count
                break
            case "HGG_SHD":
                this._playerdata.status.hggShard+=item.count
                break
            case "LGG_SHD":
                this._playerdata.status.lggShard+=item.count
                break
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