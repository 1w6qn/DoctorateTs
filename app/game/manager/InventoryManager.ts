import { ItemBundle } from "app/excel/character_table";
import excel from "../../excel/excel";
import EventEmitter from "events";
import { PlayerDataModel, PlayerSkins } from "../model/playerdata";

export class InventoryManager {
    items: { [itemId: string]: number }
    skin: PlayerSkins
    _playerdata: PlayerDataModel
    _trigger: EventEmitter
    constructor(_playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.items = _playerdata.inventory
        this.skin = _playerdata.skin
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
                this._gainItem({ id: item.id, count: -item.count })
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
            case "CHAR_SKIN":
                this.skin.characterSkins[item.id]=1
                this.skin.skinTs[item.id]=parseInt((new Date().getTime()/1000).toString())
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

    toJSON() {
        return { 
            inventory: this.items, 
            skin: this.skin
        }
    }

}