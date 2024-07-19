import { ItemBundle } from "app/excel/character_table";
import EventEmitter from "events";

export class InventoryManager {
    items: {[itemId: string]: number}
    _trigger:EventEmitter
    constructor(items: {[itemId: string]: number},_trigger:EventEmitter) {
        this.items=items
        this._trigger=_trigger
        this._trigger.on("costItems",this.costItems.bind(this))
    }

    public costItems(items:ItemBundle[]): void {
        
    }

}