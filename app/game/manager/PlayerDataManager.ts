import { EventEmitter } from "events";
import { PlayerDataModel, PlayerStatus } from "../model/playerdata";
import { InventoryManager } from "./InventoryManager";
import { TroopManager } from "./TroopManager";

export class PlayerDataManager {
    inventory: InventoryManager
    troop: TroopManager
    status:PlayerStatus
    _trigger: EventEmitter
    _playerdata: PlayerDataModel;
    constructor(playerdata:PlayerDataModel) {
        this._trigger = new EventEmitter();
        this._playerdata = playerdata;
        this.inventory = new InventoryManager(playerdata.inventory, this._trigger);
        this.troop=new TroopManager(playerdata.troop, this._trigger)
        this.status=playerdata.status
    }
    refreshStatus() {
        //
        this.status.gold=this.inventory.gold
        this.status.diamondShard=this.inventory.diamondShard
        //this.
        this.status.lastOnlineTs=new Date().getTime()
    }
    toJson() {
        return {
            status:this.status,
            inventory: this.inventory
        }
    }
}