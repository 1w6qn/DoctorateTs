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

        this._trigger.on("status:refresh",this._refreshStatus.bind(this))
        this._trigger.on("status:refresh:time",this.refreshTime.bind(this))
    }
    refreshTime(){
        let ts=parseInt((new Date().getTime()/1000).toString())
        this.status.lastRefreshTs=ts
        this.status.lastApAddTime=ts
        this.status.lastOnlineTs=ts
    }
    _refreshStatus() {
        this.status.gold=this.inventory.items["4001"]
        this.status.diamondShard=this.inventory.items["4003"]
        this.status.exp=this.inventory.items["5001"]
        this.status.socialPoint=this.inventory.items["SOCIAL_PT"]
        this.status.gachaTicket=this.inventory.items["7003"]
        this.status.tenGachaTicket=this.inventory.items["7004"]
        this.status.instantFinishTicket=this.inventory.items["7002"]
        this.status.recruitLicense=this.inventory.items["7001"]
        this.status.ap=this.inventory.items["AP_GAMEPLAY"]
        this.status.iosDiamond=this.inventory.items["4002"]
        this.status.androidDiamond=this.inventory.items["4002"]
        this.status.practiceTicket=this.inventory.items["6001"]
        this.status.hggShard=this.inventory.items["4004"]
        this.status.lggShard=this.inventory.items["4005"]
        this.status.classicShard=this.inventory.items["classic_normal_ticket"]
        this.status.classicGachaTicket=this.inventory.items["classic_gacha"]
        this.status.classicTenGachaTicket=this.inventory.items["classic_gacha_10"]
    }
    toJSON() {
        return {
            status:this.status,
            inventory: this.inventory
        }
    }
}