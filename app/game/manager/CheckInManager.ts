import EventEmitter from "events";
import { PlayerOpenServer, PlayerCheckIn, PlayerDataModel, PlayerStatus } from '../model/playerdata';
import excel from "../../excel/excel";
import { ItemBundle } from "../../excel/character_table";

export class CheckInManager {
    data: PlayerCheckIn;
    openServer: PlayerOpenServer
    _status: PlayerStatus
    _trigger: EventEmitter;
    get isSUb(): boolean {
        return this._status.monthlySubscriptionStartTime < Date.now() && Date.now() < this._status.monthlySubscriptionEndTime
    }
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.data = playerdata.checkIn;
        this.openServer = playerdata.openServer;
        this._status = playerdata.status;
        this._trigger = _trigger;
        this._trigger.on("refresh:monthly",this.monthlyRefresh.bind(this))
        this._trigger.on("refresh:daily",this.dailyRefresh.bind(this))
        
    }
    getChainLogInReward(index: number): ItemBundle[] {
        
        return []
    }
    dailyRefresh() {
        this.data.canCheckIn=1
        this.data.checkInRewardIndex +=1
    }
    monthlyRefresh() {
        let ts=parseInt((new Date().getTime()/1000).toString())
        this.data.checkInGroupId=Object.values(excel.CheckinTable.groups).find((t)=>ts>t.signStartTime&&ts<t.signEndTime)!.groupId
        this.data.checkInHistory=[]
        this.data.checkInRewardIndex=-1
    }
    checkIn(): { signInRewards: ItemBundle[], subscriptionRewards: ItemBundle[] } {
        let signInRewards: ItemBundle[] = []
        let subscriptionRewards: ItemBundle[] = []
        if (this.data.canCheckIn) {
            this.data.canCheckIn = 0;
            let item = excel.CheckinTable.groups[this.data.checkInGroupId].items[this.data.checkInRewardIndex];
            signInRewards = [{ id: item.itemId, count: item.count, type: item.itemType }]
            if (this.isSUb) {
                subscriptionRewards = excel.CheckinTable.monthlySubItem["mCard_1"][1].items
            }
            this.data.checkInHistory.push(0)
            this._trigger.emit("gainItems", subscriptionRewards.concat(signInRewards))
        }
        return { signInRewards: signInRewards, subscriptionRewards: subscriptionRewards }
    }
    toJSON() {
        return {
            checkIn: this.data,
            openServer: this.openServer
        }
    }
}