import EventEmitter from "events"
import { AvatarInfo, PlayerCollection, PlayerDataModel, PlayerStatus } from "../model/playerdata"
import { InventoryManager } from "./InventoryManager"
import excel from "../../excel/excel"

export class StatusManager {
    status: PlayerStatus
    collectionReward:PlayerCollection
    _trigger: EventEmitter
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.status = playerdata.status
        this.collectionReward=playerdata.collectionReward
        this._trigger = _trigger
        this._trigger.on("status:refresh:time",this.refreshTime.bind(this))
        this._trigger.on("status:change:secretary",this._changeSecretary.bind(this))
        this._trigger.on("refresh:daily",this.dailyRefresh.bind(this))
        this._trigger.on("refresh:weekly",this.weeklyRefresh.bind(this))
        this._trigger.on("refresh:monthly",this.monthlyRefresh.bind(this))
    }
    refreshTime(){
        let ts=parseInt((new Date().getTime()/1000).toString())
        let isNewDay=new Date(this.status.lastRefreshTs*1000-14400000).getDate()!=new Date().getDate()
        if(isNewDay){
            if(new Date().getDate()==1){
                this._trigger.emit("refresh:monthly")
            }
            if(new Date().getDay()==1){
                this._trigger.emit("refresh:weekly")
            }
            this._trigger.emit("refresh:daily")
        }
        if(this.status.ap<this.status.maxAp){
            let apAdd=Math.floor((Math.floor(ts/1000)-this.status.lastApAddTime)/300)
            if (this.status.ap+apAdd>this.status.maxAp){
                apAdd=this.status.maxAp-this.status.ap
            }
            this.status.ap+=apAdd
            this.status.lastApAddTime+=apAdd*300
        }
        this.status.lastRefreshTs=ts
        this.status.lastOnlineTs=ts
    }
    dailyRefresh(){

    }
    weeklyRefresh(){

    }
    monthlyRefresh(){

    }
    _refreshStatus(inventory:InventoryManager) {
        this.status.gold=inventory.items["4001"]
        this.status.diamondShard=inventory.items["4003"]
        this.status.exp=inventory.items["5001"]
        this.status.socialPoint=inventory.items["SOCIAL_PT"]
        this.status.gachaTicket=inventory.items["7003"]
        this.status.tenGachaTicket=inventory.items["7004"]
        this.status.instantFinishTicket=inventory.items["7002"]
        this.status.recruitLicense=inventory.items["7001"]
        this.status.ap=inventory.items["AP_GAMEPLAY"]
        this.status.iosDiamond=inventory.items["4002"]
        this.status.androidDiamond=inventory.items["4002"]
        this.status.practiceTicket=inventory.items["6001"]
        this.status.hggShard=inventory.items["4004"]
        this.status.lggShard=inventory.items["4005"]
        this.status.classicShard=inventory.items["classic_normal_ticket"]
        this.status.classicGachaTicket=inventory.items["classic_gacha"]
        this.status.classicTenGachaTicket=inventory.items["classic_gacha_10"]
    }
    _changeSecretary(charId: string, skinId: string) {
        this.status.secretary=charId
        this.status.secretarySkinId=skinId
    }
    finishStory(storyId:string){
        this.status.flags[storyId]=1
    }
    changeAvatar(avatar: AvatarInfo) {
        this.status.avatar=avatar
    }
    changeResume(resume: string) {
        this.status.resume=resume
    }
    bindNickName(nickname: string) {
        this.status.nickName=nickname
    }
    buyAp(){
        this.status.ap+=this.status.maxAp
        this.status.androidDiamond-=1
        this.status.iosDiamond-=1
    }
    exchangeDiamondShard(count:number){
        this.status.androidDiamond-=count
        this.status.iosDiamond-=count
        this.status.diamondShard+=count*excel.GameDataConst.diamondToShdRate
    }
    receiveTeamCollectionReward(rewardId:string){
        this.collectionReward.team[rewardId]=1
        this._trigger.emit("gainItems",[excel.HandbookInfoTable.teamMissionList[rewardId].item])
    }
    toJSON(){
        return {
            status:this.status,
            collectionReward:this.collectionReward
        }
    }
}