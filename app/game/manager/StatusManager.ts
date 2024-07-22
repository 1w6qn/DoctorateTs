import EventEmitter from "events"
import { AvatarInfo, PlayerStatus } from "../model/playerdata"
import { InventoryManager } from "./InventoryManager"
import excel from "../../excel/excel"

export class StatusManager {
    status: PlayerStatus
    _trigger: EventEmitter
    constructor(status: PlayerStatus, _trigger: EventEmitter) {
        this.status = status
        this._trigger = _trigger
        this._trigger.on("status:refresh:time",this.refreshTime.bind(this))
        this._trigger.on("status:refresh",this._refreshStatus.bind(this))
        this._trigger.on("status:change:secretary",this._changeSecretary.bind(this))
    }
    refreshTime(){
        let ts=parseInt((new Date().getTime()/1000).toString())
        this.status.lastRefreshTs=ts
        this.status.lastApAddTime=ts
        this.status.lastOnlineTs=ts
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
        this.status.ap+=120
        this.status.androidDiamond-=1
        this.status.iosDiamond-=1
    }
    exchangeDiamondShard(count:number){
        this.status.androidDiamond-=count
        this.status.iosDiamond-=count
        this.status.diamondShard+=count*excel.GameDataConst.diamondToShdRate
    }
    toJSON(){
        return this.status
    }
}