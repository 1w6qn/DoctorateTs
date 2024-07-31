import EventEmitter from "events"
import { AvatarInfo, PlayerCollection, PlayerDataModel, PlayerStatus, PlayerNameCardStyle, NameCardMisc } from '../model/playerdata';
import excel from "../../excel/excel"
import { ItemBundle } from "../../excel/character_table";

export class StatusManager {
    status: PlayerStatus
    collectionReward:PlayerCollection
    nameCardStyle:PlayerNameCardStyle
    _trigger: EventEmitter
    get uid(): string {
        return this.status.uid
    }
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.status = playerdata.status
        this.collectionReward=playerdata.collectionReward
        this.nameCardStyle=playerdata.nameCardStyle
        this._trigger = _trigger
        this._trigger.on("status:refresh:time",this.refreshTime.bind(this))
        this._trigger.on("status:change:secretary",this._changeSecretary.bind(this))
        this._trigger.on("refresh:daily",this.dailyRefresh.bind(this))
        this._trigger.on("refresh:weekly",this.weeklyRefresh.bind(this))
        this._trigger.on("refresh:monthly",this.monthlyRefresh.bind(this))
        this._trigger.on("useItems", (items: ItemBundle[]) => items.forEach(item => this._useItem(item)))
        this._trigger.on("gainItems", (items: ItemBundle[]) => items.forEach(item => this._gainItem(item)))
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
            let apAdd=Math.floor((ts-this.status.lastApAddTime)/300)
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
    getOtherPlayerNameCard(uid:string){
        //TODO
    }
    editNameCard(flag:number,content:{skinId?:string,component?:string[],misc?:NameCardMisc}){
        switch (flag) {
            case 1:
                this.nameCardStyle.componentOrder=content.component!
                break;
            case 2:
                this.nameCardStyle.skin.selected=content.skinId!
                break;
            case 4:
                this.nameCardStyle.misc=content.misc!
                break;
            default:
                break;
        }
    }
    _useItem(item: ItemBundle): void {
        if (!item.type) {
            item.type = excel.ItemTable.items[item.id].itemType as string
        }
        switch (item.type) {
            default:
                this._gainItem(Object.assign(item, { count: -item.count }))
                break;
        }
    }
    _gainItem(item: ItemBundle): void {
        if (!item.type) {
            item.type = excel.ItemTable.items[item.id].itemType as string
        }
        switch (item.type) {
            case "GOLD":
                this.status.gold += item.count
                break
            case "DIAMOND":
                this.status.iosDiamond += item.count
                this.status.androidDiamond += item.count
                break
            case "EXP_PLAYER":
                this.status.exp += item.count
                break
            case "DIAMOND_SHD":
                this.status.diamondShard += item.count
                break
            case "TKT_TRY":
                this.status.practiceTicket += item.count
                break
            case "TKT_RECRUIT":
                this.status.recruitLicense += item.count
                break
            case "TKT_INST_FIN":
                this.status.instantFinishTicket += item.count
                break
            case "TKT_GACHA":
                this.status.gachaTicket += item.count
                break
            case "TKT_GACHA_10":
                this.status.tenGachaTicket += item.count
                break
            case "RETURN_PROGRESS":
                //this.status.recruitLicense+=item.count
                break
            case "NEW_PROGRESS":
                //this.status.recruitLicense+=item.count
                break
            case "AP_GAMEPLAY":
                this.status.ap += item.count
                break
            case "HGG_SHD":
                this.status.hggShard += item.count
                break
            case "LGG_SHD":
                this.status.lggShard += item.count
                break
            default:
                break;
        }
    }
    toJSON(){
        return {
            status:this.status,
            collectionReward:this.collectionReward,
            nameCardStyle:this.nameCardStyle,
        }
    }
}