import EventEmitter from "events"
import { AvatarInfo, PlayerCollection, PlayerDataModel, PlayerStatus, PlayerNameCardStyle, NameCardMisc } from '../model/playerdata';
import excel from "@excel/excel"
import { checkNewDay, checkNewMonth, checkNewWeek, now } from "@utils/time";
import moment from "moment";

export class StatusManager {
    status: PlayerStatus
    collectionReward: PlayerCollection
    nameCardStyle: PlayerNameCardStyle
    _trigger: EventEmitter
    get uid(): string {
        return this.status.uid
    }
    constructor(playerdata: PlayerDataModel, _trigger: EventEmitter) {
        this.status = playerdata.status
        this.collectionReward = playerdata.collectionReward
        this.nameCardStyle = playerdata.nameCardStyle
        this._trigger = _trigger
        this._trigger.on("status:refresh:time", this.refreshTime.bind(this))
        this._trigger.on("status:change:secretary", this._changeSecretary.bind(this))
        this._trigger.on("refresh:daily", this.dailyRefresh.bind(this))
        this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this))
        this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this))
    }
    refreshTime() {
        let ts = now()
        if (checkNewDay(this.status.lastRefreshTs, ts)) {
            this._trigger.emit("refresh:daily")
        }
        if (moment().date() == 1 && checkNewMonth(this.status.lastRefreshTs, ts)) {
            this._trigger.emit("refresh:monthly")
        }
        if (moment().day() == 1 && checkNewWeek(this.status.lastRefreshTs, ts)) {
            this._trigger.emit("refresh:weekly")
        }
        if (this.status.ap < this.status.maxAp) {
            let apAdd = Math.floor((ts - this.status.lastApAddTime) / 300)
            if (this.status.ap + apAdd > this.status.maxAp) {
                apAdd = this.status.maxAp - this.status.ap
            }
            this.status.ap += apAdd
            this.status.lastApAddTime += apAdd * 300
        }
        this.status.lastRefreshTs = ts
        this.status.lastOnlineTs = ts
    }
    dailyRefresh() {

    }
    weeklyRefresh() {

    }
    monthlyRefresh() {

    }
    _changeSecretary(charId: string, skinId: string) {
        this.status.secretary = charId
        this.status.secretarySkinId = skinId
    }
    finishStory(storyId: string) {
        this.status.flags[storyId] = 1
    }
    changeAvatar(avatar: AvatarInfo) {
        this.status.avatar = avatar
    }
    changeResume(resume: string) {
        this.status.resume = resume
    }
    bindNickName(nickname: string) {
        this.status.nickName = nickname
    }
    buyAp() {
        this._trigger.emit("gainItems",[{ id:"",type: "AP_GAMEPLAY", count: this.status.maxAp }])
        this._trigger.emit("useItems",[{ id:"",type: "DIAMOND", count: 1 }])
    }
    exchangeDiamondShard(count: number) {
        this.status.androidDiamond -= count
        this.status.iosDiamond -= count
        this.status.diamondShard += count * excel.GameDataConst.diamondToShdRate
    }
    receiveTeamCollectionReward(rewardId: string) {
        this.collectionReward.team[rewardId] = 1
        this._trigger.emit("gainItems", [excel.HandbookInfoTable.teamMissionList[rewardId].item])
    }
    getOtherPlayerNameCard(uid: string) {
        //TODO
    }
    editNameCard(flag: number, content: { skinId?: string, component?: string[], misc?: NameCardMisc }) {
        switch (flag) {
            case 1:
                this.nameCardStyle.componentOrder = content.component!
                break;
            case 2:
                this.nameCardStyle.skin.selected = content.skinId!
                break;
            case 4:
                this.nameCardStyle.misc = content.misc!
                break;
            default:
                break;
        }
    }
    toJSON() {
        return {
            status: this.status,
            collectionReward: this.collectionReward,
            nameCardStyle: this.nameCardStyle,
        }
    }
}