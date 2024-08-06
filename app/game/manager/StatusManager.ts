import EventEmitter from "events"
import { AvatarInfo, PlayerCollection, PlayerDataModel, PlayerStatus, PlayerNameCardStyle, NameCardMisc } from '../model/playerdata';
import excel from "../../excel/excel"
import { ItemBundle } from "../../excel/character_table";
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
        this._trigger.on("useItems", (items: ItemBundle[]) => items.forEach(item => this._useItem(item)))
        this._trigger.on("gainItems", (items: ItemBundle[]) => items.forEach(item => this._gainItem(item)))
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
        this.status.ap += this.status.maxAp
        this.status.androidDiamond -= 1
        this.status.iosDiamond -= 1
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

    _useItem(item: ItemBundle): void {
        if (!item.type) {
            item.type = excel.ItemTable.items[item.id].itemType as string
        }
        const funcs: { [key: string]: (item: ItemBundle) => void } = {
            
        }
        if(funcs[item.type]){
            funcs[item.type](item)
        }else{
            this._gainItem(Object.assign({}, item, { count: -item.count }))
        }

    }
    _gainItem(item: ItemBundle): void {
        if (!item.type) {
            item.type = excel.ItemTable.items[item.id].itemType as string
        }
        const funcs: { [key: string]: (item: ItemBundle) => void } = {
            "GOLD": (item: ItemBundle) => this.status.gold += item.count,
            "DIAMOND": (item: ItemBundle) => {
                this.status.iosDiamond += item.count
                this.status.androidDiamond += item.count
            },
            "EXP_PLAYER": (item: ItemBundle) => this.status.exp += item.count,
            "DIAMOND_SHD": (item: ItemBundle) =>this.status.diamondShard += item.count,
            "TKT_TRY": (item: ItemBundle) => this.status.practiceTicket += item.count,
            "TKT_RECRUIT": (item: ItemBundle) => this.status.recruitLicense += item.count,
            "TKT_INST_FIN": (item: ItemBundle) => this.status.instantFinishTicket += item.count,
            "TKT_GACHA": (item: ItemBundle) => this.status.gachaTicket += item.count,
            "TKT_GACHA_10": (item: ItemBundle) => this.status.tenGachaTicket += item.count,
            "RETURN_PROGRESS": (item: ItemBundle) => {},
            "NEW_PROGRESS": (item: ItemBundle) => {},
            "AP_GAMEPLAY": (item: ItemBundle) => this.status.ap += item.count,
            "HGG_SHD": (item: ItemBundle) => this.status.hggShard += item.count,
            "LGG_SHD": (item: ItemBundle) => this.status.lggShard += item.count,
        }
        if (funcs[item.type]) {
            funcs[item.type](item)
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