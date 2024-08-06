
import { PlayerMedalBoard, PlayerDataModel, PlayerSocial, PlayerSocialReward } from "@game/model/playerdata";
import { PlayerFriendAssist } from "@game/model/character";
import EventEmitter from "events";
import { accountManager } from './AccountManger';
enum FriendServiceType {
    SEARCH_FRIEND = 0,
    GET_FRIEND_LIST = 1,
    GET_FRIEND_REQUEST = 2,
}
export class SocialManager implements PlayerSocial {
    assistCharList: PlayerFriendAssist[];
    yesterdayReward: PlayerSocialReward;
    yCrisisSs: string;
    medalBoard: PlayerMedalBoard;
    yCrisisV2Ss: string;
    _uid: string
    _trigger: EventEmitter;
    constructor(player: PlayerDataModel, _trigger: EventEmitter) {
        this.assistCharList = player.social.assistCharList;
        this.yesterdayReward = player.social.yesterdayReward;
        this.yCrisisSs = player.social.yCrisisSs;
        this.medalBoard = player.social.medalBoard;
        this.yCrisisV2Ss = player.social.yCrisisV2Ss;
        this._uid = player.status.uid;
        this._trigger = _trigger;
    }
    getSortListInfo(args: {
        type: FriendServiceType, sortKeyList: string[], param: { [key: string]: string }
    }) {
        const friendList = accountManager.getSocial(this._uid).friends;
        let res: any[] = []

        friendList.forEach(friend => {
            res.push(accountManager.getPlayerFriendInfo(friend, args.type))
        })

        return res
    }
    getFriendList(args:{idList:string[]}){
        const friendList = accountManager.getSocial(this._uid).friends;
    }
    toJSON() {
        return {
            assistCharList: this.assistCharList,
            yesterdayReward: this.yesterdayReward,
            yCrisisSs: this.yCrisisSs,
            medalBoard: this.medalBoard,
            yCrisisV2Ss: this.yCrisisV2Ss,
        }
    }
}