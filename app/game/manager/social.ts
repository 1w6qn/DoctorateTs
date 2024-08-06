
import { PlayerMedalBoard, PlayerDataModel, PlayerSocial, PlayerSocialReward } from "@game/model/playerdata";
import { PlayerFriendAssist } from "@game/model/character";
import EventEmitter from "events";

export class SocialManager implements PlayerSocial {
    assistCharList: PlayerFriendAssist[];
    yesterdayReward: PlayerSocialReward;
    yCrisisSs: string;
    medalBoard: PlayerMedalBoard;
    yCrisisV2Ss: string;
    _trigger:EventEmitter;
    constructor(player:PlayerDataModel,_trigger:EventEmitter) {
        this.assistCharList = player.social.assistCharList;
        this.yesterdayReward = player.social.yesterdayReward;
        this.yCrisisSs = player.social.yCrisisSs;
        this.medalBoard = player.social.medalBoard;
        this.yCrisisV2Ss = player.social.yCrisisV2Ss;
        this._trigger = _trigger;
    }
    toJSON(){
        return {
            assistCharList:this.assistCharList,
            yesterdayReward:this.yesterdayReward,
            yCrisisSs:this.yCrisisSs,
            medalBoard:this.medalBoard,
            yCrisisV2Ss:this.yCrisisV2Ss,
        }
    }
}