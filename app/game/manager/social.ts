import {
  PlayerDataModel,
  PlayerMedalBoard,
  PlayerSocial,
  PlayerSocialReward,
} from "@game/model/playerdata";
import { PlayerFriendAssist } from "@game/model/character";
import EventEmitter from "events";
import { accountManager } from "./AccountManger";
import { pick } from "lodash";
import { FriendDataWithNameCard } from "@game/model/social";

enum FriendServiceType {
  SEARCH_FRIEND = 0,
  GET_FRIEND_LIST = 1,
  GET_FRIEND_REQUEST = 2,
}

enum FriendDealEnum {
  REFUSE = 0,
  ACCEPT = 1,
}
export class SocialManager implements PlayerSocial {
  assistCharList: PlayerFriendAssist[];
  yesterdayReward: PlayerSocialReward;
  yCrisisSs: string;
  medalBoard: PlayerMedalBoard;
  yCrisisV2Ss: string;
  _uid: string;
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
    type: FriendServiceType;
    sortKeyList: string[];
    param: { [key: string]: string };
  }) {
    const friendIdList = accountManager.getSocial(this._uid).friends;
    const friendInfoList = friendIdList.map((friend) =>
      accountManager.getPlayerFriendInfo(friend),
    );
    const funcs: {
      [key: number]: (
        friend: FriendDataWithNameCard,
        param: { [key: string]: string },
      ) => any;
    } = {
      [FriendServiceType.SEARCH_FRIEND]: (
        friend: FriendDataWithNameCard,
        param: { [key: string]: string },
      ) => {},
      [FriendServiceType.GET_FRIEND_LIST]: (
        friendInfo: FriendDataWithNameCard,
        param: { [key: string]: string },
      ) => {
        return pick(friendInfo, ["uid", ...args.sortKeyList]);
      },
      [FriendServiceType.GET_FRIEND_REQUEST]: (
        friend: FriendDataWithNameCard,
        param: { [key: string]: string },
      ) => {},
    };

    return friendInfoList.map((friend) => funcs[args.type](friend, args.param));
  }

  getFriendList(args: { idList: string[] }) {
    return args.idList.map((friend) =>
      accountManager.getPlayerFriendInfo(friend),
    );
  }

  deleteFriend(args: { id: string }) {
    accountManager.deleteFriend(this._uid, args.id);
  }

  sendFriendRequest(args: { id: string }) {
    accountManager.sendFriendRequest(this._uid, args.id);
  }

  processFriendRequest(args: { friendId: string; action: FriendDealEnum }) {
    accountManager.deleteFriendRequest(this._uid, args.friendId);
    if (args.action === FriendDealEnum.ACCEPT) {
      accountManager.addFriend(this._uid, args.friendId);
    }
  }

  receiveSocialPoint() {
    if (this.yesterdayReward.canReceive) {
      const point =
        this.yesterdayReward.assistAmount + this.yesterdayReward.comfortAmount;
      this._trigger.emit("gainItems", [
        { id: "", type: "SOCIAL_PT", num: point },
      ]);
      this.yesterdayReward.canReceive = 0;
    }
  }

  setCardShowMedal(args: {
    type: string;
    customIndex: string;
    templateGroup: string;
  }) {
    this.medalBoard.type = args.type;
    this.medalBoard.template = args.templateGroup;
    //TODO
    //this.medalBoard.custom=args.customIndex
  }

  setAssistCharList(assistCharList: PlayerFriendAssist[]) {
    this.assistCharList = assistCharList;
  }

  setFriendAlias() {}

  searchPlayer(args: { idList: string[] }) {}

  toJSON() {
    return {
      assistCharList: this.assistCharList,
      yesterdayReward: this.yesterdayReward,
      yCrisisSs: this.yCrisisSs,
      medalBoard: this.medalBoard,
      yCrisisV2Ss: this.yCrisisV2Ss,
    };
  }
}
