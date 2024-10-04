import { PlayerFriendAssist } from "@game/model/character";
import { accountManager } from "./AccountManger";
import { pick } from "lodash";
import { FriendDataWithNameCard } from "@game/model/social";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

enum FriendServiceType {
  SEARCH_FRIEND = 0,
  GET_FRIEND_LIST = 1,
  GET_FRIEND_REQUEST = 2,
}

enum FriendDealEnum {
  REFUSE = 0,
  ACCEPT = 1,
}

export class SocialManager {
  _player: PlayerDataManager;
  _uid: string;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._uid = player._playerdata.status.uid;
    this._trigger = _trigger;
  }

  async getSortListInfo(args: {
    type: FriendServiceType;
    sortKeyList: string[];
    param: { [key: string]: string };
  }) {
    const { type, sortKeyList, param } = args;
    const friendIdList = accountManager.getSocial(this._uid).friends;
    const friendInfoList = await Promise.all(
      friendIdList.map((friend) => accountManager.getPlayerFriendInfo(friend)),
    );
    const funcs: {
      [key: number]: (
        friend: FriendDataWithNameCard,
        param: { [key: string]: string },
      ) => object | void;
    } = {
      [FriendServiceType.SEARCH_FRIEND]: () => {},
      [FriendServiceType.GET_FRIEND_LIST]: (friend: FriendDataWithNameCard) => {
        return pick(friend, ["uid", ...sortKeyList]);
      },
      [FriendServiceType.GET_FRIEND_REQUEST]: () => {},
    };

    return friendInfoList.map((friend) => funcs[type](friend, param));
  }

  async getFriendList(args: { idList: string[] }) {
    return await Promise.all(
      args.idList.map((friend) => accountManager.getPlayerFriendInfo(friend)),
    );
  }

  async deleteFriend(args: { id: string }) {
    accountManager.deleteFriend(this._uid, args.id);
  }

  async sendFriendRequest(args: { id: string }) {
    accountManager.sendFriendRequest(this._uid, args.id);
  }

  async processFriendRequest(args: {
    friendId: string;
    action: FriendDealEnum;
  }) {
    accountManager.deleteFriendRequest(this._uid, args.friendId);
    if (args.action === FriendDealEnum.ACCEPT) {
      accountManager.addFriend(this._uid, args.friendId);
    }
  }

  async receiveSocialPoint() {
    await this._player.update(async (draft) => {
      if (draft.social.yesterdayReward.canReceive) {
        const point =
          draft.social.yesterdayReward.assistAmount +
          draft.social.yesterdayReward.comfortAmount;
        this._trigger.emit("items:get", [
          { id: "", type: "SOCIAL_PT", count: point },
        ]);
        draft.social.yesterdayReward.canReceive = 0;
      }
    });
  }

  async setCardShowMedal(args: {
    type: string;
    customIndex: string;
    templateGroup: string;
  }) {
    const { type, templateGroup } = args;
    await this._player.update(async (draft) => {
      draft.social.medalBoard.type = type;
      draft.social.medalBoard.template = templateGroup;
      //TODO
      //draft.social.medalBoard.custom = customIndex;
    });
  }

  async setAssistCharList(args: { assistCharList: PlayerFriendAssist[] }) {
    const { assistCharList } = args;
    await this._player.update(async (draft) => {
      draft.social.assistCharList = assistCharList;
    });
  }

  async setFriendAlias(args: {}) {}

  async searchPlayer(args: { idList: string[] }) {
    const { idList } = args;
  }

  async getFriendRequestList() {}
}
