import { PlayerFriendAssist } from "@game/model/character";
import { accountManager } from "./AccountManger";
import { pick } from "lodash";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import excel from "@excel/excel";

enum FriendServiceType {
  SEARCH_FRIEND = 0,
  GET_FRIEND_LIST = 1,
  GET_FRIEND_REQUEST = 2,
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

    if (type === FriendServiceType.GET_FRIEND_REQUEST) {
      return await accountManager.getFriendRequests(this._uid);
    } else if (type === FriendServiceType.SEARCH_FRIEND) {
      const playerList = await accountManager.searchPlayer(
        param.nickName + "#" + param.nickNumber,
      );
      const infoList = await Promise.all(
        playerList.map((friend) => accountManager.getPlayerFriendInfo(friend)),
      );
      return infoList.map((friend) => pick(friend, ["uid", "level"]));
    } else if (type === FriendServiceType.GET_FRIEND_LIST) {
      const social = await accountManager.getSocial(this._uid);
      const friendIdList = social.friends.map((friend) => friend.uid);
      const friendInfoList = await Promise.all(
        friendIdList.map((friend) =>
          accountManager.getPlayerFriendInfo(friend),
        ),
      );
      return friendInfoList.map((friend) =>
        pick(friend, ["uid", ...sortKeyList]),
      );
    }
  }

  async getFriendList(args: { idList: string[] }) {
    const { idList } = args;
    const friends = await Promise.all(
      idList.map((friend) => accountManager.getPlayerFriendInfo(friend)),
    );
    const friendAlias = (await accountManager.getSocial(this._uid)).friends.map(
      (friend) => friend.alias,
    );
    return {
      friends,
      friendAlias,
      resultIdList: idList,
    };
  }

  async deleteFriend(args: { id: string }) {
    await accountManager.deleteFriend(this._uid, args.id);
  }

  async sendFriendRequest(args: { id: string }) {
    await accountManager.sendFriendRequest(this._uid, args.id);
  }

  async processFriendRequest(args: { friendId: string; action: number }) {
    await accountManager.deleteFriendRequest(this._uid, args.friendId);
    if (args.action === 1) {
      await accountManager.addFriend(this._uid, args.friendId);
      await accountManager.deleteFriendRequest(args.friendId, this._uid);
    }
    await this._player.update(async (draft) => {
      draft.pushFlags.hasFriendRequest = 0;
    });
    return {
      friendNum: (await accountManager.getSocial(this._uid)).friends.length,
    };
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
    const { type, customIndex, templateGroup } = args;
    await this._player.update(async (draft) => {
      const medalBoard = draft.social.medalBoard;
      medalBoard.type = type;
      if (type === "CUSTOM") {
        medalBoard.custom = customIndex;
        medalBoard.template = null;
        medalBoard.templateMedalList = null;
      } else if (type === "TEMPLATE") {
        medalBoard.custom = null;
        medalBoard.template = templateGroup;
        let medalGroupId;
        if (templateGroup.includes("Activity")) {
          medalGroupId = "activityMedal";
        } else if (templateGroup.includes("Rogue")) {
          medalGroupId = "rogueMedal";
        } else {
          medalGroupId = "";
        }
        const medalIdList = excel.MedalTable.medalTypeData[
          medalGroupId
        ].groupData.find((item) => item.groupId === templateGroup)!.medalId;
        medalIdList.push(
          ...excel.MedalTable.medalList
            .filter(
              (medal) => medal.medalId in medalIdList && medal.advancedMedal,
            )
            .map((medal) => medal.advancedMedal!),
        );

        medalBoard.templateMedalList = medalIdList.filter(
          (medal) => medal in draft.medal.medals,
        );
      } else {
        medalBoard.custom = null;
        medalBoard.template = null;
        medalBoard.templateMedalList = null;
      }
    });
  }

  async setAssistCharList(args: { assistCharList: PlayerFriendAssist[] }) {
    const { assistCharList } = args;
    await this._player.update(async (draft) => {
      draft.social.assistCharList = assistCharList;
    });
  }

  async setFriendAlias(args: { friendId: string; alias: string }) {
    const { friendId, alias } = args;
    await accountManager.setFriendAlias(this._uid, friendId, alias);
  }

  async searchPlayer(args: { idList: string[] }) {
    const { idList } = args;
    const social = await accountManager.getSocial(this._uid);
    const friendRequestList = await Promise.all(
      idList.map((id) => accountManager.getPlayerFriendInfo(id)),
    );
    const friendStatusList = friendRequestList.map((id) => {
      if (social.friends.some((friend) => friend.uid === id.uid)) {
        return 2;
      } else if (social.friendRequests.includes(id.uid)) {
        return 1;
      } else {
        return 0;
      }
    });
    return {
      players: friendRequestList,
      resultIdList: idList,
      friendStatusList: friendStatusList,
    };
  }

  async getFriendRequestList(args: { idList: string[] }) {
    const { idList } = args;
    const friendRequestList = idList.map((id) =>
      accountManager.getPlayerFriendInfo(id),
    );
    return {
      requestList: await Promise.all(friendRequestList),
      resultIdList: idList,
    };
  }
}
