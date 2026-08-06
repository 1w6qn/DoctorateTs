import { PlayerFriendAssist } from "@game/model/character";
import { accountManager } from "./AccountManger";
import { pick } from "lodash";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import excel from "@excel/excel";
import { NameCardMisc } from "@game/model/playerdata";

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
      const friendIdList = await accountManager.getFriendRequests(this._uid);
      return await Promise.all(
        friendIdList.map((friend) =>
          accountManager.getPlayerFriendInfo(friend),
        ),
      );
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

  async sendFriendRequest(args: {
    friendId: string;
    afterBattle: number;
    originType: number;
    battleOrigin: string | null;
  }) {
    await accountManager.sendFriendRequest(this._uid, args.friendId);
  }

  async processFriendRequest(args: { friendId: string; action: number }) {
    await accountManager.deleteFriendRequest(this._uid, args.friendId);
    if (args.action === 1) {
      // 双向好友：己方加对方 + 对方加己方
      await accountManager.addFriend(this._uid, args.friendId);
      await accountManager.addFriend(args.friendId, this._uid);
      await accountManager.deleteFriendRequest(args.friendId, this._uid);
    }
    if ((await accountManager.getFriendRequests(args.friendId)).length === 0) {
      await this._player.update(async (draft) => {
        draft.pushFlags.hasFriendRequest = 0;
      });
    }
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
        await this._trigger.emit("items:get", [
          [{ id: "", type: "SOCIAL_PT", count: point }],
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

  async getOtherPlayerNameCard(args: { uid: string }) {
    const { uid } = args;
    return await accountManager.getPlayerFriendInfo(uid);
  }
  async changeNameCardComponent(args: { component: string[] }){
    const { component } = args;
    await this._player.update(async (draft) => {
      draft.nameCardStyle.componentOrder = component;
    });
  }
  async changeNameCardSkin(args: { skinId: string }){
    const { skinId } = args;
    await this._player.update(async (draft) => {
      draft.nameCardStyle.skin.selected = skinId;
    });
  }
  async editNameCard(args: {
    flag: number;
    content: { skinId?: string; component?: string[]; misc?: NameCardMisc };
  }) {
    const { flag, content } = args;
    await this._player.update(async (draft) => {
      switch (flag) {
        case 1:
          draft.nameCardStyle.componentOrder = content.component!;
          break;
        case 2:
          draft.nameCardStyle.skin.selected = content.skinId!;
          break;
        case 4:
          draft.nameCardStyle.misc = content.misc!;
          break;
        default:
          break;
      }
    });
  }
  async setAssistCharList(args: { assistCharList: PlayerFriendAssist[] }) {
    const { assistCharList } = args;
    await this._player.update(async (draft) => {
      draft.social.assistCharList = assistCharList;
    });
  }

  /**
   * 获取编队助战列表（按职业筛选好友助战干员）
   * 好友随机排序，最多取 6 个，干员按 charId 去重；
   * 好友数据不足时从其他账号随机补位（非好友、可请求）
   */
  async getAssistList(args: { profession: string }) {
    const { profession } = args;
    const social = await accountManager.getSocial(this._uid);
    const friendUids = new Set(social.friends.map((f) => f.uid));
    const assistList: any[] = [];
    const usedCharIds = new Set<string>();
    const MAX_LIST = 6;

    const buildAssistInfo = (info: any, isFriend: boolean, alias: string) => {
      const assistChars: any[] = info?.assistCharList || [];
      const matched = assistChars.find((c) => {
        const data = excel.CharacterTable[c?.charId];
        return data?.profession === profession;
      });
      if (!matched) return null;
      if (usedCharIds.has(matched.charId)) return null;
      usedCharIds.add(matched.charId);
      return {
        aliasName: isFriend ? alias : null,
        assistCharList: assistChars,
        assistSlotIndex: assistChars.indexOf(matched),
        avatar: info.avatar,
        canRequestFriend: !isFriend,
        isFriend,
        lastOnlineTime: info.lastOnlineTime,
        level: info.level,
        nickName: info.nickName,
        nickNumber: info.nickNumber,
        powerScore: 200,
        uid: info.uid,
      };
    };

    // 1. 好友助战（随机洗牌，最多 MAX_LIST）
    const friends = [...social.friends].sort(() => Math.random() - 0.5);
    for (const friend of friends) {
      if (assistList.length >= MAX_LIST) break;
      let info: any;
      try {
        info = await accountManager.getPlayerFriendInfo(friend.uid);
      } catch {
        continue;
      }
      const item = buildAssistInfo(info, true, friend.alias);
      if (item) assistList.push(item);
    }

    // 2. 数据不足时随机补位（其他账号，非好友）
    if (assistList.length < MAX_LIST) {
      const otherUids = accountManager
        .getPlayerUidList()
        .filter((uid) => uid !== this._uid && !friendUids.has(uid))
        .sort(() => Math.random() - 0.5);
      for (const uid of otherUids) {
        if (assistList.length >= MAX_LIST) break;
        let info: any;
        try {
          info = await accountManager.getPlayerFriendInfo(uid);
        } catch {
          continue;
        }
        const item = buildAssistInfo(info, false, "");
        if (item) assistList.push(item);
      }
    }

    return assistList;
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
