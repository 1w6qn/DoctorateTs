/**
 * 社交服务（B-1 拆分）
 *
 * 好友/申请/访问操作（social.db 为唯一事实源）。
 * 依赖 AccountManager 门面（friendRepo/trigger/data/playerData）。
 * 由 AccountManager 持有并委托——公共方法签名保留在门面上，调用点零改动。
 */
import type { AccountManager } from "./AccountManager";

export class SocialService {
  constructor(private _manager: AccountManager) {}

  /** 获取社交信息（好友列表、好友请求、访问记录） */
  async getSocial(uid: string): Promise<{
    friends: { uid: string; alias: string }[];
    friendRequests: string[];
    visited: string[];
  }> {
    return {
      friends: this._manager._friendRepo.getFriendList(uid),
      friendRequests: this._manager._friendRepo.getFriendRequests(uid),
      visited: this._manager._friendRepo.getVisited(uid),
    };
  }

  /** 删除好友（双向删除） */
  async deleteFriend(uid: string, friendUid: string): Promise<void> {
    this._manager._friendRepo.deleteFriend(uid, friendUid);
    this._manager._friendRepo.deleteFriend(friendUid, uid);
    await this._manager._trigger.emit("save", []);
  }

  /** 添加好友（单向；双向关系由调用方决定） */
  async addFriend(uid: string, friendUid: string): Promise<void> {
    this._manager._friendRepo.addFriend(uid, friendUid);
    await this._manager._trigger.emit("save", []);
  }

  /** 发送好友请求（带校验：不能给自己发、已是好友拒绝、重复申请拒绝） */
  async sendFriendRequest(from: string, to: string): Promise<void> {
    if (from === to) {
      throw new Error("不能向自己发送好友请求");
    }
    if (this._manager._friendRepo.hasFriend(from, to)) {
      throw new Error("对方已是你的好友");
    }
    if (this._manager._friendRepo.hasFriendRequest(to, from)) {
      throw new Error("好友请求已发送，请勿重复发送");
    }
    this._manager._friendRepo.sendFriendRequest(from, to);
    const friendData = await this._manager.getPlayerData(to);
    await friendData.update(async (draft) => {
      draft.pushFlags.hasFriendRequest = 1;
    });
    await this._manager._trigger.emit("save", []);
  }

  /** 删除好友请求 */
  async deleteFriendRequest(uid: string, friendId: string): Promise<void> {
    this._manager._friendRepo.deleteFriendRequest(uid, friendId);
    await this._manager._trigger.emit("save", []);
  }

  /** 设置好友别名 */
  async setFriendAlias(
    uid: string,
    friendId: string,
    alias: string,
  ): Promise<void> {
    this._manager._friendRepo.setFriendAlias(uid, friendId, alias);
    await this._manager._trigger.emit("save", []);
  }

  /** 获取好友请求列表 */
  async getFriendRequests(uid: string): Promise<string[]> {
    return this._manager._friendRepo.getFriendRequests(uid);
  }

  /** 搜索玩家（uid/昵称/昵称#数字） */
  async searchPlayer(keyword: string): Promise<string[]> {
    return Object.entries(this._manager.data)
      .filter(([uid, data]) => {
        return (
          // 修复：原 `keyword.includes(uid)` 方向反了——昵称里含某 uid 数字就误匹配，
          // 搜索结果混入无关账号；改为按 uid 部分匹配
          uid.includes(keyword) ||
          data._playerdata.status.nickName == keyword ||
          data._playerdata.status.nickName + "#" + data._playerdata.status.nickNumber ==
            keyword
        );
      })
      .map(([uid]) => uid);
  }
}
