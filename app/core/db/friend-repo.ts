/**
 * 好友关系仓储
 *
 * 封装 friends / friend_requests / friend_request_log / visited 四张表的 CRUD。
 * 方法语义与 AccountManager 原社交方法一致，便于平滑替换。
 *
 * 后端无关：只写 `?` 占位符与公共 SQL，冲突处理经 {@link insertIgnoreSql} /
 * {@link insertReplaceSql} 按后端生成。全部方法异步（SQLite 同步执行，其余后端真实异步）。
 */
import {
  insertIgnoreSql,
  insertReplaceSql,
  toCount,
} from "./dialect";
import type { SqlDatabase } from "./types";
import { now } from "@utils/time";

/** friends 表列顺序（与 {@link FriendRepository.addFriend} 入参一致） */
const FRIENDS_COLUMNS = ["uid", "friend_uid", "alias", "create_ts"];

export class FriendRepository {
  /** @param db - 后端无关的数据库句柄 */
  constructor(private _db: SqlDatabase) {}

  /**
   * 获取用户好友列表（按创建时间升序）
   * @param uid - 账号 uid
   */
  async getFriendList(uid: string): Promise<{ uid: string; alias: string }[]> {
    return this._db
      .prepare(
        "SELECT friend_uid AS uid, alias FROM friends WHERE uid = ? ORDER BY create_ts ASC",
      )
      .all<{ uid: string; alias: string }>(uid);
  }

  /**
   * 判断是否已是好友
   * @param uid - 账号 uid
   * @param friendUid - 对方 uid
   */
  async hasFriend(uid: string, friendUid: string): Promise<boolean> {
    const row = await this._db
      .prepare("SELECT 1 FROM friends WHERE uid = ? AND friend_uid = ?")
      .get(uid, friendUid);
    return !!row;
  }

  /**
   * 添加好友（单向，调用方决定是否双向；已存在则忽略）
   * @param uid - 账号 uid
   * @param friendUid - 对方 uid
   * @param alias - 备注名
   */
  async addFriend(uid: string, friendUid: string, alias = ""): Promise<void> {
    await this._db
      .prepare(
        insertIgnoreSql(this._db.backend, "friends", FRIENDS_COLUMNS),
      )
      .run(uid, friendUid, alias, now());
  }

  /**
   * 删除好友
   * @param uid - 账号 uid
   * @param friendUid - 对方 uid
   */
  async deleteFriend(uid: string, friendUid: string): Promise<void> {
    await this._db
      .prepare("DELETE FROM friends WHERE uid = ? AND friend_uid = ?")
      .run(uid, friendUid);
  }

  /**
   * 设置好友备注
   * @param uid - 账号 uid
   * @param friendUid - 对方 uid
   * @param alias - 备注名
   */
  async setFriendAlias(
    uid: string,
    friendUid: string,
    alias: string,
  ): Promise<void> {
    await this._db
      .prepare("UPDATE friends SET alias = ? WHERE uid = ? AND friend_uid = ?")
      .run(alias, uid, friendUid);
  }

  /**
   * 获取用户收到的申请列表（from_uid 数组）
   * @param uid - 账号 uid
   */
  async getFriendRequests(uid: string): Promise<string[]> {
    const rows = await this._db
      .prepare(
        "SELECT from_uid FROM friend_requests WHERE to_uid = ? ORDER BY create_ts ASC",
      )
      .all<{ from_uid: string }>(uid);
    return rows.map((r) => r.from_uid);
  }

  /**
   * 判断是否存在未处理申请
   * @param uid - 账号 uid（收方）
   * @param fromUid - 申请方 uid
   */
  async hasFriendRequest(uid: string, fromUid: string): Promise<boolean> {
    const row = await this._db
      .prepare("SELECT 1 FROM friend_requests WHERE to_uid = ? AND from_uid = ?")
      .get(uid, fromUid);
    return !!row;
  }

  /**
   * 发送申请（from -> to；重复申请忽略）
   * @param fromUid - 申请方 uid
   * @param toUid - 收方 uid
   */
  async sendFriendRequest(fromUid: string, toUid: string): Promise<void> {
    await this._db
      .prepare(
        insertIgnoreSql(this._db.backend, "friend_requests", [
          "from_uid",
          "to_uid",
          "create_ts",
        ]),
      )
      .run(fromUid, toUid, now());
  }

  /**
   * 删除申请（删除 to 收到的来自 from 的申请）
   * @param uid - 收方 uid
   * @param fromUid - 申请方 uid
   */
  async deleteFriendRequest(uid: string, fromUid: string): Promise<void> {
    await this._db
      .prepare("DELETE FROM friend_requests WHERE to_uid = ? AND from_uid = ?")
      .run(uid, fromUid);
  }

  /**
   * 记录访问（覆盖同对账号的旧记录）
   * @param uid - 访问者 uid
   * @param visitedUid - 被访问者 uid
   */
  async addVisit(uid: string, visitedUid: string): Promise<void> {
    await this._db
      .prepare(
        insertReplaceSql(
          this._db.backend,
          "visited",
          ["uid", "visited_uid", "ts"],
          ["uid", "visited_uid"],
        ),
      )
      .run(uid, visitedUid, now());
  }

  /**
   * 获取访问记录（按时间倒序）
   * @param uid - 账号 uid
   */
  async getVisited(uid: string): Promise<string[]> {
    const rows = await this._db
      .prepare("SELECT visited_uid FROM visited WHERE uid = ? ORDER BY ts DESC")
      .all<{ visited_uid: string }>(uid);
    return rows.map((r) => r.visited_uid);
  }

  /**
   * 获取星标好友 id 列表（按建立时间升序，与好友列表同序）
   * @param uid - 账号 uid
   */
  async getStarList(uid: string): Promise<string[]> {
    const rows = await this._db
      .prepare(
        "SELECT friend_uid FROM friends WHERE uid = ? AND star = 1 ORDER BY create_ts ASC",
      )
      .all<{ friend_uid: string }>(uid);
    return rows.map((r) => r.friend_uid);
  }

  /**
   * 覆盖式设置星标好友列表（事务：先全部清零再置位，保证与入参一致）
   *
   * 入参应已由调用方完成「仅好友 + 上限截断」校验；此处只落库。
   * @param uid - 账号 uid
   * @param friendUids - 星标好友 id 列表（最终结果）
   */
  async setStarList(uid: string, friendUids: string[]): Promise<void> {
    await this._db.transaction(async (tx) => {
      await tx.prepare("UPDATE friends SET star = 0 WHERE uid = ?").run(uid);
      const stmt = tx.prepare(
        "UPDATE friends SET star = 1 WHERE uid = ? AND friend_uid = ?",
      );
      for (const fid of friendUids) await stmt.run(uid, fid);
    });
  }

  /**
   * 读取某对账号的最近一次好友申请时间（0 = 无记录）
   *
   * 用于 gamedata_const.requestSameFriendCd（实测 14400s = 4h）冷却判定——
   * 记录在申请被处理/撤回后**不删除**。
   * @param fromUid - 申请方 uid
   * @param toUid - 收方 uid
   */
  async getLastRequestTs(fromUid: string, toUid: string): Promise<number> {
    const row = await this._db
      .prepare(
        "SELECT last_ts FROM friend_request_log WHERE from_uid = ? AND to_uid = ?",
      )
      .get<{ last_ts?: unknown }>(fromUid, toUid);
    return toCount(row?.last_ts ?? 0);
  }

  /**
   * 记录一次好友申请时间（冷却基准；与 friend_requests 行解耦）
   * @param fromUid - 申请方 uid
   * @param toUid - 收方 uid
   */
  async touchRequestLog(fromUid: string, toUid: string): Promise<void> {
    await this._db
      .prepare(
        insertReplaceSql(
          this._db.backend,
          "friend_request_log",
          ["from_uid", "to_uid", "last_ts"],
          ["from_uid", "to_uid"],
        ),
      )
      .run(fromUid, toUid, now());
  }

  /**
   * 删除账号的社交数据（B-2：好友双向关系 + 申请 + 访问记录 + 冷却基准）
   * @param uid - 账号 uid
   */
  async deleteUser(uid: string): Promise<void> {
    await this._db
      .prepare("DELETE FROM friends WHERE uid = ? OR friend_uid = ?")
      .run(uid, uid);
    await this._db
      .prepare("DELETE FROM friend_requests WHERE from_uid = ? OR to_uid = ?")
      .run(uid, uid);
    await this._db
      .prepare("DELETE FROM visited WHERE uid = ? OR visited_uid = ?")
      .run(uid, uid);
    await this._db
      .prepare(
        "DELETE FROM friend_request_log WHERE from_uid = ? OR to_uid = ?",
      )
      .run(uid, uid);
  }
}
