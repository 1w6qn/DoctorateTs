/**
 * 好友关系仓储
 *
 * 封装 friends / friend_requests / visited 三张表的 CRUD。
 * 方法语义与 AccountManager 原社交方法一致，便于平滑替换。
 */
import { DatabaseSync } from "node:sqlite";
import { now } from "@utils/time";

export class FriendRepository {
  constructor(private db: DatabaseSync) {}

  /** 获取用户好友列表（按创建时间升序） */
  getFriendList(uid: string): { uid: string; alias: string }[] {
    const rows = this.db
      .prepare(
        "SELECT friend_uid AS uid, alias FROM friends WHERE uid = ? ORDER BY create_ts ASC",
      )
      .all(uid) as { uid: string; alias: string }[];
    return rows;
  }

  /** 判断是否已是好友 */
  hasFriend(uid: string, friendUid: string): boolean {
    const row = this.db
      .prepare("SELECT 1 FROM friends WHERE uid = ? AND friend_uid = ?")
      .get(uid, friendUid);
    return !!row;
  }

  /** 添加好友（单向，调用方决定是否双向） */
  addFriend(uid: string, friendUid: string, alias = ""): void {
    this.db
      .prepare(
        "INSERT OR IGNORE INTO friends (uid, friend_uid, alias, create_ts) VALUES (?, ?, ?, ?)",
      )
      .run(uid, friendUid, alias, now());
  }

  /** 删除好友 */
  deleteFriend(uid: string, friendUid: string): void {
    this.db
      .prepare("DELETE FROM friends WHERE uid = ? AND friend_uid = ?")
      .run(uid, friendUid);
  }

  /** 设置好友备注 */
  setFriendAlias(uid: string, friendUid: string, alias: string): void {
    this.db
      .prepare("UPDATE friends SET alias = ? WHERE uid = ? AND friend_uid = ?")
      .run(alias, uid, friendUid);
  }

  /** 获取用户收到的申请列表（from_uid 数组） */
  getFriendRequests(uid: string): string[] {
    const rows = this.db
      .prepare(
        "SELECT from_uid FROM friend_requests WHERE to_uid = ? ORDER BY create_ts ASC",
      )
      .all(uid) as { from_uid: string }[];
    return rows.map((r) => r.from_uid);
  }

  /** 判断是否存在未处理申请 */
  hasFriendRequest(uid: string, fromUid: string): boolean {
    const row = this.db
      .prepare("SELECT 1 FROM friend_requests WHERE to_uid = ? AND from_uid = ?")
      .get(uid, fromUid);
    return !!row;
  }

  /** 发送申请（from -> to） */
  sendFriendRequest(fromUid: string, toUid: string): void {
    this.db
      .prepare(
        "INSERT OR IGNORE INTO friend_requests (from_uid, to_uid, create_ts) VALUES (?, ?, ?)",
      )
      .run(fromUid, toUid, now());
  }

  /** 删除申请（删除 to 收到的来自 from 的申请） */
  deleteFriendRequest(uid: string, fromUid: string): void {
    this.db
      .prepare("DELETE FROM friend_requests WHERE to_uid = ? AND from_uid = ?")
      .run(uid, fromUid);
  }

  /** 记录访问 */
  addVisit(uid: string, visitedUid: string): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO visited (uid, visited_uid, ts) VALUES (?, ?, ?)",
      )
      .run(uid, visitedUid, now());
  }

  /** 获取访问记录 */
  getVisited(uid: string): string[] {
    const rows = this.db
      .prepare("SELECT visited_uid FROM visited WHERE uid = ? ORDER BY ts DESC")
      .all(uid) as { visited_uid: string }[];
    return rows.map((r) => r.visited_uid);
  }

  /**
   * 获取星标好友 id 列表（按建立时间升序，与好友列表同序）
   * @param uid - 账号 uid
   */
  getStarList(uid: string): string[] {
    const rows = this.db
      .prepare(
        "SELECT friend_uid FROM friends WHERE uid = ? AND star = 1 ORDER BY create_ts ASC",
      )
      .all(uid) as { friend_uid: string }[];
    return rows.map((r) => r.friend_uid);
  }

  /**
   * 覆盖式设置星标好友列表（事务：先全部清零再置位，保证与入参一致）
   *
   * 入参应已由调用方完成「仅好友 + 上限截断」校验；此处只落库。
   * @param uid - 账号 uid
   * @param friendUids - 星标好友 id 列表（最终结果）
   */
  setStarList(uid: string, friendUids: string[]): void {
    this.db.exec("BEGIN");
    try {
      this.db
        .prepare("UPDATE friends SET star = 0 WHERE uid = ?")
        .run(uid);
      const stmt = this.db.prepare(
        "UPDATE friends SET star = 1 WHERE uid = ? AND friend_uid = ?",
      );
      for (const fid of friendUids) stmt.run(uid, fid);
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  /**
   * 读取某对账号的最近一次好友申请时间（0 = 无记录）
   *
   * 用于 gamedata_const.requestSameFriendCd（实测 14400s = 4h）冷却判定——
   * 记录在申请被处理/撤回后**不删除**。
   */
  getLastRequestTs(fromUid: string, toUid: string): number {
    const row = this.db
      .prepare(
        "SELECT last_ts FROM friend_request_log WHERE from_uid = ? AND to_uid = ?",
      )
      .get(fromUid, toUid) as { last_ts?: number } | undefined;
    return Number(row?.last_ts ?? 0);
  }

  /** 记录一次好友申请时间（冷却基准；与 friend_requests 行解耦） */
  touchRequestLog(fromUid: string, toUid: string): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO friend_request_log (from_uid, to_uid, last_ts) VALUES (?, ?, ?)",
      )
      .run(fromUid, toUid, now());
  }

  /** 删除账号的社交数据（B-2：好友双向关系 + 申请 + 访问记录） */
  deleteUser(uid: string): void {
    this.db
      .prepare("DELETE FROM friends WHERE uid = ? OR friend_uid = ?")
      .run(uid, uid);
    this.db
      .prepare("DELETE FROM friend_requests WHERE from_uid = ? OR to_uid = ?")
      .run(uid, uid);
    this.db
      .prepare("DELETE FROM visited WHERE uid = ? OR visited_uid = ?")
      .run(uid, uid);
    this.db
      .prepare(
        "DELETE FROM friend_request_log WHERE from_uid = ? OR to_uid = ?",
      )
      .run(uid, uid);
  }
}
