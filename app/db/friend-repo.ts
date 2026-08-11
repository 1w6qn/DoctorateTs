/**
 * 好友关系仓储
 *
 * 封装 friends / friend_requests / visited 三张表的 CRUD。
 * 方法语义与 AccountManager 原社交方法一致，便于平滑替换。
 */
import { DatabaseSync } from "node:sqlite";

/** 当前时间戳（秒） */
function nowTs(): number {
  return Math.floor(Date.now() / 1000);
}

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
      .run(uid, friendUid, alias, nowTs());
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
      .run(fromUid, toUid, nowTs());
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
      .run(uid, visitedUid, nowTs());
  }

  /** 获取访问记录 */
  getVisited(uid: string): string[] {
    const rows = this.db
      .prepare("SELECT visited_uid FROM visited WHERE uid = ? ORDER BY ts DESC")
      .all(uid) as { visited_uid: string }[];
    return rows.map((r) => r.visited_uid);
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
  }
}
