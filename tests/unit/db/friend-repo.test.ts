import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { openDatabase, SCHEMA_SQL } from "@core/db/database";
import { FriendRepository } from "@core/db/friend-repo";
import { DatabaseSync } from "node:sqlite";

describe("SQLite 数据库基础设施", () => {
  it("内存库应能建表成功", () => {
    const db = openDatabase(":memory:");
    db.exec(SCHEMA_SQL);
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all()
      .map((r: any) => r.name);
    expect(tables).toContain("friends");
    expect(tables).toContain("friend_requests");
    expect(tables).toContain("visited");
    db.close();
  });

  it("重复执行建表 SQL 应幂等", () => {
    const db = openDatabase(":memory:");
    db.exec(SCHEMA_SQL);
    expect(() => db.exec(SCHEMA_SQL)).not.toThrow();
    db.close();
  });
});

describe("FriendRepository", () => {
  let repo: FriendRepository;
  let db: DatabaseSync;

  beforeEach(() => {
    db = openDatabase(":memory:");
    db.exec(SCHEMA_SQL);
    repo = new FriendRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  it("addFriend 后 getFriendList 应返回好友", () => {
    repo.addFriend("1", "2", "阿米娅");
    const list = repo.getFriendList("1");
    expect(list).toEqual([{ uid: "2", alias: "阿米娅" }]);
  });

  it("deleteFriend 应删除好友关系", () => {
    repo.addFriend("1", "2", "");
    repo.deleteFriend("1", "2");
    expect(repo.getFriendList("1")).toEqual([]);
  });

  it("setFriendAlias 应更新备注", () => {
    repo.addFriend("1", "2", "");
    repo.setFriendAlias("1", "2", "新备注");
    expect(repo.getFriendList("1")[0].alias).toBe("新备注");
  });

  it("sendFriendRequest 后 getFriendRequests 应返回申请者", () => {
    repo.sendFriendRequest("2", "1");
    expect(repo.getFriendRequests("1")).toEqual(["2"]);
  });

  it("deleteFriendRequest 应删除申请", () => {
    repo.sendFriendRequest("2", "1");
    repo.deleteFriendRequest("1", "2");
    expect(repo.getFriendRequests("1")).toEqual([]);
  });

  it("hasFriend / hasFriendRequest 应正确判断", () => {
    repo.addFriend("1", "2", "");
    repo.sendFriendRequest("3", "1");
    expect(repo.hasFriend("1", "2")).toBe(true);
    expect(repo.hasFriend("1", "3")).toBe(false);
    expect(repo.hasFriendRequest("1", "3")).toBe(true);
    expect(repo.hasFriendRequest("1", "2")).toBe(false);
  });

  it("addVisit 后 getVisited 应返回访问记录", () => {
    repo.addVisit("1", "2");
    expect(repo.getVisited("1")).toEqual(["2"]);
  });

  // Round 48（审计 §5.4-10 前半）：星标好友落库 + 申请冷却日志
  it("setStarList / getStarList：覆盖式设置星标好友（先清零再置位）", () => {
    repo.addFriend("1", "2", "");
    repo.addFriend("1", "3", "");
    repo.addFriend("1", "4", "");
    repo.setStarList("1", ["2", "4"]);
    expect(repo.getStarList("1")).toEqual(["2", "4"]);
    // 覆盖式：再次设置只保留新列表
    repo.setStarList("1", ["3"]);
    expect(repo.getStarList("1")).toEqual(["3"]);
    // 不影响他人
    expect(repo.getStarList("2")).toEqual([]);
  });

  it("setStarList 传入非好友 id 时不影响既有星标（仅好友有行可更新）", () => {
    repo.addFriend("1", "2", "");
    repo.setStarList("1", ["2"]);
    repo.setStarList("1", ["99"]); // 99 非好友
    expect(repo.getStarList("1")).toEqual([]);
  });

  it("getLastRequestTs / touchRequestLog：冷却基准与 friend_requests 行解耦（删除申请后仍保留）", () => {
    repo.sendFriendRequest("2", "1");
    repo.touchRequestLog("2", "1");
    const ts = repo.getLastRequestTs("2", "1");
    expect(ts).toBeGreaterThan(0);
    repo.deleteFriendRequest("1", "2"); // 申请被处理/撤回
    expect(repo.getLastRequestTs("2", "1")).toBe(ts); // 冷却记录仍在
  });

  it("deleteUser 应清理账号社交数据（B-2：双向好友/申请/访问）", () => {
    repo.addFriend("1", "2", "");
    repo.addFriend("2", "1", ""); // 反向关系
    repo.sendFriendRequest("3", "1");
    repo.addVisit("1", "5");
    repo.touchRequestLog("3", "1");
    repo.deleteUser("1");
    expect(repo.getFriendList("1")).toEqual([]);
    expect(repo.getFriendList("2")).toEqual([]); // 反向关系一并删除
    expect(repo.getFriendRequests("1")).toEqual([]);
    expect(repo.getVisited("1")).toEqual([]);
    expect(repo.getLastRequestTs("3", "1")).toBe(0); // 冷却记录一并清理
  });
});
