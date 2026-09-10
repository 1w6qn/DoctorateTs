import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { openDatabase, SCHEMA_SQL, closeDatabase } from "@core/db/database";
import type { SqlDatabase } from "@core/db/types";
import { FriendRepository } from "@core/db/friend-repo";

describe("数据库基础设施（SQLite 后端）", () => {
  afterEach(async () => {
    await closeDatabase();
  });

  it("内存库应能建表成功", async () => {
    const db = await openDatabase(":memory:");
    await db.exec(SCHEMA_SQL);
    const tables = (
      await db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .all<{ name: string }>()
    ).map((r) => r.name);
    expect(tables).toContain("friends");
    expect(tables).toContain("friend_requests");
    expect(tables).toContain("visited");
  });

  it("重复执行建表 SQL 应幂等", async () => {
    const db = await openDatabase(":memory:");
    await db.exec(SCHEMA_SQL);
    await expect(db.exec(SCHEMA_SQL)).resolves.toBeUndefined();
  });

  it("close() 后 openDatabase() 应重建连接（不复用已关闭连接）", async () => {
    const first = await openDatabase(":memory:");
    await first.close();
    expect(first.isOpen()).toBe(false);
    const second = await openDatabase(":memory:");
    // 用布尔比较而非 toBe(first)：断言失败时 vitest 会序列化对象，
    // 而已关闭的 DatabaseSync 在序列化过程中会抛错，掩盖真实失败原因
    expect(second === first).toBe(false);
    expect(second.isOpen()).toBe(true);
  });
});

describe("FriendRepository", () => {
  let repo: FriendRepository;
  let db: SqlDatabase;

  beforeEach(async () => {
    db = await openDatabase(":memory:");
    await db.exec(SCHEMA_SQL);
    repo = new FriendRepository(db);
  });

  afterEach(async () => {
    await closeDatabase();
  });

  it("addFriend 后 getFriendList 应返回好友", async () => {
    await repo.addFriend("1", "2", "阿米娅");
    expect(await repo.getFriendList("1")).toEqual([{ uid: "2", alias: "阿米娅" }]);
  });

  it("deleteFriend 应删除好友关系", async () => {
    await repo.addFriend("1", "2", "");
    await repo.deleteFriend("1", "2");
    expect(await repo.getFriendList("1")).toEqual([]);
  });

  it("setFriendAlias 应更新备注", async () => {
    await repo.addFriend("1", "2", "");
    await repo.setFriendAlias("1", "2", "新备注");
    expect((await repo.getFriendList("1"))[0].alias).toBe("新备注");
  });

  it("sendFriendRequest 后 getFriendRequests 应返回申请者", async () => {
    await repo.sendFriendRequest("2", "1");
    expect(await repo.getFriendRequests("1")).toEqual(["2"]);
  });

  it("deleteFriendRequest 应删除申请", async () => {
    await repo.sendFriendRequest("2", "1");
    await repo.deleteFriendRequest("1", "2");
    expect(await repo.getFriendRequests("1")).toEqual([]);
  });

  it("hasFriend / hasFriendRequest 应正确判断", async () => {
    await repo.addFriend("1", "2", "");
    await repo.sendFriendRequest("3", "1");
    expect(await repo.hasFriend("1", "2")).toBe(true);
    expect(await repo.hasFriend("1", "3")).toBe(false);
    expect(await repo.hasFriendRequest("1", "3")).toBe(true);
    expect(await repo.hasFriendRequest("1", "2")).toBe(false);
  });

  it("addVisit 后 getVisited 应返回访问记录", async () => {
    await repo.addVisit("1", "2");
    expect(await repo.getVisited("1")).toEqual(["2"]);
  });

  // Round 48（审计 §5.4-10 前半）：星标好友落库 + 申请冷却日志
  it("setStarList / getStarList：覆盖式设置星标好友（先清零再置位）", async () => {
    await repo.addFriend("1", "2", "");
    await repo.addFriend("1", "3", "");
    await repo.addFriend("1", "4", "");
    await repo.setStarList("1", ["2", "4"]);
    expect(await repo.getStarList("1")).toEqual(["2", "4"]);
    // 覆盖式：再次设置只保留新列表
    await repo.setStarList("1", ["3"]);
    expect(await repo.getStarList("1")).toEqual(["3"]);
    // 不影响他人
    expect(await repo.getStarList("2")).toEqual([]);
  });

  it("setStarList 传入非好友 id 时不影响既有星标（仅好友有行可更新）", async () => {
    await repo.addFriend("1", "2", "");
    await repo.setStarList("1", ["2"]);
    await repo.setStarList("1", ["99"]); // 99 非好友
    expect(await repo.getStarList("1")).toEqual([]);
  });

  it("setStarList 事务：抛错时回滚（星标不被半途清零）", async () => {
    await repo.addFriend("1", "2", "");
    await repo.addFriend("1", "3", "");
    await repo.setStarList("1", ["2", "3"]);
    // 注入失败：第二条 UPDATE 抛错 → 整个事务回滚，原星标保持不变
    const original = db.prepare.bind(db);
    let calls = 0;
    db.prepare = ((sql: string) => {
      calls++;
      if (calls === 2) throw new Error("boom"); // 第 2 条 = 「置位」语句，此时 star 已被清零
      return original(sql);
    }) as typeof db.prepare;
    await expect(repo.setStarList("1", ["2"])).rejects.toThrow("boom");
    db.prepare = original as typeof db.prepare;
    expect(await repo.getStarList("1")).toEqual(["2", "3"]);
  });

  it("getLastRequestTs / touchRequestLog：冷却基准与 friend_requests 行解耦（删除申请后仍保留）", async () => {
    await repo.sendFriendRequest("2", "1");
    await repo.touchRequestLog("2", "1");
    const ts = await repo.getLastRequestTs("2", "1");
    expect(ts).toBeGreaterThan(0);
    await repo.deleteFriendRequest("1", "2"); // 申请被处理/撤回
    expect(await repo.getLastRequestTs("2", "1")).toBe(ts); // 冷却记录仍在
  });

  it("deleteUser 应清理账号社交数据（B-2：双向好友/申请/访问）", async () => {
    await repo.addFriend("1", "2", "");
    await repo.addFriend("2", "1", ""); // 反向关系
    await repo.sendFriendRequest("3", "1");
    await repo.addVisit("1", "5");
    await repo.touchRequestLog("3", "1");
    await repo.deleteUser("1");
    expect(await repo.getFriendList("1")).toEqual([]);
    expect(await repo.getFriendList("2")).toEqual([]); // 反向关系一并删除
    expect(await repo.getFriendRequests("1")).toEqual([]);
    expect(await repo.getVisited("1")).toEqual([]);
    expect(await repo.getLastRequestTs("3", "1")).toBe(0); // 冷却记录一并清理
  });
});
