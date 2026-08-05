import { describe, it, expect } from "vitest";
import { openDatabase, SCHEMA_SQL } from "../../../app/db/database";

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
