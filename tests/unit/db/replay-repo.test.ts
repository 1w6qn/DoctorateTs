import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { openDatabase, SCHEMA_SQL } from "../../../app/db/database";
import { ReplayRepository } from "../../../app/db/replay-repo";

describe("ReplayRepository 战斗回放独立存储（R4）", () => {
  let repo: ReplayRepository;
  let db: DatabaseSync;

  beforeEach(() => {
    db = openDatabase(":memory:");
    db.exec(SCHEMA_SQL);
    repo = new ReplayRepository(db);
  });

  afterEach(() => {
    db.close();
  });

  it("upsert/get 回放往返（按 uid+stageId 独立存储）", () => {
    expect(repo.get("1", "st_01")).toBe("");
    repo.upsert("1", "st_01", "BASE64==");
    expect(repo.get("1", "st_01")).toBe("BASE64==");
    // 覆盖写
    repo.upsert("1", "st_01", "UPDATED");
    expect(repo.get("1", "st_01")).toBe("UPDATED");
    // 不同 uid / 不同关卡互不干扰
    expect(repo.get("1", "st_02")).toBe("");
    expect(repo.get("2", "st_01")).toBe("");
  });
});
