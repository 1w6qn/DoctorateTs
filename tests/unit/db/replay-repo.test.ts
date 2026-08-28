import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { openDatabase, SCHEMA_SQL } from "@core/db/database";
import { ReplayRepository } from "@core/db/replay-repo";

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

  it("upsertInfo/getInfo 结算信息往返（A3——独立于用户配置）", () => {
    expect(repo.getInfo("1", "battle_001")).toBeUndefined();
    const info = { stageId: "st_01", isPractice: 0, squad: { slots: [] } };
    repo.upsertInfo("1", "battle_001", info);
    expect(repo.getInfo("1", "battle_001")).toEqual(info);
    // 覆盖写 + uid/battleId 隔离
    repo.upsertInfo("1", "battle_001", { stageId: "st_02", isPractice: 1 });
    expect(repo.getInfo("1", "battle_001")).toEqual({ stageId: "st_02", isPractice: 1 });
    expect(repo.getInfo("2", "battle_001")).toBeUndefined();
  });

  it("deleteUser 应清理账号战斗数据（B-2：回放 + 结算信息）", () => {
    repo.upsert("1", "st_01", "R1");
    repo.upsert("2", "st_01", "R2");
    repo.upsertInfo("1", "b_1", { stageId: "st_01", isPractice: 0 });
    repo.deleteUser("1");
    expect(repo.get("1", "st_01")).toBe("");
    expect(repo.get("2", "st_01")).toBe("R2"); // 其他账号不受影响
    expect(repo.getInfo("1", "b_1")).toBeUndefined();
  });
});
