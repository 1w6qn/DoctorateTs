import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { openDatabase, SCHEMA_SQL, closeDatabase } from "@core/db/database";
import type { SqlDatabase } from "@core/db/types";
import { ReplayRepository } from "@core/db/replay-repo";
import type { BattleRecord } from "@game/kernel/battle-info-store";
import { asModel } from "../../helpers";

describe("ReplayRepository 战斗回放独立存储（R4）", () => {
  let repo: ReplayRepository;
  let db: SqlDatabase;

  beforeEach(async () => {
    db = await openDatabase(":memory:");
    await db.exec(SCHEMA_SQL);
    repo = new ReplayRepository(db);
  });

  afterEach(async () => {
    await closeDatabase();
  });

  it("upsert/get 回放往返（按 uid+stageId 独立存储）", async () => {
    await expect(repo.get("1", "st_01")).resolves.toBe("");
    await repo.upsert("1", "st_01", "BASE64==");
    await expect(repo.get("1", "st_01")).resolves.toBe("BASE64==");
    // 覆盖写
    await repo.upsert("1", "st_01", "UPDATED");
    await expect(repo.get("1", "st_01")).resolves.toBe("UPDATED");
    // 不同 uid / 不同关卡互不干扰
    await expect(repo.get("1", "st_02")).resolves.toBe("");
    await expect(repo.get("2", "st_01")).resolves.toBe("");
  });

  it("upsertInfo/getInfo 结算信息往返（A3——独立于用户配置）", async () => {
    await expect(repo.getInfo("1", "battle_001")).resolves.toBeUndefined();
    const info = { stageId: "st_01", isPractice: 0, squad: { slots: [] } };
    await repo.upsertInfo("1", "battle_001", info);
    await expect(repo.getInfo("1", "battle_001")).resolves.toEqual(info);
    // 覆盖写 + uid/battleId 隔离
    await repo.upsertInfo("1", "battle_001", { stageId: "st_02", isPractice: 1 });
    await expect(repo.getInfo("1", "battle_001")).resolves.toEqual({
      stageId: "st_02",
      isPractice: 1,
    });
    await expect(repo.getInfo("2", "battle_001")).resolves.toBeUndefined();
  });

  it("saveRecord / listRecords 结束记录往返（按创建时间倒序）", async () => {
    await repo.saveRecord(asModel<BattleRecord>({
      battleId: "b1",
      uid: "1",
      stageId: "st_01",
      createdTs: 1000,
    }));
    await repo.saveRecord(asModel<BattleRecord>({
      battleId: "b2",
      uid: "1",
      stageId: "st_02",
      createdTs: 2000,
    }));
    const list = await repo.listRecords("1");
    expect(list.map((r) => r.battleId)).toEqual(["b2", "b1"]);
    await expect(repo.getRecord("1", "b1")).resolves.toMatchObject({ stageId: "st_01" });
  });

  it("deleteUser 应清理账号战斗数据（B-2：回放 + 结算信息）", async () => {
    await repo.upsert("1", "st_01", "R1");
    await repo.upsert("2", "st_01", "R2");
    await repo.upsertInfo("1", "b_1", { stageId: "st_01", isPractice: 0 });
    await repo.deleteUser("1");
    await expect(repo.get("1", "st_01")).resolves.toBe("");
    await expect(repo.get("2", "st_01")).resolves.toBe("R2"); // 其他账号不受影响
    await expect(repo.getInfo("1", "b_1")).resolves.toBeUndefined();
  });
});
