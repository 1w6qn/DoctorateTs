import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { openDatabase, SCHEMA_SQL, closeDatabase } from "@core/db/database";
import type { SqlDatabase } from "@core/db/types";
import { PlayerDataRepository } from "@core/db/player-data-repo";

/**
 * 玩家存档仓储（gzip 二进制文档）
 *
 * 覆盖二进制列的往返：SQLite BLOB → MySQL LONGBLOB / PostgreSQL BYTEA 走同一
 * `Uint8Array`/`Buffer` 契约，故此处的往返测试对三种后端同等有效。
 */
describe("PlayerDataRepository", () => {
  let repo: PlayerDataRepository;
  let db: SqlDatabase;

  beforeEach(async () => {
    db = await openDatabase(":memory:");
    await db.exec(SCHEMA_SQL);
    repo = new PlayerDataRepository(db);
  });

  afterEach(async () => {
    await closeDatabase();
  });

  it("upsert/get 应无损往返存档 JSON（含中文与大对象）", async () => {
    const data = {
      status: { uid: "1", nickName: "博士", level: 120 },
      troop: { chars: Object.fromEntries(Array.from({ length: 300 }, (_, i) => [`char_${i}`, { level: 90, elite: 2 }])) },
      note: "x".repeat(50_000),
    };
    await repo.upsert("1", JSON.stringify(data));
    const raw = await repo.get("1");
    expect(raw).not.toBeNull();
    expect(JSON.parse(raw!)).toEqual(data);
  });

  it("存档以 gzip 二进制落库（体积显著小于原文）", async () => {
    const json = JSON.stringify({ note: "重复内容".repeat(5000) });
    await repo.upsert("1", json);
    const row = await db
      .prepare("SELECT data FROM player_data WHERE uid = ?")
      .get<{ data: Uint8Array }>("1");
    expect(row?.data).toBeInstanceOf(Uint8Array);
    expect(json.length).toBeGreaterThan(row!.data.length * 4); // gzip 后远小于原文
  });

  it("覆盖写（同 uid 二次 upsert 只保留最新）", async () => {
    await repo.upsert("1", JSON.stringify({ v: 1 }));
    await repo.upsert("1", JSON.stringify({ v: 2 }));
    expect(JSON.parse((await repo.get("1"))!)).toEqual({ v: 2 });
    await expect(repo.exists("1")).resolves.toBe(true);
    expect(
      Number((await db.prepare("SELECT COUNT(*) AS n FROM player_data").get<{ n: unknown }>())?.n),
    ).toBe(1);
  });

  it("get 不存在的 uid 返回 null；exists 返回 false", async () => {
    await expect(repo.get("999")).resolves.toBeNull();
    await expect(repo.exists("999")).resolves.toBe(false);
  });

  it("delete 应删除存档行", async () => {
    await repo.upsert("1", JSON.stringify({ v: 1 }));
    await repo.delete("1");
    await expect(repo.get("1")).resolves.toBeNull();
  });

  it("数据损坏（非 gzip）时 get 返回 null 而非抛错", async () => {
    await db
      .prepare("INSERT INTO player_data (uid, data, updated_ts) VALUES (?, ?, ?)")
      .run("1", Buffer.from("not-gzip-at-all"), Date.now());
    await expect(repo.get("1")).resolves.toBeNull();
  });
});
