import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import { openAssetDb, ASSET_DB_FILENAME, ASSET_SCHEMA_SQL } from "../../../app/asset-registry/asset-db";

const TEST_ROOT = path.join(os.tmpdir(), "asset-db-test");

function dbPath(): string {
  return path.join(TEST_ROOT, ASSET_DB_FILENAME);
}

beforeEach(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
  fs.mkdirSync(TEST_ROOT, { recursive: true });
});

afterEach(() => {
  fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

describe("asset-db（资产索引数据库）", () => {
  it("openAssetDb 建表 assets + asset_events，幂等可重复打开", () => {
    const db = openAssetDb(dbPath());
    const tables = db
      .prepare(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
      .all() as { name: string }[];
    const names = tables.map((t) => t.name);
    expect(names).toContain("assets");
    expect(names).toContain("asset_events");
    db.close();

    // 重复打开不报错（幂等）
    const db2 = openAssetDb(dbPath());
    db2.close();
  });

  it("带 user_version = 1 供未来 schema 迁移判断", () => {
    const db = openAssetDb(dbPath());
    const row = db.prepare("PRAGMA user_version").get() as { user_version: number };
    expect(Number(row.user_version)).toBe(1);
    db.close();
  });

  it("schema SQL 含 assets 幂等键（key UNIQUE）与事件外键索引", () => {
    expect(ASSET_SCHEMA_SQL).toContain("TEXT NOT NULL UNIQUE");
    expect(ASSET_SCHEMA_SQL).toContain("CREATE INDEX IF NOT EXISTS idx_ev_asset_id");
  });

  it("写入/读取资产与事件行（CRUD 冒烟）", () => {
    const db = openAssetDb(dbPath());
    db.prepare(
      `INSERT INTO assets (key, name, category, source, version, hash, size, first_seen_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run("a#file#v1", "a.dat", "file", "cdn", "v1", "abc", 10, 1, 1);
    db.prepare(
      `INSERT INTO asset_events (eid, asset_id, ts, action, actor, source, hash_before, hash_after)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run("E-1", 1, 1, "acquire", "router", "cdn", null, "abc");

    const asset = db.prepare("SELECT name, category FROM assets WHERE id = 1").get() as { name: string; category: string } | undefined;
    expect(asset?.name).toBe("a.dat");
    expect(asset?.category).toBe("file");

    const ev = db.prepare("SELECT action, actor FROM asset_events WHERE id = 1").get() as { action: string; actor: string } | undefined;
    expect(ev?.action).toBe("acquire");
    expect(ev?.actor).toBe("router");
    db.close();
  });
});