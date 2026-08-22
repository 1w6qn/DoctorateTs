/**
 * 资产注册表索引数据库（SQLite）
 *
 * 一体化可溯源资产系统的元数据索引（Node 24 内置 node:sqlite，零第三方依赖）。
 * 数据库只存元数据（资产注册 + 生命周期审计事件），不存文件本体——
 * 资产内容/文件仍由各来源（app/asset.ts、scripts/*、mods/）负责，本库仅作溯源与审计。
 *
 * 默认位置：tmp/asset/index.db（gitignored；测试经 assetRegistry.configure 注入临时目录）。
 */
import { DatabaseSync } from "node:sqlite";

/** 索引数据库文件名（存储根目录下） */
export const ASSET_DB_FILENAME = "index.db";

/**
 * 建表 SQL（幂等；user_version 供未来 schema 迁移判断）
 *
 * assets：每行一个已注册资产，key = name#category#version 唯一（幂等 upsert 依据）。
 * asset_events：审计事件链，外键关联 assets.id；eid 唯一（E-{ts}-{seq}）。
 */
export const ASSET_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS assets (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  key           TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  category      TEXT NOT NULL,
  source        TEXT,
  version       TEXT,
  hash          TEXT,
  size          INTEGER,
  first_seen_at INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  extra         TEXT
);

CREATE TABLE IF NOT EXISTS asset_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  eid         TEXT NOT NULL UNIQUE,
  asset_id    INTEGER NOT NULL,
  ts          INTEGER NOT NULL,
  action      TEXT NOT NULL,
  actor       TEXT,
  source      TEXT,
  version     TEXT,
  hash_before TEXT,
  hash_after  TEXT,
  size_before INTEGER,
  size_after  INTEGER,
  detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_asset_key       ON assets(key);
CREATE INDEX IF NOT EXISTS idx_asset_category  ON assets(category);
CREATE INDEX IF NOT EXISTS idx_ev_asset_id     ON asset_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_ev_ts           ON asset_events(ts);
CREATE INDEX IF NOT EXISTS idx_ev_action       ON asset_events(action);

PRAGMA user_version = 1;
`;

/**
 * 打开资产注册表数据库（建目录由调用方负责）
 *
 * @param dbPath - 数据库文件路径（测试可传临时目录下的路径）
 * @returns 已建表的 DatabaseSync 连接
 */
export function openAssetDb(dbPath: string): DatabaseSync {
  const db = new DatabaseSync(dbPath);
  // WAL：高频会话写入时不阻塞读（内存库自动回退 memory 模式）
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(ASSET_SCHEMA_SQL);
  return db;
}