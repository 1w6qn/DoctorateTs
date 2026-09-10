/**
 * 数据库连接管理（多后端）
 *
 * 主数据层支持三种后端，配置见 `app/core/db/config.ts`：
 * - `sqlite`（缺省）：Node 24 内置 `node:sqlite`，零第三方依赖，单文件本地库；
 * - `mysql` / `postgresql`：可选后端，驱动（mysql2 / pg）运行时按需动态加载。
 *
 * 本模块是全局单例入口：`openDatabase()` 建连 + 建表（幂等）+ 结构迁移，
 * `getDatabase()` 取连接，`closeDatabase()` 释放。
 *
 * 建表 DDL 由 {@link buildSchemaSql} 按后端生成——仓储层的 SQL 只写 `?` 占位符与
 * 公共语法，方言差异收敛在 `dialect.ts` 与 `schema.ts`。
 */
import { logger } from "@utils/logger";
import {
  DEFAULT_SQLITE_FILE,
  describeDatabase,
  resolveDatabaseOptions,
} from "./config";
import { MysqlDatabase } from "./drivers/mysql";
import { PostgresDatabase } from "./drivers/postgres";
import { SqliteDatabase } from "./drivers/sqlite";
import { addColumnIfMissing } from "./introspect";
import { buildSchemaSql, physicalType } from "./schema";
import type { DatabaseOptions, SqlDatabase } from "./types";

/** 重导出建表 SQL（SQLite 方言；供初始化/测试直接执行） */
export { SCHEMA_SQL } from "./schema";
/** 重导出默认库文件路径（历史常量名，等价于 {@link DEFAULT_SQLITE_FILE}） */
export { DEFAULT_SQLITE_FILE as DEFAULT_DB_PATH, DEFAULT_SQLITE_FILE } from "./config";
/** 重导出多后端契约类型，调用点无需深入子模块 */
export type {
  DatabaseBackend,
  DatabaseOptions,
  NetworkDatabaseOptions,
  SqliteDatabaseOptions,
  SqlDatabase,
  SqlParam,
  SqlRunResult,
  SqlStatement,
} from "./types";

/** 全局单例连接 */
let _db: SqlDatabase | null = null;
/** 进行中的建连（并发调用收敛到同一次建连，避免重复建池） */
let _opening: Promise<SqlDatabase> | null = null;

/**
 * 打开（或复用）数据库连接，确保表结构与增量迁移完成
 *
 * 调用形式：
 * - `openDatabase()`——按配置解析（缺省 sqlite ./data/user/social.db）
 * - `openDatabase(":memory:")`——测试用内存 SQLite（保持历史签名兼容）
 * - `openDatabase({ backend: "mysql", host: ... })`——显式指定后端
 *
 * 已建连时直接复用（`closeDatabase()` 会清空单例，故不存在复用已关闭连接的问题）。
 * @param options - 数据库文件路径字符串，或完整后端配置；缺省按配置解析
 * @returns 已就绪的数据库句柄
 */
export async function openDatabase(
  options?: string | DatabaseOptions,
): Promise<SqlDatabase> {
  if (_db && _db.isOpen()) return _db;
  _db = null; // 已关闭的连接不参与复用（调用方直接 close() 的场景）
  if (_opening) return _opening;
  const opening = openDatabaseInternal(options);
  _opening = opening;
  try {
    _db = await opening;
    return _db;
  } finally {
    _opening = null;
  }
}

/**
 * 建连 + 建表 + 结构迁移（**不走单例**）
 *
 * 供需要同时持有多个连接的场景使用（如 `scripts/db-migrate.ts` 的跨后端搬迁）。
 * 常规调用请用 {@link openDatabase}——它维护全局单例并负责复用。
 * @param options - 完整后端配置
 * @returns 已就绪的数据库句柄（由调用方负责 close）
 */
export async function createDatabase(
  options: DatabaseOptions,
): Promise<SqlDatabase> {
  const resolved = options;
  const schemaSql = buildSchemaSql(resolved.backend);
  let db: SqlDatabase;
  switch (resolved.backend) {
    case "sqlite":
      db = new SqliteDatabase(resolved.file ?? DEFAULT_SQLITE_FILE, schemaSql);
      break;
    case "mysql":
      db = await MysqlDatabase.create(resolved, schemaSql);
      break;
    case "postgresql":
      db = await PostgresDatabase.create(resolved, schemaSql);
      break;
  }

  await runSchemaMigrations(db);
  logger.info(
    "db",
    `database ready (${db.backend}): ${describeDatabase(resolved)}`,
  );
  return db;
}

/**
 * 实际建连（单例路径）：解析配置后委托 {@link createDatabase}
 * @param options - 数据库文件路径字符串，或完整后端配置
 * @returns 已就绪的数据库句柄
 */
async function openDatabaseInternal(
  options?: string | DatabaseOptions,
): Promise<SqlDatabase> {
  const resolved: DatabaseOptions =
    typeof options === "string"
      ? { backend: "sqlite", file: options }
      : (options ?? resolveDatabaseOptions());
  return createDatabase(resolved);
}

/**
 * 结构迁移：补历史版本缺失的列
 *
 * `CREATE TABLE IF NOT EXISTS` 不会给已存在的表加列；`star`（星标好友）是
 * friends 表的后加列，对旧库显式 ALTER（幂等：先探测列是否存在）。
 * @param db - 已执行建表 DDL 的连接
 */
async function runSchemaMigrations(db: SqlDatabase): Promise<void> {
  const starDef = `${physicalType("int", db.backend)} NOT NULL DEFAULT 0`;
  const added = await addColumnIfMissing(db, "friends", "star", starDef);
  if (added) {
    logger.info("db", "migrated: friends.star 列已补齐");
  }
}

/** 获取当前连接（未初始化时抛错） */
export function getDatabase(): SqlDatabase {
  if (!_db) throw new Error("数据库未初始化，请先调用 openDatabase()");
  return _db;
}

/**
 * 关闭连接并清空单例（测试与进程退出用）
 *
 * SQLite 关闭连接；MySQL/PostgreSQL 关闭连接池（等待在途查询结束）。
 */
export async function closeDatabase(): Promise<void> {
  if (_db) {
    const db = _db;
    _db = null;
    await db.close();
  }
}
