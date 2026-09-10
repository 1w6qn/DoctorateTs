/**
 * 结构探测（跨后端）
 *
 * `CREATE TABLE IF NOT EXISTS` 只保证表存在，不会给既有表补列——加列需先探测列
 * 是否存在（幂等前提）。三种后端的元数据来源不同，在此统一。
 */
import type { SqlDatabase } from "./types";
import { toCount } from "./dialect";

/**
 * 判断表中是否已存在指定列
 *
 * - sqlite：`PRAGMA table_info`
 * - mysql：`information_schema.columns`（限定当前库）
 * - postgresql：`information_schema.columns`（限定当前库的默认 schema）
 *
 * 表不存在时统一返回 `false`（交由调用方建表，而非在此报错）。
 * @param db - 数据库句柄
 * @param table - 表名
 * @param column - 列名
 * @returns 列是否存在
 */
export async function columnExists(
  db: SqlDatabase,
  table: string,
  column: string,
): Promise<boolean> {
  try {
    if (db.backend === "sqlite") {
      const rows = await db
        .prepare(`PRAGMA table_info(${table})`)
        .all<{ name?: string }>();
      return rows.some((r) => r.name === column);
    }
    const sql =
      db.backend === "mysql"
        ? "SELECT COUNT(*) AS n FROM information_schema.columns " +
          "WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?"
        : "SELECT COUNT(*) AS n FROM information_schema.columns " +
          "WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?";
    const row = await db
      .prepare(sql)
      .get<{ n: unknown }>(table, column);
    return toCount(row?.n) > 0;
  } catch {
    // 探测失败（表不存在/权限不足）不阻断启动：交由后续 DDL 与查询给出真实错误
    return false;
  }
}

/**
 * 幂等加列（列已存在则跳过）
 *
 * `ALTER TABLE ADD COLUMN` 在三种后端语法一致，差异仅在「列是否存在」的判定上。
 * @param db - 数据库句柄
 * @param table - 表名
 * @param column - 列名
 * @param definition - 列定义（不含列名，如 `"INTEGER NOT NULL DEFAULT 0"`）
 * @returns 是否实际执行了加列
 */
export async function addColumnIfMissing(
  db: SqlDatabase,
  table: string,
  column: string,
  definition: string,
): Promise<boolean> {
  if (await columnExists(db, table, column)) return false;
  await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  return true;
}
