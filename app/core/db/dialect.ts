/**
 * SQL 方言层（纯函数，零 IO）
 *
 * 三种后端在四类语法上不兼容，统一在此收口，仓储层不再出现方言分支：
 * | 语法 | sqlite | mysql | postgresql |
 * |---|---|---|---|
 * | 忽略冲突插入 | `INSERT OR IGNORE` | `INSERT IGNORE` | `ON CONFLICT DO NOTHING` |
 * | 覆盖插入 | `INSERT OR REPLACE` | `ON DUPLICATE KEY UPDATE` | `ON CONFLICT (cols) DO UPDATE` |
 * | 占位符 | `?` | `?` | `$1..$n` |
 * | 二进制列 | `BLOB` | `LONGBLOB` | `BYTEA` |
 *
 * 源 SQL 一律以 `?` 书写，PostgreSQL 由驱动调用 {@link convertPlaceholders} 改写。
 */
import type { DatabaseBackend, SqlBindValue, SqlParam } from "./types";

/**
 * 生成「忽略冲突」插入语句（已存在则不动）
 *
 * 对应原 `INSERT OR IGNORE`——好友/申请/访问记录防重复写入。
 * @param backend - 目标后端
 * @param table - 表名
 * @param columns - 列名列表（顺序即占位符顺序）
 * @returns 使用 `?` 占位符的 SQL
 */
export function insertIgnoreSql(
  backend: DatabaseBackend,
  table: string,
  columns: string[],
): string {
  const cols = columns.join(", ");
  const holes = columns.map(() => "?").join(", ");
  switch (backend) {
    case "sqlite":
      return `INSERT OR IGNORE INTO ${table} (${cols}) VALUES (${holes})`;
    case "mysql":
      return `INSERT IGNORE INTO ${table} (${cols}) VALUES (${holes})`;
    case "postgresql":
      return `INSERT INTO ${table} (${cols}) VALUES (${holes}) ON CONFLICT DO NOTHING`;
  }
}

/**
 * 生成「覆盖写入」语句（冲突则更新为本次入参）
 *
 * 对应原 `INSERT OR REPLACE`。SQLite 的 REPLACE 是「删旧行 + 插新行」，
 * 本层所有表无外键引用，语义等价。
 * @param backend - 目标后端
 * @param table - 表名
 * @param columns - 全部列名（顺序即占位符顺序）
 * @param conflictColumns - 冲突判定列（PostgreSQL 必需，须与主键一致；其余后端忽略）
 * @returns 使用 `?` 占位符的 SQL
 */
export function insertReplaceSql(
  backend: DatabaseBackend,
  table: string,
  columns: string[],
  conflictColumns: string[],
): string {
  const cols = columns.join(", ");
  const holes = columns.map(() => "?").join(", ");
  const conflictSet = new Set(conflictColumns);
  const updatable = columns.filter((c) => !conflictSet.has(c));
  switch (backend) {
    case "sqlite":
      return `INSERT OR REPLACE INTO ${table} (${cols}) VALUES (${holes})`;
    case "mysql": {
      // VALUES(col) 自 MySQL 8.0.20 起标记废弃但全版本可用；改用行别名语法会
      // 破坏 5.7 兼容，故保留 VALUES()。
      const sets = updatable.map((c) => `${c} = VALUES(${c})`).join(", ");
      return `INSERT INTO ${table} (${cols}) VALUES (${holes}) ON DUPLICATE KEY UPDATE ${sets}`;
    }
    case "postgresql": {
      const sets = updatable.map((c) => `${c} = EXCLUDED.${c}`).join(", ");
      const target = conflictColumns.join(", ");
      return `INSERT INTO ${table} (${cols}) VALUES (${holes}) ON CONFLICT (${target}) DO UPDATE SET ${sets}`;
    }
  }
}

/**
 * 把 `?` 占位符改写为 PostgreSQL 的 `$1..$n`
 *
 * 跳过单引号字符串字面量与 `--` 行注释内的 `?`（SQLite 的 `??` 转义不在本项目
 * 使用范围内）。非 PostgreSQL 后端原样返回。
 * @param sql - 以 `?` 书写的 SQL
 * @param backend - 目标后端
 * @returns 目标后端可执行的 SQL
 */
export function convertPlaceholders(sql: string, backend: DatabaseBackend): string {
  if (backend !== "postgresql") return sql;
  let out = "";
  let n = 0;
  let inString = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (inString) {
      out += ch;
      if (ch === "'") {
        // 转义写法 '' 表示字面量单引号，不结束字符串
        if (sql[i + 1] === "'") {
          out += "'";
          i++;
        } else {
          inString = false;
        }
      }
      continue;
    }
    if (ch === "'") {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "-" && sql[i + 1] === "-") {
      const lineEnd = sql.indexOf("\n", i);
      if (lineEnd === -1) {
        out += sql.slice(i);
        break;
      }
      out += sql.slice(i, lineEnd);
      i = lineEnd - 1;
      continue;
    }
    if (ch === "?") {
      n++;
      out += `$${n}`;
      continue;
    }
    out += ch;
  }
  return out;
}

/**
 * 归一化绑定参数，抹平三驱动差异
 *
 * - `undefined` → `null`（node:sqlite 绑定 undefined 直接抛错）
 * - `boolean` → `1`/`0`（node:sqlite 不支持布尔绑定；数值在三种后端语义一致）
 * - `bigint` → `number`（仅当在安全整数范围内，否则保留 bigint 交给驱动）
 * @param params - 原始参数
 * @returns 归一化后的绑定值数组（顺序不变）
 */
export function normalizeParams(params: SqlParam[]): SqlBindValue[] {
  return params.map((p) => {
    if (p === undefined) return null;
    if (typeof p === "boolean") return p ? 1 : 0;
    return p;
  });
}

/**
 * 把 `COUNT(*)` 等聚合结果统一成 number
 *
 * PostgreSQL 的 `COUNT(*)` 返回 BIGINT，pg 驱动默认映射为字符串，直接返回会
 * 让 `count() > 0` 这类判断与类型契约不一致。
 * @param value - 驱动返回的原始值
 * @returns 数值（无法解析时为 0）
 */
export function toCount(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string") {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  }
  return 0;
}
