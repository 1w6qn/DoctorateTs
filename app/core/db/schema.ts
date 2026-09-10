/**
 * 主数据层表结构定义（后端无关）
 *
 * 以声明式表规格描述结构，由 {@link buildSchemaSql} 生成三种后端的建表 DDL——
 * 新增表/列只改本文件，方言差异（VARCHAR 长度、BLOB/BYTEA、保留字、索引语法）在此收口。
 *
 * 表清单：
 * - `friends` / `friend_requests` / `friend_request_log` / `visited`：好友关系与访问记录；
 * - `users`：用户账号配置（JSON 列；users.json 仅首次迁移种子）；
 * - `replays` / `battle_infos` / `battle_records`：战斗回放、结算信息与结束记录；
 * - `player_data`：玩家存档（方案 A+C：gzip 二进制文档）。
 *
 * `CREATE TABLE IF NOT EXISTS` 保证幂等——已在库中的表不会被改动，加列靠
 * {@link import("./introspect").columnExists} 驱动的增量迁移。
 */
import type { DatabaseBackend } from "./types";

/** 列的逻辑类型（映射到各后端物理类型） */
export type ColumnType =
  /** 短标识（uid / 关卡 id / 战斗 id）：MySQL 用 VARCHAR(191) 以满足索引键长限制 */
  | "uid"
  /** 短文本：同上 */
  | "text"
  /** 长文本（JSON 文档 / 回放字符串）：MySQL 用 LONGTEXT */
  | "longtext"
  /** 毫秒时间戳：必须 BIGINT（1.7e12 超出 INT4 上限） */
  | "bigint"
  /** 小整数（计数 / 0-1 标志） */
  | "int"
  /** 二进制（MySQL LONGBLOB / PG BYTEA / SQLite BLOB） */
  | "blob";

/** 列规格 */
export interface ColumnSpec {
  /** 列名 */
  name: string;
  /** 逻辑类型 */
  type: ColumnType;
  /** 是否 NOT NULL */
  notNull?: boolean;
  /** 默认值字面量（原样拼入 DDL，如 `0`、`''`） */
  default?: string;
}

/** 二级索引规格 */
export interface IndexSpec {
  /** 索引名 */
  name: string;
  /** 索引列（有序） */
  columns: string[];
}

/** 表规格 */
export interface TableSpec {
  /** 表名 */
  name: string;
  /** 列定义（有序） */
  columns: ColumnSpec[];
  /** 主键列（有序；对应 `PRIMARY KEY (...)` 表级约束） */
  primaryKey: string[];
  /** 二级索引（SQLite/PG 单独 CREATE INDEX；MySQL 内联 KEY——MySQL 不支持 CREATE INDEX IF NOT EXISTS） */
  indexes?: IndexSpec[];
}

/** 全部表规格（顺序即建表顺序） */
export const TABLES: TableSpec[] = [
  {
    name: "friends",
    columns: [
      { name: "uid", type: "uid", notNull: true },
      { name: "friend_uid", type: "uid", notNull: true },
      { name: "alias", type: "text", notNull: true, default: "''" },
      { name: "create_ts", type: "bigint", notNull: true },
      // 星标好友标记（0/1）：上限 gamedata_const.maxStarFriendNum（实测 5）
      { name: "star", type: "int", notNull: true, default: "0" },
    ],
    primaryKey: ["uid", "friend_uid"],
    indexes: [{ name: "idx_friends_friend", columns: ["friend_uid"] }],
  },
  {
    name: "friend_requests",
    columns: [
      { name: "from_uid", type: "uid", notNull: true },
      { name: "to_uid", type: "uid", notNull: true },
      { name: "create_ts", type: "bigint", notNull: true },
    ],
    primaryKey: ["from_uid", "to_uid"],
    indexes: [{ name: "idx_friend_requests_to", columns: ["to_uid"] }],
  },
  {
    // 好友申请冷却（gamedata_const.requestSameFriendCd，实测 14400s = 4h）：
    // 记录 (from,to) 最近一次申请时间；申请被处理/撤回后本表**不删除**，
    // 故「同一好友 4 小时内不可重复申请」可跨申请生命周期生效。
    name: "friend_request_log",
    columns: [
      { name: "from_uid", type: "uid", notNull: true },
      { name: "to_uid", type: "uid", notNull: true },
      { name: "last_ts", type: "bigint", notNull: true },
    ],
    primaryKey: ["from_uid", "to_uid"],
  },
  {
    name: "visited",
    columns: [
      { name: "uid", type: "uid", notNull: true },
      { name: "visited_uid", type: "uid", notNull: true },
      { name: "ts", type: "bigint", notNull: true },
    ],
    primaryKey: ["uid", "visited_uid"],
  },
  {
    // 用户账号配置（users.json 迁移目标——库为唯一事实源，users.json 仅首次迁移种子）
    name: "users",
    columns: [
      { name: "uid", type: "uid", notNull: true },
      { name: "data", type: "longtext", notNull: true },
      { name: "updated_ts", type: "bigint", notNull: true },
    ],
    primaryKey: ["uid"],
  },
  {
    // 战斗回放（独立于用户配置存储——大字符串不再塞进 users 表 JSON，避免每次配置保存全量重写）
    name: "replays",
    columns: [
      { name: "uid", type: "uid", notNull: true },
      { name: "stage_id", type: "uid", notNull: true },
      { name: "replay", type: "longtext", notNull: true },
      { name: "updated_ts", type: "bigint", notNull: true },
    ],
    primaryKey: ["uid", "stage_id"],
  },
  {
    // 战斗结算信息（独立于用户配置存储——避免每次战斗结算全量重写 users 表）
    name: "battle_infos",
    columns: [
      { name: "uid", type: "uid", notNull: true },
      { name: "battle_id", type: "uid", notNull: true },
      { name: "info", type: "longtext", notNull: true },
      { name: "updated_ts", type: "bigint", notNull: true },
    ],
    primaryKey: ["uid", "battle_id"],
  },
  {
    // 战斗结束记录（完整结算数据留存，供未来分析——按 uid 建索引便于历史检索）
    name: "battle_records",
    columns: [
      { name: "battle_id", type: "uid", notNull: true },
      { name: "uid", type: "uid", notNull: true },
      { name: "stage_id", type: "uid", notNull: true },
      { name: "record", type: "longtext", notNull: true },
      { name: "created_ts", type: "bigint", notNull: true },
    ],
    primaryKey: ["battle_id", "uid"],
    indexes: [{ name: "idx_battle_records_uid", columns: ["uid"] }],
  },
  {
    // 玩家存档（方案 A+C：gzip 二进制文档存储，替代 data/user/databases/*.json）
    name: "player_data",
    columns: [
      { name: "uid", type: "uid", notNull: true },
      { name: "data", type: "blob", notNull: true },
      { name: "updated_ts", type: "bigint", notNull: true },
    ],
    primaryKey: ["uid"],
  },
];

/** 逻辑类型 × 后端 → 物理类型映射表 */
const PHYSICAL_TYPES: Record<DatabaseBackend, Record<ColumnType, string>> = {
  sqlite: {
    uid: "TEXT",
    text: "TEXT",
    longtext: "TEXT",
    bigint: "INTEGER",
    int: "INTEGER",
    blob: "BLOB",
  },
  mysql: {
    uid: "VARCHAR(191)",
    text: "VARCHAR(191)",
    longtext: "LONGTEXT",
    bigint: "BIGINT",
    int: "INT",
    blob: "LONGBLOB",
  },
  postgresql: {
    uid: "TEXT",
    text: "TEXT",
    longtext: "TEXT",
    bigint: "BIGINT",
    int: "INTEGER",
    blob: "BYTEA",
  },
};

/**
 * 逻辑类型 → 后端物理类型
 *
 * MySQL 的 `uid`/`text` 用 VARCHAR(191)：utf8mb4 下 191 字符 = 764 字节，
 * 低于 InnoDB 3072 字节索引键上限，且 TEXT 列无法直接作为 PRIMARY KEY。
 * @param type - 逻辑类型
 * @param backend - 目标后端
 * @returns 物理类型名
 */
export function physicalType(type: ColumnType, backend: DatabaseBackend): string {
  return PHYSICAL_TYPES[backend][type];
}

/** 是否使用 MySQL 风格的内联 `KEY` 索引（其 CREATE INDEX 不支持 IF NOT EXISTS） */
function usesInlineIndex(backend: DatabaseBackend): boolean {
  return backend === "mysql";
}

/**
 * 生成指定后端的完整建表 DDL（幂等，可重复执行）
 * @param backend - 目标后端
 * @returns 以 `;\n` 分隔的建表语句集合
 */
export function buildSchemaSql(backend: DatabaseBackend): string {
  const parts: string[] = [];
  for (const table of TABLES) {
    const defs = table.columns.map((c) => {
      let def = `  ${c.name} ${physicalType(c.type, backend)}`;
      if (c.notNull) def += " NOT NULL";
      if (c.default !== undefined) def += ` DEFAULT ${c.default}`;
      return def;
    });
    if (table.primaryKey.length > 0) {
      defs.push(`  PRIMARY KEY (${table.primaryKey.join(", ")})`);
    }
    if (usesInlineIndex(backend)) {
      for (const idx of table.indexes ?? []) {
        defs.push(`  KEY ${idx.name} (${idx.columns.join(", ")})`);
      }
    }
    let ddl = `CREATE TABLE IF NOT EXISTS ${table.name} (\n${defs.join(",\n")}\n)`;
    if (backend === "mysql") ddl += " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    parts.push(ddl + ";");

    if (!usesInlineIndex(backend)) {
      for (const idx of table.indexes ?? []) {
        parts.push(
          `CREATE INDEX IF NOT EXISTS ${idx.name} ON ${table.name}(${idx.columns.join(", ")});`,
        );
      }
    }
  }
  return parts.join("\n") + "\n";
}

/**
 * SQLite 建表 SQL（向后兼容导出：测试与旧调用点直接执行本常量）
 *
 * `openDatabase()` 不再用它建表（改由驱动按后端生成），保留以避免调用点散落
 * `buildSchemaSql("sqlite")`。
 */
export const SCHEMA_SQL = buildSchemaSql("sqlite");
