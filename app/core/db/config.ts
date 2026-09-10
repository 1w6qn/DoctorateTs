/**
 * 数据库连接配置解析
 *
 * 来源优先级（高 → 低）：
 * 1. 显式入参（`openDatabase(options)`，测试与脚本用）；
 * 2. 环境变量 `DB_TYPE` / `DB_HOST` / `DB_PORT` / `DB_USER` / `DB_PASSWORD` / `DB_NAME`
 *    （容器化部署无需改动配置文件）；
 * 3. `data/config.json` 的 `database` 块；
 * 4. 缺省值——`sqlite` + `./data/user/social.db`（与历史行为完全一致）。
 *
 * 未配置任何 `database` 块时解析结果等价于历史默认值，零迁移成本。
 */
import config from "@core/config";
import type { DatabaseBackend, DatabaseOptions } from "./types";

/** 默认 SQLite 数据库文件路径（相对项目根） */
export const DEFAULT_SQLITE_FILE = "./data/user/social.db";

/** `config.json` 中 `database` 块的形状（与 {@link import("./types").DatabaseOptions} 字段对齐） */
export interface DatabaseConfigBlock {
  /** 后端类型（缺省 sqlite） */
  type?: DatabaseBackend;
  /** SQLite 数据库文件路径（type=sqlite 时生效） */
  file?: string;
  /** 主机（type=mysql|postgresql 时生效） */
  host?: string;
  /** 端口（缺省 mysql 3306 / postgresql 5432） */
  port?: number;
  /** 用户名 */
  user?: string;
  /** 密码 */
  password?: string;
  /** 库名（须已存在——本层只建表不建库） */
  database?: string;
  /** 连接池最大连接数（缺省 10） */
  connectionLimit?: number;
  /** SSL 配置（透传驱动） */
  ssl?: boolean | Record<string, unknown>;
  /** 连接字符集（仅 mysql；缺省 utf8mb4） */
  charset?: string;
}

/**
 * 读取环境变量覆盖（空串视为未设置）
 * @param name - 环境变量名
 * @returns 变量值或 undefined
 */
function env(name: string): string | undefined {
  const v = process.env[name];
  return v === undefined || v === "" ? undefined : v;
}

/**
 * 解析环境变量中的端口
 * @param name - 环境变量名
 * @returns 合法端口号或 undefined
 */
function envPort(name: string): number | undefined {
  const raw = env(name);
  if (raw === undefined) return undefined;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : undefined;
}

/**
 * 归一化后端名（兼容 `postgres`/`postgresql`/`pg` 写法）
 * @param raw - 配置或环境变量中的后端名
 * @returns 标准后端名；无法识别时返回 undefined
 */
function normalizeBackend(raw: string | undefined): DatabaseBackend | undefined {
  if (!raw) return undefined;
  const v = raw.trim().toLowerCase();
  if (v === "sqlite" || v === "sqlite3") return "sqlite";
  if (v === "mysql" || v === "mariadb") return "mysql";
  if (v === "postgres" || v === "postgresql" || v === "pg") return "postgresql";
  return undefined;
}

/**
 * 解析最终数据库连接配置
 * @returns 已完成优先级合并的配置（`backend` 必定存在）
 */
export function resolveDatabaseOptions(): DatabaseOptions {
  const block: DatabaseConfigBlock =
    (config as { database?: DatabaseConfigBlock }).database ?? {};
  const backend =
    normalizeBackend(env("DB_TYPE")) ??
    normalizeBackend(block.type) ??
    "sqlite";

  if (backend === "sqlite") {
    return { backend: "sqlite", file: env("DB_FILE") ?? block.file ?? DEFAULT_SQLITE_FILE };
  }
  return {
    backend,
    host: env("DB_HOST") ?? block.host,
    port: envPort("DB_PORT") ?? block.port,
    user: env("DB_USER") ?? block.user,
    password: env("DB_PASSWORD") ?? block.password,
    database: env("DB_NAME") ?? block.database,
    connectionLimit: block.connectionLimit,
    ssl: block.ssl,
    charset: block.charset,
  };
}

/**
 * 生成用于日志的连接描述（绝不包含密码）
 * @param options - 数据库配置
 * @returns 可安全打印的一行描述
 */
export function describeDatabase(options: DatabaseOptions): string {
  if (options.backend === "sqlite") {
    return `sqlite:${options.file ?? DEFAULT_SQLITE_FILE}`;
  }
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? (options.backend === "mysql" ? 3306 : 5432);
  const name = options.database ?? "arknights";
  return `${options.backend}://${options.user ?? "-"}@${host}:${port}/${name}`;
}
