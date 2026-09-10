/**
 * PostgreSQL 驱动（可选后端）
 *
 * 基于 pg 连接池。源 SQL 统一写 `?`，此处经 {@link convertPlaceholders} 改写为
 * `$1..$n`；方言差异（`ON CONFLICT`）已在 dialect.ts 收口。
 *
 * 驱动为可选项（optionalDependencies）——本文件不做顶层 import，仅在实际选用
 * postgresql 后端时经 {@link loadOptionalDriver} 动态载入。
 */
import { loadOptionalDriver } from "./load";
import { convertPlaceholders, normalizeParams, toCount } from "../dialect";
import type {
  NetworkDatabaseOptions,
  SqlBindValue,
  SqlDatabase,
  SqlParam,
  SqlRunResult,
  SqlStatement,
} from "../types";

/** pg 查询结果 */
interface PgQueryResult {
  /** 结果行 */
  rows: unknown[];
  /** 受影响行数（SELECT 为行数，DML 为影响行数，少数语句为 null） */
  rowCount: number | null;
}

/** pg 单连接/池的查询面 */
interface PgQueryable {
  /** 执行参数化查询 */
  query(config: { text: string; values?: unknown[] }): Promise<PgQueryResult>;
  /** 执行无参原始 SQL（可含多条语句） */
  query(sql: string): Promise<PgQueryResult>;
}

/** pg 池连接 */
interface PgPoolClientLike extends PgQueryable {
  /** 归还连接到池 */
  release(): void;
}

/** pg 连接池 */
interface PgPoolLike extends PgQueryable {
  /** 取一条独占连接（事务用） */
  connect(): Promise<PgPoolClientLike>;
  /** 关闭池 */
  end(): Promise<void>;
}

/** pg 模块导出面 */
interface PgModule {
  /** 连接池构造器 */
  Pool: new (config: Record<string, unknown>) => PgPoolLike;
  /** 类型解析器注册表（用于把 BIGINT 映射为 number） */
  types?: {
    setTypeParser(oid: number, parse: (value: string) => unknown): void;
  };
}

/** PostgreSQL BIGINT（OID 20）——pg 默认映射为字符串 */
const PG_OID_INT8 = 20;

/**
 * pg 绑定值转换
 *
 * pg 仅识别 `Buffer` 形式的二进制参数，故把 `Uint8Array` 统一转 Buffer。
 * @param params - 原始参数
 * @returns 可直接交给 pg 的绑定值
 */
function bind(params: SqlParam[]): SqlBindValue[] {
  return normalizeParams(params).map((v) =>
    v instanceof Uint8Array && !Buffer.isBuffer(v) ? Buffer.from(v) : v,
  );
}

/** PostgreSQL 预编译语句 */
class PostgresStatement implements SqlStatement {
  /**
   * @param _conn - 执行语句的连接（事务内为独占连接）
   * @param _sql - 已改写为 `$n` 占位符的语句文本
   */
  constructor(
    private _conn: PgQueryable,
    private _sql: string,
  ) {}

  /** 查询单行 */
  async get<T = Record<string, unknown>>(
    ...params: SqlParam[]
  ): Promise<T | undefined> {
    const res = await this._conn.query({ text: this._sql, values: bind(params) });
    return res.rows[0] as T | undefined;
  }

  /** 查询多行 */
  async all<T = Record<string, unknown>>(...params: SqlParam[]): Promise<T[]> {
    const res = await this._conn.query({ text: this._sql, values: bind(params) });
    return res.rows as T[];
  }

  /** 执行写操作 */
  async run(...params: SqlParam[]): Promise<SqlRunResult> {
    const res = await this._conn.query({ text: this._sql, values: bind(params) });
    return { changes: toCount(res.rowCount ?? 0) };
  }
}

/** PostgreSQL 数据库连接（pg 连接池封装） */
export class PostgresDatabase implements SqlDatabase {
  /** 后端类型 */
  readonly backend = "postgresql" as const;
  /** 连接池 */
  private _pool: PgPoolLike;
  /** 事务嵌套深度（pg 不支持嵌套事务；>0 时复用外层事务） */
  private _txDepth = 0;
  /** 连接池是否已关闭 */
  private _closed = false;

  /**
   * 构造（仅由 {@link createPostgresDatabase} 调用——驱动加载是异步的）
   * @param pool - 已建立的连接池
   */
  private constructor(pool: PgPoolLike) {
    this._pool = pool;
  }

  /**
   * 建立 PostgreSQL 连接池并确保表结构存在
   * @param options - 连接配置
   * @param schemaSql - 建表 DDL（PostgreSQL 方言）
   * @returns 可用的 PostgreSQL 数据库句柄
   */
  static async create(
    options: NetworkDatabaseOptions,
    schemaSql: string,
  ): Promise<PostgresDatabase> {
    const pg = await loadOptionalDriver<PgModule>(
      "pg",
      "pg",
      "PostgreSQL 后端（config.database.type = \"postgresql\"）",
    );
    // BIGINT 默认映射为字符串：COUNT(*) 与毫秒时间戳会退化为 string，破坏调用方
    // 的类型契约与数值比较，故注册为 number（本项目 BIGINT 仅存毫秒时间戳，安全）。
    pg.types?.setTypeParser(PG_OID_INT8, (v) => Number(v));
    const pool = new pg.Pool({
      host: options.host ?? "127.0.0.1",
      port: options.port ?? 5432,
      user: options.user ?? "postgres",
      password: options.password ?? "",
      database: options.database ?? "arknights",
      max: options.connectionLimit ?? 10,
      ssl: options.ssl,
    });
    const db = new PostgresDatabase(pool);
    await db.exec(schemaSql);
    return db;
  }

  /** 准备语句（占位符 `?` → `$n`） */
  prepare(sql: string): SqlStatement {
    return new PostgresStatement(
      this._pool,
      convertPlaceholders(sql, "postgresql"),
    );
  }

  /** 执行原始 SQL（无参数多语句，由简单查询协议执行；DDL 建表用） */
  async exec(sql: string): Promise<void> {
    await this._pool.query(sql);
  }

  /** 事务（独占池连接；嵌套时复用外层事务） */
  async transaction<T>(fn: (tx: SqlDatabase) => Promise<T>): Promise<T> {
    if (this._txDepth > 0) return fn(this);
    const conn = await this._pool.connect();
    const tx: SqlDatabase = {
      backend: this.backend,
      prepare: (sql: string) =>
        new PostgresStatement(conn, convertPlaceholders(sql, "postgresql")),
      exec: async (sql: string) => {
        await conn.query(sql);
      },
      transaction: <R>(inner: (t: SqlDatabase) => Promise<R>) => inner(tx),
      close: async () => {},
      isOpen: () => true,
    };
    this._txDepth++;
    try {
      await conn.query("BEGIN");
      const result = await fn(tx);
      await conn.query("COMMIT");
      return result;
    } catch (e) {
      await conn.query("ROLLBACK");
      throw e;
    } finally {
      this._txDepth--;
      conn.release();
    }
  }

  /** 连接池是否仍可用 */
  isOpen(): boolean {
    return !this._closed;
  }

  /** 关闭连接池 */
  async close(): Promise<void> {
    if (this._closed) return;
    this._closed = true;
    await this._pool.end();
  }
}
