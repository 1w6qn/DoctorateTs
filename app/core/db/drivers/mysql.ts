/**
 * MySQL 驱动（可选后端）
 *
 * 基于 mysql2/promise 连接池。mysql2 与源 SQL 一样使用 `?` 占位符，无需改写；
 * 方言差异（`INSERT IGNORE` / `ON DUPLICATE KEY UPDATE`）已在 dialect.ts 收口。
 *
 * 驱动为可选项（optionalDependencies）——本文件不做顶层 import，仅在实际选用
 * mysql 后端时经 {@link loadOptionalDriver} 动态载入。
 */
import { loadOptionalDriver } from "./load";
import { normalizeParams, toCount } from "../dialect";
import type {
  NetworkDatabaseOptions,
  SqlDatabase,
  SqlParam,
  SqlRunResult,
  SqlStatement,
} from "../types";

/** mysql2 查询结果：[rows, fields]；写操作时 rows 为结果头对象 */
type MysqlQueryResult = [unknown, unknown];

/** mysql2 连接（池连接与单连接公共面） */
interface MysqlConnectionLike {
  /** 执行语句（`?` 占位符，客户端转义） */
  query(sql: string, values?: unknown[]): Promise<MysqlQueryResult>;
}

/** mysql2 事务连接 */
interface MysqlPoolConnectionLike extends MysqlConnectionLike {
  /** 开启事务 */
  beginTransaction(): Promise<void>;
  /** 提交 */
  commit(): Promise<void>;
  /** 回滚 */
  rollback(): Promise<void>;
  /** 归还连接到池 */
  release(): void;
}

/** mysql2 连接池 */
interface MysqlPoolLike extends MysqlConnectionLike {
  /** 取一条独占连接（事务用） */
  getConnection(): Promise<MysqlPoolConnectionLike>;
  /** 关闭池 */
  end(): Promise<void>;
}

/** mysql2/promise 模块导出面 */
interface Mysql2Module {
  /** 创建连接池 */
  createPool(config: Record<string, unknown>): MysqlPoolLike;
}

/** MySQL 预编译语句 */
class MysqlStatement implements SqlStatement {
  /**
   * @param _conn - 执行语句的连接（事务内为独占连接）
   * @param _sql - 语句文本（`?` 占位符）
   */
  constructor(
    private _conn: MysqlConnectionLike,
    private _sql: string,
  ) {}

  /** 查询单行 */
  async get<T = Record<string, unknown>>(
    ...params: SqlParam[]
  ): Promise<T | undefined> {
    const [rows] = await this._conn.query(this._sql, normalizeParams(params));
    return Array.isArray(rows) ? (rows[0] as T | undefined) : undefined;
  }

  /** 查询多行 */
  async all<T = Record<string, unknown>>(...params: SqlParam[]): Promise<T[]> {
    const [rows] = await this._conn.query(this._sql, normalizeParams(params));
    return Array.isArray(rows) ? (rows as T[]) : [];
  }

  /** 执行写操作 */
  async run(...params: SqlParam[]): Promise<SqlRunResult> {
    const [res] = await this._conn.query(this._sql, normalizeParams(params));
    const header = res as { affectedRows?: number } | undefined;
    return { changes: toCount(header?.affectedRows ?? 0) };
  }
}

/** MySQL 数据库连接（mysql2 连接池封装） */
export class MysqlDatabase implements SqlDatabase {
  /** 后端类型 */
  readonly backend = "mysql" as const;
  /** 连接池 */
  private _pool: MysqlPoolLike;
  /** 事务嵌套深度（MySQL 不支持嵌套事务；>0 时复用外层事务） */
  private _txDepth = 0;
  /** 连接池是否已关闭 */
  private _closed = false;

  /**
   * 构造（仅由 {@link createMysqlDatabase} 调用——驱动加载是异步的）
   * @param pool - 已建立的连接池
   */
  private constructor(pool: MysqlPoolLike) {
    this._pool = pool;
  }

  /**
   * 建立 MySQL 连接池并确保表结构存在
   * @param options - 连接配置
   * @param schemaSql - 建表 DDL（MySQL 方言）
   * @returns 可用的 MySQL 数据库句柄
   */
  static async create(
    options: NetworkDatabaseOptions,
    schemaSql: string,
  ): Promise<MysqlDatabase> {
    const mysql = await loadOptionalDriver<Mysql2Module>(
      "mysql2/promise",
      "mysql2",
      "MySQL 后端（config.database.type = \"mysql\"）",
    );
    const pool = mysql.createPool({
      host: options.host ?? "127.0.0.1",
      port: options.port ?? 3306,
      user: options.user ?? "root",
      password: options.password ?? "",
      database: options.database ?? "arknights",
      connectionLimit: options.connectionLimit ?? 10,
      charset: options.charset ?? "utf8mb4",
      ssl: options.ssl === true ? {} : options.ssl,
      // 建表 DDL 为多条语句合并的脚本，须开启多语句执行
      multipleStatements: true,
      waitForConnections: true,
    });
    const db = new MysqlDatabase(pool);
    await db.exec(schemaSql);
    return db;
  }

  /** 准备语句 */
  prepare(sql: string): SqlStatement {
    return new MysqlStatement(this._pool, sql);
  }

  /** 执行原始 SQL（可含多条语句；DDL 建表用） */
  async exec(sql: string): Promise<void> {
    await this._pool.query(sql);
  }

  /** 事务（独占池连接；嵌套时复用外层事务） */
  async transaction<T>(fn: (tx: SqlDatabase) => Promise<T>): Promise<T> {
    if (this._txDepth > 0) return fn(this);
    const conn = await this._pool.getConnection();
    const tx: SqlDatabase = {
      backend: this.backend,
      prepare: (sql: string) => new MysqlStatement(conn, sql),
      exec: async (sql: string) => {
        await conn.query(sql);
      },
      transaction: <R>(inner: (t: SqlDatabase) => Promise<R>) => inner(tx),
      close: async () => {},
      isOpen: () => true,
    };
    this._txDepth++;
    try {
      await conn.beginTransaction();
      const result = await fn(tx);
      await conn.commit();
      return result;
    } catch (e) {
      await conn.rollback();
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
