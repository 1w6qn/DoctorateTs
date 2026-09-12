/**
 * 主数据层跨后端搬迁（SQLite ⇄ MySQL / PostgreSQL）
 *
 * 用途：把现有数据从一种后端整表复制到另一种后端。切换 `config.database.type` 本身
 * 只会新建空表，不会搬运数据——本脚本补齐这一步。
 *
 * 用法：
 * ```bash
 * # 1) 先把 data/config.json 的 database 块配成目标后端
 * pnpm run db:migrate                 # 默认源：./data/user/social.db → 配置的后端
 * pnpm run db:migrate -- --dry-run    # 只统计不写入
 * pnpm run db:migrate -- --force      # 目标已有数据仍覆盖
 *
 * # 2) 也可显式指定两端
 * pnpm run db:migrate -- --from-file ./data/user/social.db --to mysql --host 127.0.0.1 --user root --password pw --database arknights
 * ```
 *
 * 特性：
 * - 逐表按主键覆盖写（`insertReplaceSql`）——可重复执行，不会产生重复行；
 * - 目标表非空时默认拒绝执行（避免把线上库误覆盖），`--force` 显式确认；
 * - 每 200 行一个事务，失败即中止并报出表名与行号。
 *
 * 注意：源端为 SQLite 时按文件直连（不经配置），目标端为配置/入参解析——
 * 因此本脚本可安全地在「配置已切到 MySQL、但 SQLite 数据还在」的状态下运行。
 */
import {
  closeDatabase,
  createDatabase,
} from "@core/db/database";
import { describeDatabase, resolveDatabaseOptions } from "@core/db/config";
import { insertReplaceSql } from "@core/db/dialect";
import { TABLES } from "@core/db/schema";
import type { DatabaseBackend, DatabaseOptions, SqlDatabase } from "@core/db/types";
import { logger } from "@utils/logger";

/** 单事务写入的行数上限（大表分片提交，避免长事务锁表） */
const BATCH_SIZE = 200;

/** CLI 参数解析结果 */
interface CliArgs {
  /** 源 SQLite 文件路径 */
  fromFile: string;
  /** 目标后端（缺省取 config.database） */
  to?: DatabaseBackend;
  /** 目标为 sqlite 时的文件路径 */
  file?: string;
  /** 目标为网络型后端时的连接参数 */
  host?: string;
  port?: number;
  user?: string;
  password?: string;
  database?: string;
  /** 目标库非空时是否仍执行 */
  force: boolean;
  /** 只统计不写入 */
  dryRun: boolean;
}

/**
 * 读取命名参数
 * @param argv - 参数数组
 * @param name - 参数名（含前导 --）
 * @returns 参数值或 undefined
 */
function arg(argv: string[], name: string): string | undefined {
  const idx = argv.indexOf(name);
  return idx >= 0 && argv[idx + 1] !== undefined ? argv[idx + 1] : undefined;
}

/**
 * 解析命令行参数
 * @param argv - process.argv.slice(2)
 * @returns 结构化参数
 */
function parseArgs(argv: string[]): CliArgs {
  const portRaw = arg(argv, "--port");
  const toRaw = arg(argv, "--to")?.trim().toLowerCase();
  const to =
    toRaw === undefined
      ? undefined
      : toRaw === "postgres" || toRaw === "pg"
        ? "postgresql"
        : toRaw === "mariadb"
          ? "mysql"
          : (toRaw as DatabaseBackend);
  if (to !== undefined && !["sqlite", "mysql", "postgresql"].includes(to)) {
    throw new Error(`未知目标后端 "${toRaw}"（可选：sqlite / mysql / postgresql）`);
  }
  return {
    fromFile: arg(argv, "--from-file") ?? "./data/user/social.db",
    to,
    file: arg(argv, "--file"),
    host: arg(argv, "--host"),
    port: portRaw === undefined ? undefined : Number(portRaw),
    user: arg(argv, "--user"),
    password: arg(argv, "--password"),
    database: arg(argv, "--database"),
    force: argv.includes("--force"),
    dryRun: argv.includes("--dry-run"),
  };
}

/**
 * 由 CLI 参数与配置合成目标后端配置
 * @param args - 已解析参数
 * @returns 目标连接配置
 */
function resolveTarget(args: CliArgs): DatabaseOptions {
  const configured = resolveDatabaseOptions();
  const backend = args.to ?? configured.backend;
  if (backend === "sqlite") {
    // configured.file 只存在于 sqlite 后端对象上；非 sqlite 配置里它本就取不到值（undefined）
    const file = configured.backend === "sqlite" ? configured.file : undefined;
    return { backend: "sqlite", file: args.file ?? file };
  }
  const base = configured.backend === backend ? configured : undefined;
  return {
    backend,
    host: args.host ?? base?.host,
    port: args.port ?? base?.port,
    user: args.user ?? base?.user,
    password: args.password ?? base?.password,
    database: args.database ?? base?.database,
  };
}

/**
 * 复制单张表（按主键覆盖写，分片事务）
 * @param source - 源连接
 * @param target - 目标连接
 * @param table - 表名
 * @param columns - 列名（有序）
 * @param pk - 主键列
 * @param dryRun - 只统计不写入
 * @returns 已复制的行数
 */
async function copyTable(
  source: SqlDatabase,
  target: SqlDatabase,
  table: string,
  columns: string[],
  pk: string[],
  dryRun: boolean,
): Promise<number> {
  const rows = await source
    .prepare(`SELECT ${columns.join(", ")} FROM ${table}`)
    .all<Record<string, unknown>>();
  if (dryRun || rows.length === 0) return rows.length;

  const sql = insertReplaceSql(target.backend, table, columns, pk);
  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    await target.transaction(async (tx) => {
      const stmt = tx.prepare(sql);
      for (const row of batch) {
        await stmt.run(
          ...columns.map((c) => row[c] as string | number | Uint8Array | null),
        );
      }
    });
  }
  return rows.length;
}

/** CLI 入口 */
async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const targetOptions = resolveTarget(args);
  const sourceOptions: DatabaseOptions = {
    backend: "sqlite",
    file: args.fromFile,
  };

  if (
    targetOptions.backend === "sqlite" &&
    (targetOptions.file ?? "") === args.fromFile
  ) {
    throw new Error(
      `源与目标是同一个 SQLite 文件（${args.fromFile}）——请用 --file 指定不同的目标文件，` +
        "或把 --from-file 指向待搬迁的旧库",
    );
  }

  logger.info("db-migrate", `源：${describeDatabase(sourceOptions)}`);
  logger.info("db-migrate", `目标：${describeDatabase(targetOptions)}`);
  if (args.dryRun) logger.info("db-migrate", "dry-run：只统计，不写入");

  const source = await createDatabase(sourceOptions);
  let target: SqlDatabase | null = null;
  try {
    target = await createDatabase(targetOptions);

    let total = 0;
    for (const table of TABLES) {
      const columns = table.columns.map((c) => c.name);
      const existing = await target
        .prepare(`SELECT COUNT(*) AS n FROM ${table.name}`)
        .get<{ n: unknown }>();
      const existingCount = Number(existing?.n ?? 0);
      if (existingCount > 0 && !args.force) {
        throw new Error(
          `目标表 ${table.name} 已有 ${existingCount} 行——为避免覆盖现有数据，已中止。` +
            "确认要覆盖请加 --force",
        );
      }
      const n = await copyTable(
        source,
        target,
        table.name,
        columns,
        table.primaryKey,
        args.dryRun,
      );
      total += n;
      logger.info("db-migrate", `${table.name}: ${n} 行`);
    }
    logger.info(
      "db-migrate",
      `完成：${TABLES.length} 张表 / ${total} 行` +
        (args.dryRun ? "（dry-run，未写入）" : ""),
    );
    if (!args.dryRun) {
      logger.info(
        "db-migrate",
        "后续：把 data/config.json 的 database.type 设为目标后端后重启服务；" +
          "SQLite 旧文件建议确认无误后再删除",
      );
    }
  } finally {
    await target?.close();
    await source.close();
    await closeDatabase();
  }
}

if (require.main === module) {
  main().catch((e) => {
    logger.error("db-migrate", (e as Error).message);
    process.exitCode = 1;
  });
}

/** 内部工具导出（供单测直接验证参数解析与单表复制） */
export { copyTable, parseArgs, resolveTarget };
