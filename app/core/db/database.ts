/**
 * SQLite 连接管理模块
 *
 * 使用 Node 24 内置 node:sqlite（DatabaseSync），零第三方依赖。
 * 默认数据库文件为 data/user/social.db，测试可传入 ":memory:"。
 */
import { DatabaseSync } from "node:sqlite";
import { SCHEMA_SQL } from "./schema";

/** 重导出建表 SQL（供初始化/测试使用） */
export { SCHEMA_SQL } from "./schema";

/** 默认数据库文件路径（相对项目根） */
export const DEFAULT_DB_PATH = "./data/user/social.db";

/** 全局单例连接 */
let _db: DatabaseSync | null = null;

/**
 * 打开（或复用）SQLite 连接并确保表结构存在
 * @param path - 数据库路径或 ":memory:"
 */
export function openDatabase(path: string = DEFAULT_DB_PATH): DatabaseSync {
  if (_db) {
    // 已有连接：校验仍可读写（避免复用被 close 的连接）
    try {
      _db.prepare("SELECT 1").get();
      return _db;
    } catch {
      _db = null; // 连接已关闭，重建
    }
  }
  const db = new DatabaseSync(path);
  // WAL 模式：回放/结算/社交高频写时不阻塞读（内存库自动回退 memory 模式，无副作用）
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(SCHEMA_SQL);
  migrateFriendsStarColumn(db);
  _db = db;
  return db;
}

/**
 * 迁移：为既有 friends 表补 star 列（星标好友）
 *
 * CREATE TABLE IF NOT EXISTS 不会给已存在的表加列，故对旧库显式 ALTER（幂等：
 * 先查 PRAGMA table_info，已有列则跳过）。
 * @param db - 已打开且执行过 SCHEMA_SQL 的连接
 */
function migrateFriendsStarColumn(db: DatabaseSync): void {
  try {
    const cols = db.prepare("PRAGMA table_info(friends)").all() as {
      name?: string;
    }[];
    if (cols.some((c) => c.name === "star")) return;
    db.exec("ALTER TABLE friends ADD COLUMN star INTEGER NOT NULL DEFAULT 0");
  } catch {
    // 表不存在等异常场景交由后续查询报错；迁移本身不阻断启动
  }
}

/** 获取当前连接（未初始化时抛错） */
export function getDatabase(): DatabaseSync {
  if (!_db) throw new Error("数据库未初始化，请先调用 openDatabase()");
  return _db;
}

/** 关闭连接并清空单例（测试用） */
export function closeDatabase(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}
