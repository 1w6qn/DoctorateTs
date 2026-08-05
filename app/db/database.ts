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
  db.exec(SCHEMA_SQL);
  _db = db;
  return db;
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
