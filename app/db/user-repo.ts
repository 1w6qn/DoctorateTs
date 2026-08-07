/**
 * 用户配置仓储
 *
 * 封装 users 表 CRUD：UserConfig 以 JSON 列存储（AccountManager.configs 内存对象整体序列化）。
 * users.json 退化为「首次迁移种子」——首次启动 users 表空时由 migrateUsersFromJsonFile 导入。
 */
import { DatabaseSync } from "node:sqlite";
import { readJson } from "@utils/file";
import type { UserConfig } from "@game/manager/AccountManger";

/** 当前时间戳（秒） */
function nowTs(): number {
  return Math.floor(Date.now() / 1000);
}

export class UserRepository {
  constructor(private db: DatabaseSync) {}

  /** 全量读取用户配置（uid → UserConfig） */
  getAll(): { [uid: string]: UserConfig } {
    const rows = this.db
      .prepare("SELECT uid, data FROM users")
      .all() as { uid: string; data: string }[];
    const out: { [uid: string]: UserConfig } = {};
    for (const r of rows) out[r.uid] = JSON.parse(r.data);
    return out;
  }

  /** 读取单个用户配置 */
  get(uid: string): UserConfig | undefined {
    const row = this.db
      .prepare("SELECT data FROM users WHERE uid = ?")
      .get(uid) as { data: string } | undefined;
    return row ? (JSON.parse(row.data) as UserConfig) : undefined;
  }

  /** 插入/覆盖单个用户配置 */
  upsert(uid: string, config: UserConfig): void {
    this.db
      .prepare("INSERT OR REPLACE INTO users (uid, data, updated_ts) VALUES (?, ?, ?)")
      .run(uid, JSON.stringify(config), nowTs());
  }

  /**
   * 全量同步（事务——与传入 configs 完全一致：先清空再插入，部分失败回滚）
   * 语义：saveUserConfig 保存的是内存 configs 完整集合，删除的账号不应在数据库残留
   */
  upsertAll(configs: { [uid: string]: UserConfig }): void {
    const stmt = this.db.prepare(
      "INSERT OR REPLACE INTO users (uid, data, updated_ts) VALUES (?, ?, ?)",
    );
    const ts = nowTs();
    this.db.exec("BEGIN");
    try {
      this.db.exec("DELETE FROM users");
      for (const [uid, config] of Object.entries(configs)) {
        stmt.run(uid, JSON.stringify(config), ts);
      }
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }

  /** 用户数量 */
  count(): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM users").get() as { n: number };
    return row.n;
  }
}

/**
 * 从 users.json 迁移用户配置到 SQLite（幂等：users 表非空跳过）
 * @param db - SQLite 连接
 * @param repo - 用户仓储
 * @returns 导入的用户数（跳过返回 0）
 */
export async function migrateUsersFromJsonFile(
  db: DatabaseSync,
  repo: UserRepository,
): Promise<number> {
  if (repo.count() > 0) return 0;
  let json: { [uid: string]: UserConfig };
  try {
    json = await readJson("./data/user/users.json");
  } catch {
    return 0;
  }
  repo.upsertAll(json);
  return Object.keys(json).length;
}
