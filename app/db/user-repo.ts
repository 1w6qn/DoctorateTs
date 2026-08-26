/**
 * 用户配置仓储
 *
 * 封装 users 表 CRUD：UserConfig 以 JSON 列存储（AccountManager.configs 内存对象整体序列化）。
 * users.json 退化为「首次迁移种子」——首次启动 users 表空时由 migrateUsersFromJsonFile 导入。
 */
import { DatabaseSync } from "node:sqlite";
import { readJson } from "@utils/file";
import { now } from "@utils/time";
import type { UserConfig } from "@game/service/manager/AccountManager";

/**
 * 持久化前剔除社交字段
 *
 * 社交数据（好友/申请/访问）以 social.db 为唯一事实源（运行时只写 social.db），
 * users 表若继续存 social 只会残留过期快照——剔除后单事实源，消除双写不一致。
 */
function stripSocial(
  config: UserConfig,
): Omit<UserConfig, "social"> & { social?: never } {
  // UserConfig 已无 social 字段；旧种子数据（users.json 解析）可能仍带 social，按 any 剔除
  const { social: _social, ...rest } = config as UserConfig & {
    social?: unknown;
  };
  return rest;
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

  /** 插入/覆盖单个用户配置（社交字段不入库——social.db 为唯一事实源） */
  upsert(uid: string, config: UserConfig): void {
    this.db
      .prepare("INSERT OR REPLACE INTO users (uid, data, updated_ts) VALUES (?, ?, ?)")
      .run(uid, JSON.stringify(stripSocial(config)), now());
  }

  /**
   * 全量同步（事务——结果与传入 configs 完全一致，增量执行）
   * 语义：saveUserConfig 保存的是内存 configs 完整集合，删除的账号不应在数据库残留。
   * 实现（B-3）：逐行 INSERT OR REPLACE + 删除不在 configs 的 uid——不再清空整表重插，
   * 账号多时避免表级锁竞争与全表写放大。
   * 社交字段默认不入库（social.db 唯一事实源）；keepSocial 仅首次种子迁移（users.json → social.db 的桥）时用。
   */
  upsertAll(configs: { [uid: string]: UserConfig }, keepSocial = false): void {
    const stmt = this.db.prepare(
      "INSERT OR REPLACE INTO users (uid, data, updated_ts) VALUES (?, ?, ?)",
    );
    const delStmt = this.db.prepare("DELETE FROM users WHERE uid = ?");
    const existing = (
      this.db.prepare("SELECT uid FROM users").all() as { uid: string }[]
    ).map((r) => r.uid);
    const next = new Set(Object.keys(configs));
    const ts = now();
    this.db.exec("BEGIN");
    try {
      for (const [uid, config] of Object.entries(configs)) {
        stmt.run(uid, JSON.stringify(keepSocial ? config : stripSocial(config)), ts);
      }
      for (const uid of existing) {
        if (!next.has(uid)) delStmt.run(uid);
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
  repo.upsertAll(json, true); // keepSocial：种子带 social，供首次 migrateFromUserConfigs 导入 social.db
  return Object.keys(json).length;
}
