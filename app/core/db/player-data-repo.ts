/**
 * 玩家存档仓储：player_data 表（gzip 二进制文档存储）。
 *
 * 替代 data/user/databases/*.json 全量文件写——事务原子 + 体积 -88%（1.5MB → ~150KB）。
 * 存档为 JSON 文档（Immer delta / save-health 兼容），仅存储后端变化。
 *
 * 后端无关：二进制列在 SQLite 为 BLOB、MySQL 为 LONGBLOB、PostgreSQL 为 BYTEA，
 * 驱动层统一以 `Uint8Array`/`Buffer` 往返，仓储层不做方言分支。
 */
import { insertReplaceSql } from "./dialect";
import type { SqlDatabase } from "./types";
import { gzipSync, gunzipSync } from "zlib";

export class PlayerDataRepository {
  /** @param db - 后端无关的数据库句柄 */
  constructor(private _db: SqlDatabase) {}

  /**
   * 读存档（二进制 → JSON 字符串）
   * @param uid - 账号 uid
   * @returns JSON 字符串；无记录或数据损坏返回 null
   */
  async get(uid: string): Promise<string | null> {
    const row = await this._db
      .prepare("SELECT data FROM player_data WHERE uid = ?")
      .get<{ data: Uint8Array }>(uid);
    if (!row?.data) return null;
    try {
      return gunzipSync(Buffer.from(row.data)).toString("utf-8");
    } catch {
      return null; // 损坏 → 回退文件/重建
    }
  }

  /**
   * 写存档（JSON 字符串 → gzip 二进制覆盖写，事务原子）
   * @param uid - 账号 uid
   * @param json - 存档 JSON 字符串
   */
  async upsert(uid: string, json: string): Promise<void> {
    // level=1：gzip 快速档——落盘 CPU 从 ~15ms 降到 ~6ms（二进制 154KB→187KB，
    // 事件循环时间是私服更稀缺的资源；存档体积差异可忽略）
    const blob = gzipSync(json, { level: 1 });
    await this._db
      .prepare(
        insertReplaceSql(
          this._db.backend,
          "player_data",
          ["uid", "data", "updated_ts"],
          ["uid"],
        ),
      )
      .run(uid, blob, Date.now());
  }

  /**
   * 删除存档
   * @param uid - 账号 uid
   */
  async delete(uid: string): Promise<void> {
    await this._db.prepare("DELETE FROM player_data WHERE uid = ?").run(uid);
  }

  /**
   * 存档是否存在
   * @param uid - 账号 uid
   */
  async exists(uid: string): Promise<boolean> {
    const row = await this._db
      .prepare("SELECT 1 FROM player_data WHERE uid = ?")
      .get(uid);
    return row !== undefined;
  }
}
