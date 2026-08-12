/**
 * 玩家存档仓储（方案 A+C）：SQLite player_data 表（gzip BLOB 文档存储）。
 * 替代 data/user/databases/*.json 全量文件写——事务原子 + 体积 -88%（1.5MB → ~150KB）。
 * 存档为 JSON 文档（Immer delta / save-health 兼容），仅存储后端变化。
 */
import { DatabaseSync } from "node:sqlite";
import { gzipSync, gunzipSync } from "zlib";

export class PlayerDataRepository {
  constructor(private db: DatabaseSync) {}

  /** 读存档（gzip BLOB → JSON 字符串），无记录返回 null */
  get(uid: string): string | null {
    const row = this.db
      .prepare("SELECT data FROM player_data WHERE uid = ?")
      .get(uid) as { data: Uint8Array } | undefined;
    if (!row) return null;
    try {
      return gunzipSync(Buffer.from(row.data)).toString("utf-8");
    } catch {
      return null; // 损坏 → 回退文件/重建
    }
  }

  /** 写存档（JSON 字符串 → gzip BLOB upsert，事务原子） */
  upsert(uid: string, json: string): void {
    const blob = gzipSync(json);
    this.db
      .prepare(
        "INSERT OR REPLACE INTO player_data (uid, data, updated_ts) VALUES (?, ?, ?)",
      )
      .run(uid, blob, Date.now());
  }

  delete(uid: string): void {
    this.db.prepare("DELETE FROM player_data WHERE uid = ?").run(uid);
  }

  exists(uid: string): boolean {
    return (
      (this.db
        .prepare("SELECT 1 FROM player_data WHERE uid = ?")
        .get(uid) as { 1: number } | undefined) !== undefined
    );
  }
}
