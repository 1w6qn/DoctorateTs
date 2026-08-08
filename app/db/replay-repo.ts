/**
 * 战斗回放仓储
 *
 * 回放独立于用户配置存储（replays 表）——大字符串不再塞进 users 表 JSON，
 * 避免每次保存配置时全量重写回放（R4：战斗回放独立存储）。
 */
import { DatabaseSync } from "node:sqlite";

/** 当前时间戳（秒） */
function nowTs(): number {
  return Math.floor(Date.now() / 1000);
}

export class ReplayRepository {
  constructor(private db: DatabaseSync) {}

  /** 获取回放（无则返回空串） */
  get(uid: string, stageId: string): string {
    const row = this.db
      .prepare("SELECT replay FROM replays WHERE uid = ? AND stage_id = ?")
      .get(uid, stageId) as { replay: string } | undefined;
    return row?.replay ?? "";
  }

  /** 写入/覆盖回放 */
  upsert(uid: string, stageId: string, replay: string): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO replays (uid, stage_id, replay, updated_ts) VALUES (?, ?, ?, ?)",
      )
      .run(uid, stageId, replay, nowTs());
  }
}
