/**
 * 战斗数据仓储（回放 + 结算信息）
 *
 * 回放与结算信息独立于用户配置存储（replays / battle_infos 表）——大对象不再塞进
 * users 表 JSON，避免每次保存配置时全量重写（R4 + A3）。
 */
import { DatabaseSync } from "node:sqlite";
import type { BattleInfo } from "@game/manager/AccountManger";

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

  /** 获取战斗结算信息（无则返回 undefined） */
  getInfo(uid: string, battleId: string): BattleInfo | undefined {
    const row = this.db
      .prepare("SELECT info FROM battle_infos WHERE uid = ? AND battle_id = ?")
      .get(uid, battleId) as { info: string } | undefined;
    return row ? (JSON.parse(row.info) as BattleInfo) : undefined;
  }

  /** 写入/覆盖战斗结算信息 */
  upsertInfo(uid: string, battleId: string, info: BattleInfo): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO battle_infos (uid, battle_id, info, updated_ts) VALUES (?, ?, ?, ?)",
      )
      .run(uid, battleId, JSON.stringify(info), nowTs());
  }
}
