/**
 * 战斗数据仓储（回放 + 结算信息）
 *
 * 回放与结算信息独立于用户配置存储（replays / battle_infos 表）——大对象不再塞进
 * users 表 JSON，避免每次保存配置时全量重写（R4 + A3）。
 */
import { DatabaseSync } from "node:sqlite";
import { now } from "@utils/time";
import type {
  BattleInfo,
  BattleRecord,
} from "@game/manager/BattleInfoStore";

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
      .run(uid, stageId, replay, now());
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
      .run(uid, battleId, JSON.stringify(info), now());
  }

  /** 删除账号的战斗数据（B-2：回放 + 结算信息） */
  deleteUser(uid: string): void {
    this.db.prepare("DELETE FROM replays WHERE uid = ?").run(uid);
    this.db.prepare("DELETE FROM battle_infos WHERE uid = ?").run(uid);
    this.db.prepare("DELETE FROM battle_records WHERE uid = ?").run(uid);
  }

  /** 留存战斗结束记录（写入/覆盖，供未来分析） */
  saveRecord(record: BattleRecord): void {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO battle_records (battle_id, uid, stage_id, record, created_ts) VALUES (?, ?, ?, ?, ?)",
      )
      .run(
        record.battleId,
        record.uid,
        record.stageId,
        JSON.stringify(record),
        record.createdTs,
      );
  }

  /** 按账号+战斗 id 读取战斗结束记录（无则 undefined） */
  getRecord(uid: string, battleId: string): BattleRecord | undefined {
    const row = this.db
      .prepare(
        "SELECT record FROM battle_records WHERE uid = ? AND battle_id = ?",
      )
      .get(uid, battleId) as { record: string } | undefined;
    return row ? (JSON.parse(row.record) as BattleRecord) : undefined;
  }

  /** 按账号读取最近 N 条战斗结束记录（按创建时间倒序） */
  listRecords(uid: string, limit = 50): BattleRecord[] {
    const rows = this.db
      .prepare(
        "SELECT record FROM battle_records WHERE uid = ? ORDER BY created_ts DESC LIMIT ?",
      )
      .all(uid, limit) as { record: string }[];
    return rows.map((r) => JSON.parse(r.record) as BattleRecord);
  }
}
