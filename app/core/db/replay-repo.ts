/**
 * 战斗数据仓储（回放 + 结算信息 + 结束记录）
 *
 * 回放与结算信息独立于用户配置存储（replays / battle_infos / battle_records 表）——
 * 大对象不再塞进 users 表 JSON，避免每次保存配置时全量重写（R4 + A3）。
 *
 * 后端无关：只写 `?` 占位符与公共 SQL，冲突处理经 {@link insertReplaceSql} 按后端生成。
 */
import { insertReplaceSql } from "./dialect";
import type { SqlDatabase } from "./types";
import { now } from "@utils/time";
import type {
  BattleInfo,
  BattleRecord,
} from "@game/kernel/battle-info-store";

export class ReplayRepository {
  /** @param db - 后端无关的数据库句柄 */
  constructor(private _db: SqlDatabase) {}

  /**
   * 获取回放（无则返回空串）
   * @param uid - 账号 uid
   * @param stageId - 关卡 id
   */
  async get(uid: string, stageId: string): Promise<string> {
    const row = await this._db
      .prepare("SELECT replay FROM replays WHERE uid = ? AND stage_id = ?")
      .get<{ replay: string }>(uid, stageId);
    return row?.replay ?? "";
  }

  /**
   * 写入/覆盖回放
   * @param uid - 账号 uid
   * @param stageId - 关卡 id
   * @param replay - 回放数据
   */
  async upsert(uid: string, stageId: string, replay: string): Promise<void> {
    await this._db
      .prepare(
        insertReplaceSql(
          this._db.backend,
          "replays",
          ["uid", "stage_id", "replay", "updated_ts"],
          ["uid", "stage_id"],
        ),
      )
      .run(uid, stageId, replay, now());
  }

  /**
   * 获取战斗结算信息（无则返回 undefined）
   * @param uid - 账号 uid
   * @param battleId - 战斗 id
   */
  async getInfo(uid: string, battleId: string): Promise<BattleInfo | undefined> {
    const row = await this._db
      .prepare("SELECT info FROM battle_infos WHERE uid = ? AND battle_id = ?")
      .get<{ info: string }>(uid, battleId);
    return row ? (JSON.parse(row.info) as BattleInfo) : undefined;
  }

  /**
   * 写入/覆盖战斗结算信息
   * @param uid - 账号 uid
   * @param battleId - 战斗 id
   * @param info - 结算信息
   */
  async upsertInfo(
    uid: string,
    battleId: string,
    info: BattleInfo,
  ): Promise<void> {
    await this._db
      .prepare(
        insertReplaceSql(
          this._db.backend,
          "battle_infos",
          ["uid", "battle_id", "info", "updated_ts"],
          ["uid", "battle_id"],
        ),
      )
      .run(uid, battleId, JSON.stringify(info), now());
  }

  /**
   * 删除账号的战斗数据（B-2：回放 + 结算信息 + 结束记录）
   * @param uid - 账号 uid
   */
  async deleteUser(uid: string): Promise<void> {
    await this._db.prepare("DELETE FROM replays WHERE uid = ?").run(uid);
    await this._db.prepare("DELETE FROM battle_infos WHERE uid = ?").run(uid);
    await this._db.prepare("DELETE FROM battle_records WHERE uid = ?").run(uid);
  }

  /**
   * 留存战斗结束记录（写入/覆盖，供未来分析）
   * @param record - 战斗结束记录
   */
  async saveRecord(record: BattleRecord): Promise<void> {
    await this._db
      .prepare(
        insertReplaceSql(
          this._db.backend,
          "battle_records",
          ["battle_id", "uid", "stage_id", "record", "created_ts"],
          ["battle_id", "uid"],
        ),
      )
      .run(
        record.battleId,
        record.uid,
        record.stageId,
        JSON.stringify(record),
        record.createdTs,
      );
  }

  /**
   * 按账号+战斗 id 读取战斗结束记录（无则 undefined）
   * @param uid - 账号 uid
   * @param battleId - 战斗 id
   */
  async getRecord(
    uid: string,
    battleId: string,
  ): Promise<BattleRecord | undefined> {
    const row = await this._db
      .prepare("SELECT record FROM battle_records WHERE uid = ? AND battle_id = ?")
      .get<{ record: string }>(uid, battleId);
    return row ? (JSON.parse(row.record) as BattleRecord) : undefined;
  }

  /**
   * 按账号读取最近 N 条战斗结束记录（按创建时间倒序）
   * @param uid - 账号 uid
   * @param limit - 最大条数
   */
  async listRecords(uid: string, limit = 50): Promise<BattleRecord[]> {
    const rows = await this._db
      .prepare(
        "SELECT record FROM battle_records WHERE uid = ? ORDER BY created_ts DESC LIMIT ?",
      )
      .all<{ record: string }>(uid, limit);
    return rows.map((r) => JSON.parse(r.record) as BattleRecord);
  }
}
