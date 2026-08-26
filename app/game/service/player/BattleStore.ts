/**
 * 战斗数据存储（B-1 拆分）
 *
 * 封装回放（replays 表）与结算信息（battle_infos 表）的读写——
 * 大对象独立于用户配置存储，避免每次保存配置时全量重写（R4 + A3）。
 * 由 AccountManager 持有并委托（门面保留原公共方法签名）。
 */
import type { BattleInfo, BattleRecord } from "./BattleInfoStore";
import type { ReplayRepository } from "../../../db/replay-repo";

export class BattleStore {
  constructor(private _replayRepo?: ReplayRepository) {}

  /** 获取战斗回放（无则返回空串） */
  getReplay(uid: string, stageId: string): string {
    return this._replayRepo?.get(uid, stageId) ?? "";
  }

  /** 保存战斗回放 */
  saveReplay(uid: string, stageId: string, replay: string): void {
    this._replayRepo?.upsert(uid, stageId, replay);
  }

  /** 获取战斗结算信息（无则 undefined） */
  getInfo(uid: string, battleId: string): BattleInfo | undefined {
    return this._replayRepo?.getInfo(uid, battleId);
  }

  /** 保存战斗结算信息 */
  saveInfo(uid: string, battleId: string, info: BattleInfo): void {
    this._replayRepo?.upsertInfo(uid, battleId, info);
  }

  /** 留存战斗结束记录 */
  saveRecord(record: BattleRecord): void {
    this._replayRepo?.saveRecord(record);
  }

  /** 读取战斗结束记录（无则 undefined） */
  getRecord(uid: string, battleId: string): BattleRecord | undefined {
    return this._replayRepo?.getRecord(uid, battleId);
  }

  /** 读取最近 N 条战斗结束记录 */
  listRecords(uid: string, limit = 50): BattleRecord[] {
    return this._replayRepo?.listRecords(uid, limit) ?? [];
  }
}
