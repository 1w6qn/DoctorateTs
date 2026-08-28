/**
 * 战斗信息存储接口模块
 *
 * 定义 BattleInfo / BattleRecord 数据结构与 BattleInfoStore 存储接口。
 * 独立于 AccountManager，供 PlayerDataManager 通过构造器注入使用，
 * 避免 PlayerDataManager 与 AccountManager 之间的循环依赖。
 */
import type { ItemBundle } from "@excel/excel";

/**
 * 战斗信息接口（battle_infos 表：结算所需的最小上下文，战斗期间即写入）
 */
export interface BattleInfo {
  stageId: string;
  isPractice: number;
  /** 出战编队（用于结算信赖等后处理） */
  squad?: { slots: ({ charInstId: number } | null)[] };
  /** 助战好友信息（编队借用好友干员） */
  assistFriend?: {
    uid: string;
    nickName: string;
    assistChar: { charId: string; level?: number }[];
    assistSlotIndex: number;
  } | null;
}

/**
 * 战斗来源
 */
export type BattleSource = "quest" | "rlv2";

/**
 * 战斗结束记录（battle_records 表留存数据，供未来分析）
 *
 * 在战斗结算完成后持久化完整的解析结果——相比仅存结算上下文（BattleInfo），
 * 本记录汇聚了战斗统计摘要 + 结算奖励 + 完整遍历统计，用于掉落经济、干员强度、
 * 关卡难度等长期分析，不随会话结束而丢失。
 */
export interface BattleRecord {
  /** 战斗唯一标识（crypto.randomUUID 生成） */
  battleId: string;
  /** 所属账号 uid */
  uid: string;
  /** 关卡 id */
  stageId: string;
  /** 是否演习（1=演习，0=正式结算） */
  isPractice: number;
  /** 战斗来源（游戏内常规战斗 / 肉鸽 rlv2） */
  source: BattleSource;
  /** 结算星级（1=失败，2=通关，3=三星，4=……） */
  completeState: number;
  /** 战斗开始时间戳（秒） */
  beginTs: number;
  /** 战斗结束时间戳（秒） */
  endTs: number;
  /** 击杀数（checkKilledCnt，任务/勋章通用口径） */
  killCnt: number;
  /** 我方造成总伤害 */
  totalDamage: number;
  /** 结算剩余生命（左边血量百分比） */
  leftHp: number;
  /** 我方总治疗量 */
  totalHeal: number;
  /** 有效战斗时长（ms） */
  fixedPlayTime: number;
  /** 参战干员 instId 列表（不含助战） */
  squadInstIds: number[];
  /** 结算奖励摘要（常规+额外+稀有+家具+首通） */
  rewards: ItemBundle[];
  /** 完整战斗统计（BattleStats，含 enemyStats/charStats 等，供深度分析） */
  stats: unknown;
  /** 战报反作弊标识（battleData.isCheat——私服仅留存不校验） */
  isCheat?: string;
  /** 解析后的战斗回放（battleLog 经 decryptBattleReplay 解压，无/解析失败为 undefined） */
  battleLog?: unknown;
  /** 记录创建时间戳（秒） */
  createdTs: number;
}

/**
 * 战斗数据存储接口
 *
 * 提供战斗结算信息（BattleInfo）与战斗结束记录（BattleRecord）的读写能力，
 * 由 AccountManager 实现并注入 PlayerDataManager。解耦对 accountManager 单例的直接依赖。
 */
export interface BattleInfoStore {
  /**
   * 获取战斗结算信息
   * 调用方约定：传入的 battleId 必须已存在（AccountManager 内部以 `as BattleInfo` 强转非 undefined）。
   */
  getBattleInfo(uid: string, battleId: string): Promise<BattleInfo>;
  /** 保存战斗结算信息 */
  saveBattleInfo(uid: string, battleId: string, info: BattleInfo): Promise<void>;
  /** 留存战斗结束记录（battle_records 表，供未来分析） */
  saveBattleRecord(record: BattleRecord): Promise<void>;
  /** 按账号+战斗 id 读取战斗结束记录（无则 undefined） */
  getBattleRecord(uid: string, battleId: string): Promise<BattleRecord | undefined>;
  /** 按账号读取最近 N 条战斗结束记录（limit 缺省 50，按创建时间倒序） */
  listBattleRecords(uid: string, limit?: number): Promise<BattleRecord[]>;
}