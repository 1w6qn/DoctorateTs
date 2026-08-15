/**
 * 战斗信息存储接口模块
 *
 * 定义 BattleInfo 数据结构与 BattleInfoStore 存储接口。
 * 独立于 AccountManager，供 PlayerDataManager 通过构造器注入使用，
 * 避免 PlayerDataManager 与 AccountManager 之间的循环依赖。
 */

/**
 * 战斗信息接口
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
 * 战斗信息存储接口
 *
 * 提供战斗结算信息的读取与持久化能力，由 AccountManager 实现并注入。
 * 解耦 PlayerDataManager 对 accountManager 单例的直接依赖。
 */
export interface BattleInfoStore {
  /**
   * 获取战斗结算信息
   * 调用方约定：传入的 battleId 必须已存在（AccountManager 内部以 `as BattleInfo` 强转非 undefined）。
   */
  getBattleInfo(uid: string, battleId: string): Promise<BattleInfo>;
  /** 保存战斗结算信息 */
  saveBattleInfo(uid: string, battleId: string, info: BattleInfo): Promise<void>;
}