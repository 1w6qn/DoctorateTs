import { PlayerSquad, SquadFriendData } from "../model/character";

type ListCounterPool<T> = { Key: T; Value: number }[];
export interface BattleData {
  battleId: string;
  interrupt: number;
  giveUp: number;
  percent: number;
  completeState: number;
  killCnt: number;
  validKillCnt: number;
  battleData: BattleLogger;
  currentIndex: number;
  platform: number;
}

export interface BattleLogger {
  stats: BattleStats;
  isCheat: string;
  completeTime: number;
}

export interface BattleStats {
  killedEnemiesCnt: number;
  unnatrualRecoveredCost: number;
  charStats: object[];
  enemyStats: ListCounterPool<BattleStats.EnemyStatKey>;
  skillTrigStats: object[];
  charAdvancedStats: object;
  enemyAdvancedStats: object;
  runeAdvancedStats: object[];
  rlBuffAdvancedStats: object[];
  extraBattleInfoStats: object;
  extraBattleInfoSubStats: object[];
  charList: object;
  enemyList: { [key: string]: number[][] };
  runeList: object[];
  rlBuffList: object[];
  beginTs: number;
  endTs: number;
  access: string;
  hash: string;
  packageName: string;
  checkKilledCnt: number;
  leftHp: number;
  totalHeal: number;
  totalDamage: number;
  fixedPlayTime: number;
  extraInfo: { [key: string]: string };
  extraBattleInfo: { [key: string]: number };
  clientAntiCheatLog: object;
  idList: object[];
  packedRuneDataList: null;
  autoReplayCancelled: number;
}

export namespace BattleStats {
  export interface EnemyStatKey {
    enemyId: string;
    counterType: string;
    isInvalidKilled: number;
  }
}
export interface CommonStartBattleRequest {
  isRetro: number;
  pray: number;
  battleType: number;
  continuous: {
    battleTimes: number;
  };
  usePracticeTicket: number;
  stageId: string;
  squad: PlayerSquad;
  assistFriend: null | SquadFriendData;
  isReplay: number;
  startTs: number;
}
