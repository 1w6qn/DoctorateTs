export interface BattleData {
    battleId:      string;
    interrupt:     number;
    giveUp:        number;
    percent:       number;
    completeState: number;
    killCnt:       number;
    validKillCnt:  number;
    battleData:    BattleLogger;
    currentIndex:  number;
    platform:      number;
}

export interface BattleLogger {
    stats:        BattleStats;
    isCheat:      string;
    completeTime: number;
}

export interface BattleStats {
    killedEnemiesCnt:        number;
    unnatrualRecoveredCost:  number;
    charStats:               any[];
    enemyStats:              any[];
    skillTrigStats:          any[];
    charAdvancedStats:       {};
    enemyAdvancedStats:      {};
    runeAdvancedStats:       any[];
    rlBuffAdvancedStats:     any[];
    extraBattleInfoStats:    {};
    extraBattleInfoSubStats: any[];
    charList:                {};
    enemyList:               {[key: string]:number[][]};
    runeList:                any[];
    rlBuffList:              any[];
    beginTs:                 number;
    endTs:                   number;
    access:                  string;
    hash:                    string;
    packageName:             string;
    checkKilledCnt:          number;
    leftHp:                  number;
    totalHeal:               number;
    totalDamage:             number;
    fixedPlayTime:           number;
    extraInfo:               { [key: string]: string };
    extraBattleInfo:         {};
    clientAntiCheatLog:      {};
    idList:                  any[];
    packedRuneDataList:      null;
    autoReplayCancelled:     number;
}

