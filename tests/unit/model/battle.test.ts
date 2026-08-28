import { describe, it, expect } from 'vitest';
import type {
  BattleData,
  BattleLogger,
  BattleStats,
  CommonStartBattleRequest,
} from '@game/modules/battle/battle-model';
import type { PlayerSquad, SquadFriendData } from '@game/kernel/model';

describe('Battle 模型', () => {
  describe('BattleData', () => {
    it('应包含战斗基础状态字段', () => {
      const battle: BattleData = {
        battleId: 'battle_001',
        interrupt: 0,
        giveUp: 0,
        percent: 100,
        completeState: 3,
        killCnt: 15,
        validKillCnt: 12,
        battleData: {
          stats: createMinimalBattleStats(),
          isCheat: '0',
          completeTime: 1700000000,
        },
        currentIndex: 10,
        platform: 1,
      };

      expect(battle.battleId).toBe('battle_001');
      expect(battle.interrupt).toBe(0);
      expect(battle.giveUp).toBe(0);
      expect(battle.percent).toBe(100);
      expect(battle.completeState).toBe(3);
      expect(battle.killCnt).toBe(15);
      expect(battle.validKillCnt).toBe(12);
    });

    it('中断状态应为非零值', () => {
      const battle: BattleData = {
        battleId: 'battle_002',
        interrupt: 1,
        giveUp: 0,
        percent: 50,
        completeState: 0,
        killCnt: 5,
        validKillCnt: 3,
        battleData: {
          stats: createMinimalBattleStats(),
          isCheat: '0',
          completeTime: 0,
        },
        currentIndex: 5,
        platform: 1,
      };

      expect(battle.interrupt).toBe(1);
      expect(battle.completeState).toBe(0);
    });

    it('放弃状态应正确反映', () => {
      const battle: BattleData = {
        battleId: 'battle_003',
        interrupt: 0,
        giveUp: 1,
        percent: 20,
        completeState: 0,
        killCnt: 2,
        validKillCnt: 0,
        battleData: {
          stats: createMinimalBattleStats(),
          isCheat: '0',
          completeTime: 0,
        },
        currentIndex: 3,
        platform: 2,
      };

      expect(battle.giveUp).toBe(1);
      expect(battle.validKillCnt).toBe(0);
      expect(battle.platform).toBe(2);
    });

    it('进度百分比应在 0-100 之间', () => {
      const battles: BattleData[] = [0, 25, 50, 75, 100].map((pct, i) => ({
        battleId: `battle_${i}`,
        interrupt: 0,
        giveUp: 0,
        percent: pct,
        completeState: pct === 100 ? 3 : 0,
        killCnt: Math.floor(pct / 10),
        validKillCnt: Math.floor(pct / 15),
        battleData: {
          stats: createMinimalBattleStats(),
          isCheat: '0',
          completeTime: pct === 100 ? 1700000000 : 0,
        },
        currentIndex: i,
        platform: 1,
      }));

      for (const b of battles) {
        expect(b.percent).toBeGreaterThanOrEqual(0);
        expect(b.percent).toBeLessThanOrEqual(100);
      }
    });
  });

  describe('BattleLogger', () => {
    it('应包含统计数据和反作弊字段', () => {
      const logger: BattleLogger = {
        stats: {
          killedEnemiesCnt: 20,
          unnatrualRecoveredCost: 0,
          charStats: [],
          enemyStats: [],
          skillTrigStats: [],
          charAdvancedStats: {},
          enemyAdvancedStats: {},
          runeAdvancedStats: [],
          rlBuffAdvancedStats: [],
          extraBattleInfoStats: {},
          extraBattleInfoSubStats: [],
          charList: {},
          enemyList: {},
          runeList: [],
          rlBuffList: [],
          beginTs: 1700000000,
          endTs: 1700000300,
          access: 'normal',
          hash: 'abc123',
          packageName: 'com.example.game',
          checkKilledCnt: 20,
          leftHp: 5000,
          totalHeal: 300,
          totalDamage: 15000,
          fixedPlayTime: 180,
          extraInfo: { key1: 'val1' },
          extraBattleInfo: { info1: 10 },
          clientAntiCheatLog: {},
          idList: [],
          packedRuneDataList: null,
          autoReplayCancelled: 0,
        },
        isCheat: '0',
        completeTime: 1700000300,
      };

      expect(logger.stats.killedEnemiesCnt).toBe(20);
      expect(logger.stats.totalDamage).toBe(15000);
      expect(logger.stats.leftHp).toBe(5000);
      expect(logger.isCheat).toBe('0');
      expect(logger.completeTime).toBe(1700000300);
    });

    it('应正确记录战斗时间戳', () => {
      const logger: BattleLogger = {
        stats: {
          ...createMinimalBattleStats(),
          beginTs: 1700000000,
          endTs: 1700000600,
          fixedPlayTime: 300,
        },
        isCheat: '0',
        completeTime: 1700000600,
      };

      expect(logger.stats.endTs - logger.stats.beginTs).toBeGreaterThanOrEqual(0);
      expect(logger.stats.fixedPlayTime).toBe(300);
    });
  });

  describe('BattleStats', () => {
    it('应包含完整的战斗统计字段', () => {
      const stats: BattleStats = {
        killedEnemiesCnt: 10,
        unnatrualRecoveredCost: 5,
        charStats: [{ charId: 'c1', dmg: 5000 }],
        enemyStats: [
          { Key: { enemyId: 'e1', counterType: 'melee', isInvalidKilled: 0 }, Value: 3 },
        ],
        skillTrigStats: [{ skillId: 's1', count: 5 }],
        charAdvancedStats: { totalDmg: 10000 },
        enemyAdvancedStats: { totalHp: 50000 },
        runeAdvancedStats: [{ runeId: 'r1', effect: 'atk_up' }],
        rlBuffAdvancedStats: [{ buffId: 'b1', duration: 30 }],
        extraBattleInfoStats: { info: 'test' },
        extraBattleInfoSubStats: [{ key: 'val' }],
        charList: { c1: 1, c2: 2 },
        enemyList: { e1: [[1, 2], [3, 4]] },
        runeList: [{ id: 'r1' }],
        rlBuffList: [{ id: 'b1' }],
        beginTs: 1700000000,
        endTs: 1700000300,
        access: 'normal',
        hash: 'hash_001',
        packageName: 'com.test',
        checkKilledCnt: 10,
        leftHp: 3000,
        totalHeal: 500,
        totalDamage: 8000,
        fixedPlayTime: 180,
        extraInfo: { key: 'value' },
        extraBattleInfo: { stat1: 1 },
        clientAntiCheatLog: {},
        idList: ['id1', 'id2'],
        packedRuneDataList: null,
        autoReplayCancelled: 0,
      };

      expect(stats.killedEnemiesCnt).toBe(10);
      expect(stats.totalDamage).toBe(8000);
      expect(stats.charStats).toHaveLength(1);
      expect(stats.enemyStats).toHaveLength(1);
      expect(stats.enemyStats[0].Key.enemyId).toBe('e1');
      expect(stats.enemyStats[0].Value).toBe(3);
    });

    it('enemyStats 应使用 ListCounterPool 泛型结构', () => {
      const enemyStats: BattleStats.EnemyStatKey[] = [
        { enemyId: 'enemy_001', counterType: 'melee', isInvalidKilled: 0 },
        { enemyId: 'enemy_002', counterType: 'ranged', isInvalidKilled: 1 },
        { enemyId: 'enemy_003', counterType: 'boss', isInvalidKilled: 0 },
      ];

      expect(enemyStats).toHaveLength(3);
      expect(enemyStats[0].counterType).toBe('melee');
      expect(enemyStats[1].isInvalidKilled).toBe(1);
      expect(enemyStats[2].enemyId).toBe('enemy_003');
    });

    it('应支持 null packedRuneDataList', () => {
      const stats: BattleStats = {
        ...createMinimalBattleStats(),
        packedRuneDataList: null,
      };
      expect(stats.packedRuneDataList).toBeNull();
    });
  });

  describe('CommonStartBattleRequest', () => {
    it('应包含开始战斗所需的全部字段', () => {
      const squad: PlayerSquad = {
        squadId: 'squad_001',
        name: 'Alpha',
        slots: [
          { charInstId: 1001, skillIndex: 0, currentEquip: null },
          null,
        ],
      };

      const request: CommonStartBattleRequest = {
        isRetro: 0,
        pray: 0,
        battleType: 1,
        continuous: { battleTimes: 1 },
        usePracticeTicket: 0,
        stageId: 'stage_001',
        squad: squad,
        assistFriend: null,
        isReplay: 0,
        startTs: 1700000000,
      };

      expect(request.isRetro).toBe(0);
      expect(request.battleType).toBe(1);
      expect(request.stageId).toBe('stage_001');
      expect(request.squad.squadId).toBe('squad_001');
      expect(request.continuous.battleTimes).toBe(1);
      expect(request.assistFriend).toBeNull();
    });

    it('应支持协助好友数据', () => {
      const assistFriend: SquadFriendData = {
        nickName: 'Helper',
        uid: 'helper_001',
        serverName: 'CN',
        nickNumber: '0001',
        level: 150,
        lastOnlineTime: new Date(),
        recentVisited: true,
        avatar: { type: 't', id: 'id' },
        assistChar: [
          {
            charId: 'char_helper_01',
            potentialRank: 6,
            mainSkillLvl: 10,
            evolvePhase: 2,
            level: 90,
            favorPoint: 300,
            crisisRecord: {},
            crisisV2Record: {},
          },
        ],
        assistSlotIndex: 0,
      };

      const request: CommonStartBattleRequest = {
        isRetro: 0,
        pray: 0,
        battleType: 1,
        continuous: { battleTimes: 1 },
        usePracticeTicket: 0,
        stageId: 'stage_002',
        squad: {
          squadId: 'squad_002',
          name: 'Bravo',
          slots: [{ charInstId: 2001, skillIndex: 0, currentEquip: null }],
        },
        assistFriend: assistFriend,
        isReplay: 0,
        startTs: 1700000000,
      };

      expect(request.assistFriend).not.toBeNull();
      expect(request.assistFriend!.nickName).toBe('Helper');
      expect(request.assistFriend!.assistChar[0].level).toBe(90);
    });

    it('isReplay 为 1 时表示回放模式', () => {
      const request: CommonStartBattleRequest = {
        isRetro: 0,
        pray: 0,
        battleType: 2,
        continuous: { battleTimes: 1 },
        usePracticeTicket: 0,
        stageId: 'stage_replay',
        squad: {
          squadId: null,
          name: null,
          slots: [],
        },
        assistFriend: null,
        isReplay: 1,
        startTs: 1700000000,
      };

      expect(request.isReplay).toBe(1);
      expect(request.battleType).toBe(2);
    });

    it('连续战斗次数应正确设置', () => {
      const request: CommonStartBattleRequest = {
        isRetro: 0,
        pray: 0,
        battleType: 1,
        continuous: { battleTimes: 4 },
        usePracticeTicket: 0,
        stageId: 'stage_003',
        squad: {
          squadId: 'squad_003',
          name: null,
          slots: [],
        },
        assistFriend: null,
        isReplay: 0,
        startTs: 1700000000,
      };

      expect(request.continuous.battleTimes).toBe(4);
    });
  });

  describe('BattleData 完整性', () => {
    it('完整的战斗数据应能序列化', () => {
      const battle: BattleData = {
        battleId: 'battle_full_001',
        interrupt: 0,
        giveUp: 0,
        percent: 100,
        completeState: 3,
        killCnt: 30,
        validKillCnt: 28,
        battleData: {
          stats: {
            ...createMinimalBattleStats(),
            killedEnemiesCnt: 30,
            checkKilledCnt: 30,
            totalDamage: 25000,
            totalHeal: 800,
            leftHp: 8000,
            endTs: 1700000900,
            fixedPlayTime: 420,
          },
          isCheat: '0',
          completeTime: 1700000900,
        },
        currentIndex: 20,
        platform: 1,
      };

      const json = JSON.stringify(battle);
      const parsed = JSON.parse(json);
      expect(parsed.battleId).toBe('battle_full_001');
      expect(parsed.battleData.stats.totalDamage).toBe(25000);
    });
  });
});

function createMinimalBattleStats(): BattleStats {
  return {
    killedEnemiesCnt: 0,
    unnatrualRecoveredCost: 0,
    charStats: [],
    enemyStats: [],
    skillTrigStats: [],
    charAdvancedStats: {},
    enemyAdvancedStats: {},
    runeAdvancedStats: [],
    rlBuffAdvancedStats: [],
    extraBattleInfoStats: {},
    extraBattleInfoSubStats: [],
    charList: {},
    enemyList: {},
    runeList: [],
    rlBuffList: [],
    beginTs: 0,
    endTs: 0,
    access: '',
    hash: '',
    packageName: '',
    checkKilledCnt: 0,
    leftHp: 0,
    totalHeal: 0,
    totalDamage: 0,
    fixedPlayTime: 0,
    extraInfo: {},
    extraBattleInfo: {},
    clientAntiCheatLog: {},
    idList: [],
    packedRuneDataList: null,
    autoReplayCancelled: 0,
  };
}