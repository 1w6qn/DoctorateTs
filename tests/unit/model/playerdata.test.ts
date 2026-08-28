import { describe, it, expect } from 'vitest';
import type {
  PlayerDataModel,
  PlayerStatus,
  PlayerBirthday,
  PlayerDungeon,
  PlayerStage,
  PlayerHiddenStage,
  PlayerSpecialStage,
  PlayerEquipment,
  PlayerEquipMission,
  PlayerSkins,
  PlayerGacha,
  PlayerGachaPool,
  PlayerNewbeeGachaPool,
  PlayerFreeLimitGacha,
  PlayerAttainGacha,
  PlayerSingleGacha,
  PlayerFesClassicGacha,
  PlayerConsumableItem,
  PlayerDataShop,
  PlayerSocial,
  PlayerBuilding,
  PlayerBuildingStatus,
  MissionPlayerData,
  MissionPlayerState,
  BaseProgress,
  PlayerCheckIn,
  PlayerOpenServer,
  PlayerMedal,
  PlayerMedalCustom,
  PlayerMainlineRecord,
  PlayerAvatar,
  PlayerSetting,
  PlayerSettingPerf,
  PlayerPushFlags,
} from '@game/kernel/playerdata';
import { mockPlayerData } from '../../helpers/mockPlayerData';

describe('PlayerDataModel 模型', () => {
  describe('PlayerDataModel 整体结构', () => {
    it('应包含所有必需的顶级模块', () => {
      const model: PlayerDataModel = {
        dungeon: { stages: {}, cowLevel: {}, hideStages: {}, mainlineBannedStages: [] },
        activity: {} as any,
        status: createMinimalStatus(),
        troop: {
          curCharInstId: 0,
          curSquadCount: 0,
          squads: {},
          chars: {},
          addon: {},
          charGroup: {},
          charMission: {},
        },
        npcAudio: {},
        pushFlags: {
          hasGifts: 0,
          hasFriendRequest: 0,
          hasClues: 0,
          hasFreeLevelGP: 0,
          status: 0,
        },
        equipment: { missions: {} },
        skin: { characterSkins: {}, skinTs: {} },
        shop: { LS: {} as any, HS: {} as any, ES: {} as any, CASH: {} as any, GP: {} as any, FURNI: {} as any, SOCIAL: {} as any, EPGS: {} as any, REP: {} as any, CLASSIC: {} as any },
        mission: { missions: {}, missionRewards: {}, missionGroups: {} },
        social: { assistCharList: [], yesterdayReward: {}, yCrisisSs: '', medalBoard: {}, yCrisisV2Ss: '' },
        building: createMinimalBuilding(),
        dexNav: { character: {}, formula: { shop: {}, manufacture: {}, workshop: {} }, enemy: { enemies: {}, stage: {} }, teamV2: {} },
        crisis: {} as any,
        crisisV2: {} as any,
        nameCardStyle: { componentOrder: [], skin: { selected: '', state: {} }, misc: { showDetail: false, showBirthday: false } },
        tshop: {},
        gacha: createMinimalGacha(),
        backflow: { open: false, current: null },
        mainline: { record: {}, cache: [], version: 0, additionalMission: {}, charVoiceRecord: {}, explore: { game: null, outer: { isOpen: false, lastGameResult: { groupId: '', groupCode: '', heritageAbilities: {} }, historyPaths: [], mission: {} } } },
        avatar: { avatar_icon: {} },
        background: { selected: '', bgs: {} },
        homeTheme: { selected: '', themes: {} },
        rlv2: null,
        deepSea: { places: {}, nodes: {}, choices: {}, events: {}, treasures: {}, stories: {}, techTrees: {}, logs: {} },
        tower: { current: {} as any, outer: {} as any, season: {} as any },
        siracusaMap: { select: null, card: {}, opera: { total: 0, show: null, release: {}, like: {} }, area: {} },
        sandboxPerm: null,
        storyreview: { groups: {}, tags: {} },
        medal: { medals: {}, custom: { currentIndex: '', customs: {} } },
        event: { building: 0 },
        retro: { coin: 0, supplement: 0, block: {}, lst: 0, nst: 0, trail: {}, rewardPerm: [] },
        share: { shareMissions: {} },
        roguelike: { current: null, stable: null },
        ticket: {},
        aprilFool: { act3fun: { stages: {} }, act4fun: { stages: {}, liveEndings: {}, cameraLv: 0, fans: 0, posts: 0, missions: {} }, act5fun: { stageState: {}, highScore: 0 } },
        consumable: {},
        charm: { charms: {}, squad: [] },
        carousel: { furnitureShop: { goods: {}, groups: {} } },
        openServer: { checkIn: { isAvailable: false, history: [] }, chainLogin: { isAvailable: false, nowIndex: 0, history: [] } },
        car: { battleCar: {} as any, exhibitionCar: {} as any, accessories: {} },
        recruit: { normal: { slots: {} } },
        templateTrap: { domains: {} },
        checkIn: { canCheckIn: 0, checkInGroupId: '', checkInRewardIndex: 0, checkInHistory: [], newbiePackage: { open: false, groupId: '', finish: 0, stopSale: 0, checkInHistory: [] } },
        inventory: {},
        campaignsV2: { campaignCurrentFee: 0, campaignTotalFee: 0, lastRefreshTs: 0, instances: {}, open: { permanent: [], rotate: '', rGroup: '', training: [], tGroup: '', tAllOpen: '' }, missions: {}, sweepMaxKills: {} },
        setting: { perf: { lowPower: 0 } },
        checkMeta: { version: 1, ts: 1700000000 },
        limitedBuff: { dailyUsage: {}, inventory: {} },
        collectionReward: { team: {} },
        trainingGround: { stages: {} },
        charRotation: { current: '', preset: {} },
      };

      expect(model.status.uid).toBeDefined();
      expect(model.dungeon).toBeDefined();
      expect(model.gacha).toBeDefined();
      expect(model.building).toBeDefined();
      expect(model.checkMeta.version).toBe(1);
    });
  });

  describe('PlayerStatus', () => {
    it('玩家状态应包含等级、经验、理智值等核心属性', () => {
      const status: PlayerStatus = {
        ...createMinimalStatus(),
        level: 120,
        exp: 50000,
        socialPoint: 30,
        gachaTicket: 5,
        tenGachaTicket: 2,
        instantFinishTicket: 10,
        hggShard: 0,
        lggShard: 0,
        recruitLicense: 3,
        progress: 80,
        buyApRemainTimes: 1,
        apLimitUpFlag: 0,
        flags: { flag_1: 1 },
        ap: 135,
        maxAp: 135,
        androidDiamond: 5000,
        iosDiamond: 0,
        diamondShard: 0,
        gold: 10000,
        practiceTicket: 3,
        lastRefreshTs: 1700000000,
        lastApAddTime: 1700000000,
        mainStageProgress: 'stage_05-10',
        registerTs: 1600000000,
        lastOnlineTs: 1700000000,
        serverName: 'Server CN',
        avatarId: 'avatar_001',
        resume: '',
        birthday: { month: 1, day: 15 },
        friendNumLimit: 50,
        monthlySubscriptionStartTime: 1700000000,
        monthlySubscriptionEndTime: 1702500000,
        secretary: 'char_001',
        secretarySkinId: 'skin_001',
        tipMonthlyCardExpireTs: 0,
        avatar: { type: 'frame', id: 'frame_01' },
        globalVoiceLan: 'zh_cn',
        classicShard: 0,
        classicGachaTicket: 0,
        classicTenGachaTicket: 0,
      };

      expect(status.level).toBe(120);
      expect(status.exp).toBe(50000);
      expect(status.ap).toBe(135);
      expect(status.maxAp).toBe(135);
      expect(status.gold).toBe(10000);
      expect(status.diamondShard).toBe(0);
      expect(status.birthday.month).toBe(1);
      expect(status.birthday.day).toBe(15);
      expect(status.mainStageProgress).toBe('stage_05-10');
    });

    it('生日数据应正确表示', () => {
      const birthday: PlayerBirthday = { month: 6, day: 15 };
      expect(birthday.month).toBe(6);
      expect(birthday.day).toBe(15);
    });
  });

  describe('PlayerDungeon', () => {
    it('关卡数据应包含 stage 列表', () => {
      const dungeon: PlayerDungeon = {
        stages: {
          'stage_01-07': {
            stageId: 'stage_01-07',
            completeTimes: 3,
            startTimes: 5,
            practiceTimes: 1,
            state: 3,
            hasBattleReplay: 1,
            noCostCnt: 0,
          },
        },
        cowLevel: {
          cow_01: { id: 'cow_01', type: 'normal', val: [[1, 2], [3, 4]], fts: 0, rts: 0 },
        },
        hideStages: {
          hide_01: { missions: [{ target: 10, value: 5 }], unlock: 1 },
        },
        mainlineBannedStages: ['stage_banned_01'],
      };

      expect(dungeon.stages['stage_01-07'].state).toBe(3);
      expect(dungeon.hideStages.hide_01.unlock).toBe(1);
      expect(dungeon.mainlineBannedStages).toContain('stage_banned_01');
    });
  });

  describe('PlayerStage', () => {
    it('关卡记录应包含通关次数和状态', () => {
      const stage: PlayerStage = {
        stageId: 'stage_02-03',
        completeTimes: 1,
        startTimes: 2,
        practiceTimes: 0,
        state: 3,
        hasBattleReplay: 0,
        noCostCnt: 1,
      };

      expect(stage.stageId).toBe('stage_02-03');
      expect(stage.completeTimes).toBe(1);
      expect(stage.state).toBe(3);
      expect(stage.noCostCnt).toBe(1);
    });
  });

  describe('PlayerHiddenStage', () => {
    it('隐藏关卡应包含任务进度和解锁状态', () => {
      const hidden: PlayerHiddenStage = {
        missions: [
          { target: 100, value: 50 },
          { target: 200, value: 150 },
        ],
        unlock: 1,
      };

      expect(hidden.missions).toHaveLength(2);
      expect(hidden.missions[0].value).toBe(50);
      expect(hidden.unlock).toBe(1);
    });
  });

  describe('PlayerEquipment', () => {
    it('装备数据应包含任务进度', () => {
      const equip: PlayerEquipment = {
        missions: {
          mission_001: { target: 10, value: 5 },
          mission_002: { target: 50, value: 30 },
        },
      };

      expect(equip.missions.mission_001.target).toBe(10);
      expect(equip.missions.mission_002.value).toBe(30);
    });
  });

  describe('PlayerSkins', () => {
    it('皮肤数据应包含已购买皮肤和时间戳', () => {
      const skins: PlayerSkins = {
        characterSkins: { skin_001: 1, skin_002: 1 },
        skinTs: { skin_001: 1700000000 },
      };

      expect(skins.characterSkins.skin_001).toBe(1);
      expect(skins.skinTs.skin_001).toBe(1700000000);
    });
  });

  describe('PlayerGacha', () => {
    it('抽卡系统应包含所有池子类型', () => {
      const gacha: PlayerGacha = {
        newbee: { openFlag: 1, cnt: 0, poolId: 'newbee_pool' },
        normal: {
          normal_pool: { cnt: 50, maxCnt: 100, rarity: 6, avail: true },
        },
        limit: {
          limit_pool: { leastFree: 10, poolCnt: 90, recruitedFreeChar: false },
        },
        linkage: {},
        attain: {
          attain_pool: { attain6Count: 50 },
        },
        single: {
          single_pool: { singleEnsureCnt: 10, singleEnsureUse: false, singleEnsureChar: '' },
        },
        fesClassic: {
          classic_pool: { upChar: { '6_star': ['char_001'] } },
        },
      };

      expect(gacha.newbee.poolId).toBe('newbee_pool');
      expect(gacha.normal.normal_pool.rarity).toBe(6);
      expect(gacha.limit.limit_pool.leastFree).toBe(10);
      expect(gacha.attain.attain_pool.attain6Count).toBe(50);
    });

    it('PlayerNewbeeGachaPool 应有新手指引标记', () => {
      const newbee: PlayerNewbeeGachaPool = {
        openFlag: 1,
        cnt: 1,
        poolId: 'newbee_pool_01',
      };
      expect(newbee.openFlag).toBe(1);
      expect(newbee.cnt).toBe(1);
    });

    it('PlayerGachaPool 应有保底计数', () => {
      const pool: PlayerGachaPool = {
        cnt: 85,
        maxCnt: 100,
        rarity: 6,
        avail: true,
      };
      expect(pool.cnt).toBe(85);
      expect(pool.maxCnt).toBe(100);
      expect(pool.rarity).toBe(6);
    });

    it('PlayerSingleGacha 应有单抽保底', () => {
      const single: PlayerSingleGacha = {
        singleEnsureCnt: 50,
        singleEnsureUse: false,
        singleEnsureChar: '',
      };
      expect(single.singleEnsureCnt).toBe(50);
      expect(single.singleEnsureUse).toBe(false);
    });
  });

  describe('PlayerConsumableItem', () => {
    it('消耗品应包含数量和时间戳', () => {
      const item: PlayerConsumableItem = {
        ts: 1700000000,
        count: 50,
      };
      expect(item.count).toBe(50);
      expect(item.ts).toBe(1700000000);
    });
  });

  describe('PlayerDataShop', () => {
    it('商店数据应包含各类商店', () => {
      const shop: PlayerDataShop = {
        LS: { curShopId: 'ls_01', curGroupId: 'ls_g1', info: [] },
        HS: { curShopId: 'hs_01', info: [], progressInfo: {} },
        ES: { curShopId: 'es_01', info: [], lastClick: 0 },
        CASH: { info: [] },
        GP: { oneTime: { info: [] }, level: { info: [] }, weekly: { curGroupId: '', info: [] }, monthly: { curGroupId: '', info: [] }, choose: { info: [] } },
        FURNI: { info: [], groupInfo: {} },
        SOCIAL: { curShopId: 'social_01', info: [], charPurchase: {} },
        EPGS: { info: [] },
        REP: { info: [] },
        CLASSIC: { info: [], progressInfo: {} },
      };

      expect(shop.LS.curShopId).toBe('ls_01');
      expect(shop.GP.monthly.curGroupId).toBe('');
    });
  });

  describe('PlayerBuilding', () => {
    it('基建数据应包含状态、房间、干员等', () => {
      const building: PlayerBuilding = createMinimalBuilding();
      expect(building.status).toBeDefined();
      expect(building.rooms).toBeDefined();
      expect(building.solution).toBeDefined();
    });
  });

  describe('MissionPlayerData', () => {
    it('任务数据应包含任务进度和奖励', () => {
      const mission: MissionPlayerData = {
        missions: {
          daily: {
            mission_001: { state: 3, progress: [{ target: 1, value: 1 }] },
          },
        },
        missionRewards: {
          dailyPoint: 100,
          weeklyPoint: 500,
          rewards: { reward_001: { item_001: 5 } },
        },
        missionGroups: { group_daily: 1 },
      };

      expect(mission.missions.daily.mission_001.state).toBe(3);
      expect(mission.missionRewards.dailyPoint).toBe(100);
    });
  });

  describe('BaseProgress', () => {
    it('基础进度应包含目标和当前值', () => {
      const progress: BaseProgress = { target: 100, value: 75 };
      expect(progress.target).toBe(100);
      expect(progress.value).toBe(75);
    });

    it('目标可以为 null', () => {
      const progress: BaseProgress = { target: null, value: 50 };
      expect(progress.target).toBeNull();
      expect(progress.value).toBe(50);
    });
  });

  describe('PlayerCheckIn', () => {
    it('签到数据应包含历史和礼包', () => {
      const checkIn: PlayerCheckIn = {
        canCheckIn: 1,
        checkInGroupId: 'checkin_01',
        checkInRewardIndex: 3,
        checkInHistory: [1, 1, 1, 0, 1],
        newbiePackage: {
          open: true,
          groupId: 'newbie_01',
          finish: 5,
          stopSale: 0,
          checkInHistory: [1, 1, 1, 1, 1],
        },
      };

      expect(checkIn.canCheckIn).toBe(1);
      expect(checkIn.checkInRewardIndex).toBe(3);
      expect(checkIn.newbiePackage.open).toBe(true);
    });
  });

  describe('PlayerOpenServer', () => {
    it('开服活动应包含签到和连续登录', () => {
      const openServer: PlayerOpenServer = {
        checkIn: { isAvailable: true, history: [1, 1, 0] },
        chainLogin: { isAvailable: true, nowIndex: 5, history: [1, 1, 1, 1, 1] },
      };

      expect(openServer.checkIn.isAvailable).toBe(true);
      expect(openServer.chainLogin.nowIndex).toBe(5);
    });
  });

  describe('PlayerMedal', () => {
    it('勋章数据应包含勋章列表和自定义布局', () => {
      const medal: PlayerMedal = {
        medals: {
          medal_001: { id: 'medal_001', val: [[1, 0]], fts: 0, rts: 0 },
        },
        custom: {
          currentIndex: 'layout_01',
          customs: {
            layout_01: {
              layout: [{ id: 'slot_01', pos: [0, 0] }],
            },
          },
        },
      };

      expect(medal.medals.medal_001.id).toBe('medal_001');
      expect(medal.custom.currentIndex).toBe('layout_01');
    });
  });

  describe('PlayerMainlineRecord', () => {
    it('主线记录应包含通关记录和探索数据', () => {
      const mainline: PlayerMainlineRecord = {
        record: { stage_01: 3 },
        cache: [],
        version: 1,
        additionalMission: {},
        charVoiceRecord: {},
        explore: {
          game: null,
          outer: {
            isOpen: false,
            lastGameResult: { groupId: '', groupCode: '', heritageAbilities: {} },
            historyPaths: [],
            mission: {},
          },
        },
      };

      expect(mainline.record.stage_01).toBe(3);
      expect(mainline.version).toBe(1);
    });
  });

  describe('PlayerAvatar', () => {
    it('头像数据应包含解锁的头像块', () => {
      const avatar: PlayerAvatar = {
        avatar_icon: {
          icon_001: { ts: 1700000000, src: 'avatar_source_01' },
        },
      };

      expect(avatar.avatar_icon.icon_001.ts).toBe(1700000000);
      expect(avatar.avatar_icon.icon_001.src).toBe('avatar_source_01');
    });
  });

  describe('PlayerSetting', () => {
    it('设置应包含性能配置', () => {
      const setting: PlayerSetting = {
        perf: { lowPower: 1 },
      };
      expect(setting.perf.lowPower).toBe(1);
    });
  });

  describe('PlayerPushFlags', () => {
    it('推送标记应包含所有标志位', () => {
      const flags: PlayerPushFlags = {
        hasGifts: 1,
        hasFriendRequest: 0,
        hasClues: 1,
        hasFreeLevelGP: 0,
        status: 1,
      };

      expect(flags.hasGifts).toBe(1);
      expect(flags.hasFriendRequest).toBe(0);
      expect(flags.status).toBe(1);
    });
  });

  describe('PlayerSocial', () => {
    it('社交数据应包含协助干员列表', () => {
      const social: PlayerSocial = {
        assistCharList: [],
        yesterdayReward: { canReceive: 0, assistAmount: 0, comfortAmount: 0, first: 0 },
        yCrisisSs: '',
        medalBoard: { type: '', custom: null, template: null, templateMedalList: null },
        yCrisisV2Ss: '',
      };

      expect(social.assistCharList).toHaveLength(0);
      expect(social.yesterdayReward.canReceive).toBe(0);
    });
  });

  describe('mockPlayerData 工具', () => {
    it('应创建带有默认值的玩家数据', () => {
      const mock = mockPlayerData();
      expect(mock._playerdata.status).toBeDefined();
      expect(mock.uid).toBe(10000);
      expect(mock.update).toBeDefined();
      expect(mock.get).toBeDefined();
    });

    it('应接受初始数据覆盖默认值', () => {
      const mock = mockPlayerData({
        status: { uid: 99999, nickName: 'CustomUser', nickNumber: 42, level: 50, exp: 999 } as any,
      });
      expect(mock.uid).toBe(99999);
      expect((mock._playerdata.status as any).nickName).toBe('CustomUser');
    });
  });
});

function createMinimalStatus(): PlayerStatus {
  return {
    nickName: 'TestUser',
    nickNumber: '0001',
    level: 1,
    exp: 0,
    socialPoint: 0,
    gachaTicket: 0,
    tenGachaTicket: 0,
    instantFinishTicket: 0,
    hggShard: 0,
    lggShard: 0,
    recruitLicense: 0,
    progress: 0,
    buyApRemainTimes: 0,
    apLimitUpFlag: 0,
    uid: '10000',
    flags: {},
    ap: 100,
    maxAp: 100,
    androidDiamond: 0,
    iosDiamond: 0,
    diamondShard: 0,
    gold: 0,
    practiceTicket: 0,
    lastRefreshTs: 0,
    lastApAddTime: 0,
    mainStageProgress: null,
    registerTs: 0,
    lastOnlineTs: 0,
    serverName: '',
    avatarId: '',
    resume: '',
    birthday: { month: 1, day: 1 },
    friendNumLimit: 0,
    monthlySubscriptionStartTime: 0,
    monthlySubscriptionEndTime: 0,
    secretary: '',
    secretarySkinId: '',
    tipMonthlyCardExpireTs: 0,
    avatar: { type: '', id: '' },
    globalVoiceLan: '',
    classicShard: 0,
    classicGachaTicket: 0,
    classicTenGachaTicket: 0,
  };
}

function createMinimalGacha(): PlayerGacha {
  return {
    newbee: { openFlag: 0, cnt: 0, poolId: '' },
    normal: {},
    limit: {},
    linkage: {},
    attain: {},
    single: {},
    fesClassic: {},
  };
}

function createMinimalBuilding(): PlayerBuilding {
  return {
    status: { labor: { buffSpeed: 0, processPoint: 0, value: 0, lastUpdateTime: 0, maxValue: 0 }, workshop: { bonusActive: 0, bonus: {} } },
    chars: {},
    roomSlots: {},
    rooms: {} as any,
    furniture: {},
    diyPresetSolutions: {},
    assist: [],
    solution: { furnitureTs: {} },
    music: { selected: '' },
  };
}