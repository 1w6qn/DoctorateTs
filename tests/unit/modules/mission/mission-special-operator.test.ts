/**
 * 特勤干员（SPECIAL_OPERATOR）任务单元测试
 *
 * 覆盖：
 * - 18 个 Rlv2* 模板的 init 目标构建与 update 进度推进（含门槛/主题/节点类型过滤）
 * - MissionManager.init 播种 SPECIAL_OPERATOR 任务到玩家数据（幂等）
 * - MissionProgress.init 对 SPECIAL_OPERATOR 类型查 SpecialOperatorTable.nodeUnlockMissionData
 * - confirmMission 对 SPECIAL_OPERATOR 任务标记已领（无奖励）
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// vi.mock 工厂必须使用内联数据（被提升到文件顶部，导入变量尚未初始化）
vi.mock("@excel/excel", () => {
  return {
    default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

      MissionTable: {
        missions: {},
        missionGroups: {},
        periodicalRewards: {},
        weeklyRewards: {},
        dailyMissionGroupInfo: {},
        dailyMissionPeriodInfo: [],
        mainlineMissionEndImageDataList: [],
        crossAppShareMissions: {},
        crossAppShareMissionConst: {},
        guideMissionGroupInfo: {},
      },
      SpecialOperatorTable: {
        // 覆盖全部 18 类 Rlv2* 模板的样例任务（param 取自官服数据）
        nodeUnlockMissionData: {
          t_evolve_1: {
            id: "t_evolve_1",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2PassZoneSpec",
            param: ["1", "rogue_5", "NORMAL", "0", "1", "zone_2"],
            rewards: null,
          },
          t_skill_to7: {
            id: "t_skill_to7",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2PassNodeSpec",
            param: ["1", "rogue_5", "NORMAL", "1", "INCIDENT", "5"],
            rewards: null,
          },
          t_master3_1: {
            id: "t_master3_1",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2CandleTimes",
            param: ["1", "rogue_5", "NORMAL", "1", "5"],
            rewards: null,
          },
          t_master4_1: {
            id: "t_master4_1",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2SpZoneSteps",
            param: ["1", "rogue_5", "NORMAL", "1", "8"],
            rewards: null,
          },
          t_evolve_2: {
            id: "t_evolve_2",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2BandGradeCnt",
            param: ["1", "rogue_5", "2", "1"],
            rewards: null,
          },
          t_skill1_to9: {
            id: "t_skill1_to9",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2EndingBandGradeCnt",
            param: ["1", "rogue_5", "5", "2", "ro5_ending_2"],
            rewards: null,
          },
          t_uniequip1_2: {
            id: "t_uniequip1_2",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2EndingModeGrade",
            param: ["1", "rogue_5", "NORMAL", "9", "ro5_ending_3"],
            rewards: null,
          },
          t_skill1_to10: {
            id: "t_skill1_to10",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2EndingWithBandChar",
            param: [
              "1",
              "rogue_5",
              "NORMAL",
              "7",
              "rogue_5_band_15,rogue_5_band_16",
              "char_4195_radian",
            ],
            rewards: null,
          },
          t_master3_3: {
            id: "t_master3_3",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2EndingWithCharPassSpBattle",
            param: ["1", "rogue_5", "NORMAL", "6", "char_4195_radian", "2", "ro5_ending_1"],
            rewards: null,
          },
          t_master4_3: {
            id: "t_master4_3",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2EndingWithCandleChar",
            param: ["1", "rogue_5", "NORMAL", "6", "char_4195_radian", "6", "ro5_ending_2"],
            rewards: null,
          },
          t_master5_3: {
            id: "t_master5_3",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2EliteBattleWithChar",
            param: ["1", "rogue_5", "NORMAL", "6", "char_4195_radian"],
            rewards: null,
          },
          t_master6_3: {
            id: "t_master6_3",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2StageSimpleEventMore",
            param: ["1", "rogue_5", "NORMAL", "6", "ro5_b_4", "radian_kill_enemy_dylbhm", "1"],
            rewards: null,
          },
          mcnist_t_master1_1: {
            id: "mcnist_t_master1_1",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2RecruitSpecificChar",
            param: ["1", "rogue_6", "char_4230_mcnist", "1"],
            rewards: null,
          },
          mcnist_t_master1_2: {
            id: "mcnist_t_master1_2",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2UpgradeSpecificChar",
            param: ["1", "rogue_6", "char_4230_mcnist", "1"],
            rewards: null,
          },
          mcnist_t_master2_1: {
            id: "mcnist_t_master2_1",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2MeetBandit",
            param: ["1", "rogue_6", "NORMAL", "4", "1"],
            rewards: null,
          },
          mcnist_t_master4_1: {
            id: "mcnist_t_master4_1",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2GainItem",
            param: ["1", "10", "SCRAP"],
            rewards: null,
          },
          mcnist_t_master4_2: {
            id: "mcnist_t_master4_2",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2MoveCostAp",
            param: ["1", "rogue_6", "NORMAL", "0", "40"],
            rewards: null,
          },
          mcnist_t_master4_3: {
            id: "mcnist_t_master4_3",
            type: "SPECIAL_OPERATOR",
            template: "Rlv2ShopRecycle",
            param: ["1", "SCRAP", "10"],
            rewards: null,
          },
        },
      },
      MedalTable: { medalList: [], medalTypeData: {} },
      StageTable: {},
      GachaTable: {},
      GameDataConst: {},
      CharacterTable: {},
      ItemTable: { items: {}, expItems: {} },
      ShopClientTable: {},
      SkillDataBundle: {},
    },
  };
});

vi.mock("@game/kernel/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

vi.mock("@utils/time", () => ({
  now: () => Math.floor(Date.now() / 1000),
  checkBetween: (ts: number, start: number, end: number) =>
    ts >= start && ts <= end,
}));


vi.mock("moment", () => ({
  default: () => ({ diff: () => 0 }),
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../../helpers";
import {
  MissionManager,
  MissionProgress,
  MissionTemplates,
} from "@game/modules/mission/logic";

/** 构造任务进度实例（与既有 mission.test 同款） */
function makeMission(param: string[], value = 0) {
  return { value, param, progress: [] } as any;
}

describe("特勤干员（SPECIAL_OPERATOR）任务模板", () => {
  let mockExcelRef: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockExcelRef = (vi.mocked(await import("@excel/excel")).default as any);
  });

  describe("init 目标构建", () => {
    const cases: { name: string; template: string; param: string[]; target: number }[] = [
      { name: "Rlv2PassZoneSpec", template: "Rlv2PassZoneSpec", param: ["1", "rogue_5", "NORMAL", "0", "1", "zone_2"], target: 1 },
      { name: "Rlv2PassNodeSpec", template: "Rlv2PassNodeSpec", param: ["1", "rogue_5", "NORMAL", "1", "INCIDENT", "5"], target: 5 },
      { name: "Rlv2CandleTimes", template: "Rlv2CandleTimes", param: ["1", "rogue_5", "NORMAL", "1", "5"], target: 5 },
      { name: "Rlv2SpZoneSteps", template: "Rlv2SpZoneSteps", param: ["1", "rogue_5", "NORMAL", "1", "8"], target: 8 },
      { name: "Rlv2BandGradeCnt", template: "Rlv2BandGradeCnt", param: ["1", "rogue_5", "2", "1"], target: 1 },
      { name: "Rlv2EndingBandGradeCnt", template: "Rlv2EndingBandGradeCnt", param: ["1", "rogue_5", "5", "2", "ro5_ending_2"], target: 2 },
      { name: "Rlv2EndingModeGrade", template: "Rlv2EndingModeGrade", param: ["1", "rogue_5", "NORMAL", "9", "ro5_ending_3"], target: 1 },
      { name: "Rlv2EndingWithBandChar", template: "Rlv2EndingWithBandChar", param: ["1", "rogue_5", "NORMAL", "7", "rogue_5_band_15,rogue_5_band_16", "char_4195_radian"], target: 1 },
      { name: "Rlv2EndingWithCharPassSpBattle", template: "Rlv2EndingWithCharPassSpBattle", param: ["1", "rogue_5", "NORMAL", "6", "char_4195_radian", "2", "ro5_ending_1"], target: 1 },
      { name: "Rlv2EndingWithCandleChar", template: "Rlv2EndingWithCandleChar", param: ["1", "rogue_5", "NORMAL", "6", "char_4195_radian", "6", "ro5_ending_2"], target: 1 },
      { name: "Rlv2EliteBattleWithChar", template: "Rlv2EliteBattleWithChar", param: ["1", "rogue_5", "NORMAL", "6", "char_4195_radian"], target: 1 },
      { name: "Rlv2StageSimpleEventMore", template: "Rlv2StageSimpleEventMore", param: ["1", "rogue_5", "NORMAL", "6", "ro5_b_4", "radian_kill_enemy_dylbhm", "1"], target: 1 },
      { name: "Rlv2RecruitSpecificChar", template: "Rlv2RecruitSpecificChar", param: ["1", "rogue_6", "char_4230_mcnist", "1"], target: 1 },
      { name: "Rlv2UpgradeSpecificChar", template: "Rlv2UpgradeSpecificChar", param: ["1", "rogue_6", "char_4230_mcnist", "1"], target: 1 },
      { name: "Rlv2MeetBandit", template: "Rlv2MeetBandit", param: ["1", "rogue_6", "NORMAL", "4", "1"], target: 1 },
      { name: "Rlv2GainItem", template: "Rlv2GainItem", param: ["1", "10", "SCRAP"], target: 10 },
      { name: "Rlv2MoveCostAp", template: "Rlv2MoveCostAp", param: ["1", "rogue_6", "NORMAL", "0", "40"], target: 40 },
      { name: "Rlv2ShopRecycle", template: "Rlv2ShopRecycle", param: ["1", "SCRAP", "10"], target: 10 },
    ];

    for (const c of cases) {
      it(`${c.name} 应构建目标 ${c.target}`, () => {
        const mission = makeMission(c.param);
        MissionTemplates[c.template as keyof typeof MissionTemplates]["1"].init(mission);
        expect(mission.progress[0].value).toBe(0);
        expect(mission.progress[0].target).toBe(c.target);
      });
    }
  });

  describe("Rlv2PassZoneSpec", () => {
    it("到达指定区域且主题/难度门槛匹配应推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "1", "1", "zone_4"]);
      MissionTemplates.Rlv2PassZoneSpec["1"].init(mission);
      MissionTemplates.Rlv2PassZoneSpec["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 1, zoneId: "zone_4",
      });
      expect(mission.progress[0].value).toBe(1);
    });

    it("区域不匹配/主题不匹配/难度不足不应推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "2", "1", "zone_4"]);
      MissionTemplates.Rlv2PassZoneSpec["1"].init(mission);
      MissionTemplates.Rlv2PassZoneSpec["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 2, zoneId: "zone_5",
      });
      expect(mission.progress[0].value).toBe(0);
      MissionTemplates.Rlv2PassZoneSpec["1"].update(mission, {
        theme: "rogue_6", mode: "NORMAL", grade: 2, zoneId: "zone_4",
      });
      expect(mission.progress[0].value).toBe(0);
      MissionTemplates.Rlv2PassZoneSpec["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 1, zoneId: "zone_4",
      });
      expect(mission.progress[0].value).toBe(0);
    });
  });

  describe("Rlv2PassNodeSpec", () => {
    it("通过指定类型节点累计，其他类型不计", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "1", "BATTLE_NORMAL,BATTLE_ELITE,BATTLE_BOSS", "5"]);
      MissionTemplates.Rlv2PassNodeSpec["1"].init(mission);
      MissionTemplates.Rlv2PassNodeSpec["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 1, nodeType: 2,
      });
      expect(mission.progress[0].value).toBe(1);
      MissionTemplates.Rlv2PassNodeSpec["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 1, nodeType: 32,
      });
      expect(mission.progress[0].value).toBe(1);
    });

    it("不期而遇（INCIDENT=32）节点累计", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "1", "INCIDENT", "5"]);
      MissionTemplates.Rlv2PassNodeSpec["1"].init(mission);
      MissionTemplates.Rlv2PassNodeSpec["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 1, nodeType: 32,
      });
      expect(mission.progress[0].value).toBe(1);
    });
  });

  describe("Rlv2BandGradeCnt / EndingBandGradeCnt / EndingModeGrade", () => {
    const bandGrade = {
      band_1: { "2": 1, "3": 2 }, // band_1 达到 grade2/3
      band_2: { "0": 3 }, // band_2 仅 grade0
    };
    const bandCnt = {
      band_1: { ro5_ending_2: 1 },
      band_2: { ro5_ending_1: 2 },
    };

    it("按 grade 门槛统计分队数并取较大值", () => {
      const mission = makeMission(["1", "rogue_5", "2", "2"]);
      MissionTemplates.Rlv2BandGradeCnt["1"].init(mission);
      MissionTemplates.Rlv2BandGradeCnt["1"].update(mission, { theme: "rogue_5", bandGrade });
      // band_1（grade2+ 通关任意结局）计 1；band_2 仅 grade0 不计
      expect(mission.progress[0].value).toBe(1);
    });

    it("指定结局 + grade 门槛统计分队数", () => {
      const mission = makeMission(["1", "rogue_5", "5", "2", "ro5_ending_2"]);
      MissionTemplates.Rlv2EndingBandGradeCnt["1"].init(mission);
      MissionTemplates.Rlv2EndingBandGradeCnt["1"].update(mission, {
        theme: "rogue_5", bandGrade, bandCnt, ending: "ro5_ending_2",
      });
      // band_1 达成 ro5_ending_2 且 grade>=5? bandGrade band_1 最高 3 < 5 → 不计
      expect(mission.progress[0].value).toBe(0);
    });

    it("EndingModeGrade 达成即完成（目标 1）", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "2", "ro5_ending_2"]);
      MissionTemplates.Rlv2EndingModeGrade["1"].init(mission);
      MissionTemplates.Rlv2EndingModeGrade["1"].update(mission, {
        theme: "rogue_5", bandGrade, bandCnt, ending: "ro5_ending_2",
      });
      // band_1 达成 ending_2 且 grade>=2（最高 3）→ 计 1
      expect(mission.progress[0].value).toBe(1);
    });
  });

  describe("Rlv2EndingWithBandChar", () => {
    it("使用指定分队且招募指定干员并通关结局才推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "7", "rogue_5_band_15,rogue_5_band_16", "char_4195_radian"]);
      MissionTemplates.Rlv2EndingWithBandChar["1"].init(mission);
      MissionTemplates.Rlv2EndingWithBandChar["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 7,
        bandId: "rogue_5_band_16", charIds: ["char_4195_radian", "char_1001_amiya"], ending: "ro5_ending_1",
      });
      expect(mission.progress[0].value).toBe(1);
    });

    it("分队不属于列表或未招募指定干员不推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "7", "rogue_5_band_15", "char_4195_radian"]);
      MissionTemplates.Rlv2EndingWithBandChar["1"].init(mission);
      MissionTemplates.Rlv2EndingWithBandChar["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 7,
        bandId: "rogue_5_band_99", charIds: ["char_4195_radian"], ending: "ro5_ending_1",
      });
      expect(mission.progress[0].value).toBe(0);
      MissionTemplates.Rlv2EndingWithBandChar["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 7,
        bandId: "rogue_5_band_15", charIds: ["char_1001_amiya"], ending: "ro5_ending_1",
      });
      expect(mission.progress[0].value).toBe(0);
    });
  });

  describe("Rlv2EndingWithCharPassSpBattle", () => {
    it("招募指定干员、通过足量祸乱节点且达成指定结局才推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "6", "char_4195_radian", "2", "ro5_ending_1"]);
      MissionTemplates.Rlv2EndingWithCharPassSpBattle["1"].init(mission);
      MissionTemplates.Rlv2EndingWithCharPassSpBattle["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 6,
        charIds: ["char_4195_radian"], spBattleCount: 2, ending: "ro5_ending_1",
      });
      expect(mission.progress[0].value).toBe(1);
    });

    it("祸乱节点数不足不推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "6", "char_4195_radian", "2", "ro5_ending_1"]);
      MissionTemplates.Rlv2EndingWithCharPassSpBattle["1"].init(mission);
      MissionTemplates.Rlv2EndingWithCharPassSpBattle["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 6,
        charIds: ["char_4195_radian"], spBattleCount: 1, ending: "ro5_ending_1",
      });
      expect(mission.progress[0].value).toBe(0);
    });
  });

  describe("Rlv2EndingWithCandleChar", () => {
    it("伺烛客数达标才推进（param[5]>0）", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "6", "char_4195_radian", "6", "ro5_ending_2"]);
      MissionTemplates.Rlv2EndingWithCandleChar["1"].init(mission);
      MissionTemplates.Rlv2EndingWithCandleChar["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 6,
        charIds: ["char_4195_radian"], candleCharCount: 6, ending: "ro5_ending_2",
      });
      expect(mission.progress[0].value).toBe(1);
    });

    it("param[5]=0 表示任意伺烛客数", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "10", "char_4195_radian", "0", "ro5_ending_3"]);
      MissionTemplates.Rlv2EndingWithCandleChar["1"].init(mission);
      MissionTemplates.Rlv2EndingWithCandleChar["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 10,
        charIds: ["char_4195_radian"], candleCharCount: 1, ending: "ro5_ending_3",
      });
      expect(mission.progress[0].value).toBe(1);
    });
  });

  describe("Rlv2EliteBattleWithChar", () => {
    it("未通过紧急作战不推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "6", "char_4195_radian"]);
      MissionTemplates.Rlv2EliteBattleWithChar["1"].init(mission);
      MissionTemplates.Rlv2EliteBattleWithChar["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 6,
        charIds: ["char_4195_radian"], eliteCount: 0, ending: "ro5_ending_1",
      });
      expect(mission.progress[0].value).toBe(0);
    });

    it("通过紧急作战且招募指定干员才推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "6", "char_4195_radian"]);
      MissionTemplates.Rlv2EliteBattleWithChar["1"].init(mission);
      MissionTemplates.Rlv2EliteBattleWithChar["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 6,
        charIds: ["char_4195_radian"], eliteCount: 1, ending: "ro5_ending_1",
      });
      expect(mission.progress[0].value).toBe(1);
    });
  });

  describe("Rlv2StageSimpleEventMore", () => {
    it("指定关卡命中事件键才累计（取较大值）", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "6", "ro5_b_4", "radian_kill_enemy_dylbhm", "1"]);
      MissionTemplates.Rlv2StageSimpleEventMore["1"].init(mission);
      MissionTemplates.Rlv2StageSimpleEventMore["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 6, stageId: "ro5_b_4",
        events: { radian_kill_enemy_dylbhm: 2, other: 5 },
      });
      expect(mission.progress[0].value).toBe(1);
      MissionTemplates.Rlv2StageSimpleEventMore["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 6, stageId: "ro5_b_5",
        events: { radian_kill_enemy_dylbhm: 2 },
      });
      // 非指定关卡不计
      expect(mission.progress[0].value).toBe(1);
    });
  });

  describe("Rlv2RecruitSpecificChar / UpgradeSpecificChar", () => {
    it("招募指定干员累计、其他干员不计", () => {
      const mission = makeMission(["1", "rogue_6", "char_4230_mcnist", "3"]);
      MissionTemplates.Rlv2RecruitSpecificChar["1"].init(mission);
      MissionTemplates.Rlv2RecruitSpecificChar["1"].update(mission, {
        theme: "rogue_6", charId: "char_4230_mcnist",
      });
      MissionTemplates.Rlv2RecruitSpecificChar["1"].update(mission, {
        theme: "rogue_6", charId: "char_1001_amiya",
      });
      expect(mission.progress[0].value).toBe(1);
    });

    it("进阶指定干员累计（其他主题不计）", () => {
      const mission = makeMission(["1", "rogue_6", "char_4230_mcnist", "1"]);
      MissionTemplates.Rlv2UpgradeSpecificChar["1"].init(mission);
      MissionTemplates.Rlv2UpgradeSpecificChar["1"].update(mission, {
        theme: "rogue_5", charId: "char_4230_mcnist",
      });
      expect(mission.progress[0].value).toBe(0);
      MissionTemplates.Rlv2UpgradeSpecificChar["1"].update(mission, {
        theme: "rogue_6", charId: "char_4230_mcnist",
      });
      expect(mission.progress[0].value).toBe(1);
    });
  });

  describe("Rlv2MeetBandit", () => {
    it("门槛匹配才推进", () => {
      const mission = makeMission(["1", "rogue_6", "NORMAL", "4", "1"]);
      MissionTemplates.Rlv2MeetBandit["1"].init(mission);
      MissionTemplates.Rlv2MeetBandit["1"].update(mission, {
        theme: "rogue_6", mode: "NORMAL", grade: 3,
      });
      expect(mission.progress[0].value).toBe(0);
      MissionTemplates.Rlv2MeetBandit["1"].update(mission, {
        theme: "rogue_6", mode: "NORMAL", grade: 4,
      });
      expect(mission.progress[0].value).toBe(1);
    });
  });

  describe("Rlv2GainItem / ShopRecycle / MoveCostAp / SpZoneSteps / CandleTimes", () => {
    it("Rlv2GainItem 按数量累计（SCRAP）", () => {
      const mission = makeMission(["1", "10", "SCRAP"]);
      MissionTemplates.Rlv2GainItem["1"].init(mission);
      MissionTemplates.Rlv2GainItem["1"].update(mission, { itemType: "SCRAP", count: 3 });
      expect(mission.progress[0].value).toBe(3);
      MissionTemplates.Rlv2GainItem["1"].update(mission, { itemType: "GOLD", count: 5 });
      expect(mission.progress[0].value).toBe(3);
    });

    it("Rlv2ShopRecycle 按数量累计", () => {
      const mission = makeMission(["1", "SCRAP", "10"]);
      MissionTemplates.Rlv2ShopRecycle["1"].init(mission);
      MissionTemplates.Rlv2ShopRecycle["1"].update(mission, { itemType: "SCRAP", count: 1 });
      expect(mission.progress[0].value).toBe(1);
    });

    it("Rlv2MoveCostAp 按步数累计且主题匹配", () => {
      const mission = makeMission(["1", "rogue_6", "NORMAL", "0", "40"]);
      MissionTemplates.Rlv2MoveCostAp["1"].init(mission);
      MissionTemplates.Rlv2MoveCostAp["1"].update(mission, {
        theme: "rogue_6", mode: "NORMAL", grade: 0, cost: 3,
      });
      expect(mission.progress[0].value).toBe(3);
      MissionTemplates.Rlv2MoveCostAp["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 0, cost: 5,
      });
      expect(mission.progress[0].value).toBe(3);
    });

    it("Rlv2SpZoneSteps 按烛火消耗累计（岁兽残识）", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "1", "8"]);
      MissionTemplates.Rlv2SpZoneSteps["1"].init(mission);
      MissionTemplates.Rlv2SpZoneSteps["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 2, cost: 2,
      });
      expect(mission.progress[0].value).toBe(2);
    });

    it("Rlv2CandleTimes 门槛匹配才推进", () => {
      const mission = makeMission(["1", "rogue_5", "NORMAL", "1", "5"]);
      MissionTemplates.Rlv2CandleTimes["1"].init(mission);
      MissionTemplates.Rlv2CandleTimes["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 0,
      });
      expect(mission.progress[0].value).toBe(0);
      MissionTemplates.Rlv2CandleTimes["1"].update(mission, {
        theme: "rogue_5", mode: "NORMAL", grade: 1,
      });
      expect(mission.progress[0].value).toBe(1);
    });
  });
});

describe("SPECIAL_OPERATOR 播种与 init", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;
  let mockExcelRef: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockExcelRef = (vi.mocked(await import("@excel/excel")).default as any);

    mockPlayer = mockPlayerData({
      mission: {
        missions: {
          DAILY: {},
          WEEKLY: {},
          ACTIVITY: {},
          OPENSERVER: {},
        },
        missionRewards: {
          dailyPoint: 0,
          weeklyPoint: 0,
          rewards: { DAILY: {}, WEEKLY: {} },
        },
        missionGroups: {},
      },
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("MissionManager.init 应播种全部 SPECIAL_OPERATOR 任务到玩家数据", async () => {
    const manager = new MissionManager(mockPlayer as any, mockTrigger as any);
    await manager.init();

    const group =
      mockPlayer._playerdata.mission.missions["SPECIAL_OPERATOR"];
    expect(group).toBeDefined();
    const ids = Object.keys(mockExcelRef.SpecialOperatorTable.nodeUnlockMissionData);
    expect(ids.length).toBeGreaterThan(0);
    for (const id of ids) {
      expect(group[id]).toBeDefined();
      expect(group[id].state).toBe(1);
    }
    // 播种条目的 progress 由模板 init 构建（非空）
    for (const id of ids) {
      expect(Array.isArray(group[id].progress)).toBe(true);
    }
    // 内存列表已构建（含模板监听器）
    expect(manager.missions["SPECIAL_OPERATOR"].length).toBe(ids.length);
  });

  it("MissionManager.init 重复调用不覆盖已有进度（幂等）", async () => {
    const manager = new MissionManager(mockPlayer as any, mockTrigger as any);
    await manager.init();
    // 模拟玩家已推进进度
    mockPlayer._playerdata.mission.missions["SPECIAL_OPERATOR"]["t_evolve_1"].progress[0].value = 1;
    await manager.init();
    expect(
      mockPlayer._playerdata.mission.missions["SPECIAL_OPERATOR"]["t_evolve_1"].progress[0].value
    ).toBe(1);
  });

  it("MissionProgress.init 对 SPECIAL_OPERATOR 类型查 SpecialOperatorTable 并构建进度", async () => {
    // 预播种条目
    mockPlayer._playerdata.mission.missions["SPECIAL_OPERATOR"] = {
      t_evolve_1: { state: 1, progress: [] },
    };
    const mission = new MissionProgress(
      "t_evolve_1",
      "SPECIAL_OPERATOR",
      mockPlayer as any,
    );
    await mission.init();
    expect(mission.valid).toBe(true);
    expect(mission.progress[0].target).toBe(1);
    expect(mission.param).toEqual(["1", "rogue_5", "NORMAL", "0", "1", "zone_2"]);
  });

  it("MissionProgress.init 对未知 SPECIAL_OPERATOR 任务标记无效", async () => {
    mockPlayer._playerdata.mission.missions["SPECIAL_OPERATOR"] = {
      unknown_mission: { state: 1, progress: [] },
    };
    const mission = new MissionProgress(
      "unknown_mission",
      "SPECIAL_OPERATOR",
      mockPlayer as any,
    );
    await mission.init();
    expect(mission.valid).toBe(false);
  });

  it("confirmMission 对 SPECIAL_OPERATOR 任务标记已领且无奖励", async () => {
    mockPlayer._playerdata.mission.missions["SPECIAL_OPERATOR"] = {
      t_evolve_1: { state: 2, progress: [{ value: 1, target: 1 }] },
    };
    const manager = new MissionManager(mockPlayer as any, mockTrigger as any);
    const items = await manager.confirmMission({ missionId: "t_evolve_1" });
    expect(items).toEqual([]);
    expect(
      (mockPlayer._playerdata.mission.missions["SPECIAL_OPERATOR"]["t_evolve_1"] as any).confirmed
    ).toBe(1);
    expect(mockPlayer._playerdata.mission.missions["SPECIAL_OPERATOR"]["t_evolve_1"].state).toBe(3);
  });
});
