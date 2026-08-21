import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@excel/excel", () => {
  return {
    default: {
      ActivityTable: {
        basicInfo: {
          act5d0: {
            id: "act5d0", type: "TYPE_ACT5D0", name: "火蓝之心·复刻", displayType: "SIDESTORY",
            startTime: 1597132800, endTime: 1597953599, rewardEndTime: 1598299199,
          },
          act6bossrush: {
            id: "act6bossrush", type: "BOSS_RUSH", name: "引航者试炼", displayType: "BOSS_RUSH",
            startTime: 1766692800, endTime: 1767902399, rewardEndTime: 1768161599,
          },
          act1arkhub: {
            id: "act1arkhub", type: "ARK_HUB", name: "奇象巡展", displayType: "ARK_HUB",
            startTime: 1786176000, endTime: 1788465599, rewardEndTime: 1788724799,
          },
          act53side: {
            id: "act53side", type: "TYPE_ACT53SIDE", name: "直到大地变成一颗酸橙",
            startTime: 1785538800, endTime: 1787342399, rewardEndTime: 1787947199,
          },
          // 窗口已过期的 TYPE_ACT 别传：forceOpen 时强制播种；medalGroupId 触发奖章组播种
          act49side: {
            id: "act49side", type: "TYPE_ACT9D0", name: "辞岁行", displayType: "SIDESTORY",
            startTime: 1600000000, endTime: 1610000000, rewardEndTime: 1620000000,
            medalGroupId: "medalGroupActivity49side",
          },
          // 已过期（rewardEndTime 早于测试冻结 ts）
          act_expired: {
            id: "act_expired", type: "TYPE_ACT", name: "过期活动",
            startTime: 1500000000, endTime: 1540000000, rewardEndTime: 1550000000,
          },
          // 未来活动（startTime 晚于冻结 ts）——不应播种
          act_future: {
            id: "act_future", type: "TYPE_ACT", name: "未来活动",
            startTime: 1900000000, endTime: 1900001000, rewardEndTime: 1900001000,
          },
          // null 占位条目（真实数据含 20/331）——播种/修剪必须跳过不崩溃
          __null__: null,
        },
        missionGroup: [
          { id: "act5d0", type: "SANDBOX_PERM", rewards: [], missionIds: ["act5d0_1", "act5d0_2"] },
          { id: "act49side", rewards: [], missionIds: ["49sideActivity_1"] },
        ],
        missionData: [
          { id: "49sideActivity_1", template: "CompleteAnyStage", param: ["0", "act49side_01", "2"], rewards: [] },
        ],
        activity: {
          bOSS_RUSH: {
            act6bossrush: { relicList: [{ relicId: "act6bossrush_relic_01", sortId: 1 }] },
          },
          tYPE_ACT5D0: {},
          tYPE_ACT9D0: {},
          aRK_HUB: {},
          tYPE_ACT53SIDE: {
            act53side: {
              constData: { arkOdcTopicId: "ark_odc_act53side" },
            },
          },
        },
      },
      MedalTable: {
        medalTypeData: {
          activityMedal: {
            groupData: [
              {
                groupId: "medalGroupActivity49side",
                medalId: [
                  "medal_activity_49side_01",
                  "medal_activity_49side_04",
                  "medal_activity_49side_10",
                ],
              },
            ],
          },
        },
        medalList: [
          { medalId: "medal_activity_49side_01", template: null, unlockParam: [] },
          { medalId: "medal_activity_49side_04", template: "PassStageSome", unlockParam: ["3", "act49side_01;act49side_11", "11"] },
          { medalId: "medal_activity_49side_10", template: "PassStageSome", unlockParam: ["3", "act49side_10", "1"], advancedMedal: "medal_activity_49side_105" },
          { medalId: "medal_activity_49side_105", template: "PassStageWithSimpleCountLess", unlockParam: ["3", "act49side_10", "e1;e2;e3;e4", "sui_part_sealed", "2"] },
        ],
      },
      StageTable: {
        stages: {
          main_00_01: { unlockCondition: [] },
          main_00_02: {
            unlockCondition: [{ stageId: "main_00_01", completeState: "COMPLETE" }],
          },
        },
      },
      CharWordTable: {
        startTimeWithTypeDict: {
          "3": [
            { timestamp: 1597132800, charSet: ["char_001", "char_002"] },
            { timestamp: 1777590000, charSet: ["char_4204_mantra"] },
          ],
        },
      },
    },
  };
});

import config from "../../../app/config";
import { mockPlayerData } from "../../helpers";
import { unlockActivity } from "@game/manager/activity/unlockActivity";

describe("unlockActivity（活动播种，DoctoratePy 移植）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  const original = config.developer;

  afterEach(() => {
    config.developer = original;
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mockPlayer = mockPlayerData({
      status: { uid: 1, nickName: "T", nickNumber: 0, level: 1, exp: 0 } as any,
      activity: {
        // 已过期活动条目——冻结播种时应被修剪
        TYPE_ACT5D0: { act_expired: { coin: 1, news: {} } },
        // 未在 basicInfo 的活动——应保持不动
        TYPE_ACT9D0: { act40side: { coin: 131, favorList: [], news: {} } },
      },
      mission: { missions: { ACTIVITY: {} } },
      dungeon: { stages: {} },
    });
  });

  it("真实时间模式（timestamp -1）按当前时间播种窗口内活动 + 修剪过期", async () => {
    config.developer = { timestamp: -1 };
    await unlockActivity(mockPlayer as any);
    // 修复：原真实模式 no-op → 当前窗口活动（奇象巡展 TYPE_ACT53SIDE/ARK_HUB）永不
    // 播种 → 客户端教程卡死；现 userTimestamp()=now()，按窗口播种
    expect(mockPlayer._playerdata.activity?.TYPE_ACT53SIDE?.act53side).toBeDefined();
    expect(mockPlayer._playerdata.activity?.ARK_HUB?.act1arkhub).toBeDefined();
    // 过期活动被修剪（act_expired 窗口已过）
    expect(Object.keys(mockPlayer._playerdata.activity?.TYPE_ACT5D0 ?? {})).toEqual([]);
    // 未在 basicInfo 中的既有条目保持原样
    expect(mockPlayer._playerdata.activity?.TYPE_ACT9D0?.act40side).toEqual({
      coin: 131, favorList: [], news: {},
    });
    // 无条件关卡播种（main_00_01 unlockCondition 为空）
    expect(Object.keys(mockPlayer._playerdata.dungeon?.stages ?? {})).toContain("main_00_01");
  });

  it("冻结到 TYPE_ACT 窗口：播种默认状态 + 任务 + 修剪过期 + 解锁无条件关卡", async () => {
    config.developer = { timestamp: 1597132800 };
    await unlockActivity(mockPlayer as any);

    // TYPE_ACT 默认状态（coin/favorList 来自 charword startTimeWithTypeDict/news）
    expect(mockPlayer._playerdata.activity?.TYPE_ACT5D0?.act5d0).toEqual({
      coin: 0,
      favorList: ["char_001", "char_002"],
      news: {},
    });
    // 活动任务播种（state:2 + value==target，可直接领取）
    const actMissions = mockPlayer._playerdata.mission?.missions?.ACTIVITY ?? {};
    expect(actMissions["act5d0_1"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
    expect(actMissions["act5d0_2"]).toEqual({ state: 2, progress: [{ value: 1, target: 1 }] });
    // 修剪：过期活动被删除；未在 basicInfo 的保留
    expect(mockPlayer._playerdata.activity?.TYPE_ACT5D0?.act_expired).toBeUndefined();
    expect(mockPlayer._playerdata.activity?.TYPE_ACT9D0?.act40side).toBeDefined();
    // 未来活动不播种
    expect(mockPlayer._playerdata.activity?.TYPE_ACT?.act_future).toBeUndefined();
    // 关卡：无条件 main_00_01 解锁；main_00_02 前置未完成不解锁
    expect(mockPlayer._playerdata.dungeon?.stages?.main_00_01).toBeDefined();
    expect(mockPlayer._playerdata.dungeon?.stages?.main_00_02).toBeUndefined();
  });

  it("冻结到 BOSS_RUSH 窗口：播种遗物/里程碑结构", async () => {
    config.developer = { timestamp: 1766692800 };
    await unlockActivity(mockPlayer as any);

    const br = mockPlayer._playerdata.activity?.BOSS_RUSH?.act6bossrush as any;
    expect(br).toBeDefined();
    expect(br.milestone).toEqual({ point: 0, got: [] });
    expect(br.relic.token).toEqual({ current: 0, total: 0 });
    // 默认遗物来自 activity.bOSS_RUSH[id].relicList[0].relicId
    expect(br.relic.unlockedRelicLevelDic).toEqual({ act6bossrush_relic_01: 1 });
    expect(br.relic.selectingRelicId).toBe("");
    expect(br.bestWaveDic).toEqual({});
  });

  it("已有 BOSS_RUSH 条目不覆盖（setdefault 语义）", async () => {
    config.developer = { timestamp: 1766692800 };
    mockPlayer._playerdata.activity!.BOSS_RUSH = {
      act6bossrush: {
        milestone: { point: 50, got: ["act6bossrush_m_1"] },
        relic: {
          token: { current: 10, total: 20 },
          unlockedRelicLevelDic: { act6bossrush_relic_01: 2 },
          selectingRelicId: "act6bossrush_relic_01",
        },
        bestWaveDic: { "1": 3 },
      },
    };
    await unlockActivity(mockPlayer as any);
    expect((mockPlayer._playerdata.activity!.BOSS_RUSH!.act6bossrush as any).milestone.point).toBe(50);
  });

  it("冻结模式：前置关卡完成后联动解锁", async () => {
    config.developer = { timestamp: 1597132800 };
    mockPlayer._playerdata.dungeon!.stages = {
      main_00_01: { stageId: "main_00_01", state: 3, completeTimes: 1, startTimes: 1, practiceTimes: 0, hasBattleReplay: 0, noCostCnt: 1 },
    };
    await unlockActivity(mockPlayer as any);
    expect(mockPlayer._playerdata.dungeon!.stages!.main_00_02).toBeDefined();
  });

  it("冻结到 ARK_HUB 窗口：播种奇象巡展方舟枢纽默认状态", async () => {
    config.developer = { timestamp: 1786176000 };
    await unlockActivity(mockPlayer as any);

    const hub = mockPlayer._playerdata.activity?.ARK_HUB?.act1arkhub as any;
    expect(hub).toBeDefined();
    expect(hub.coin).toBe(0);
    expect(hub.secretary).toBe("");
    expect(hub.secretarySkinId).toBe("");
    expect(hub.protectTs).toBe(-1);
    expect(hub.globalBan).toBe(false);
    // 4 个空队伍槽（客户端展示可用编队位）
    expect(hub.squads).toHaveLength(4);
    expect(hub.squads[0]).toEqual({ slots: [] });
  });

  it("冻结到 TYPE_ACT53SIDE 窗口：播种官方形状（actCoin/campaignCnt/favorList）", async () => {
    config.developer = { timestamp: 1785538800 };
    await unlockActivity(mockPlayer as any);

    const act53 = mockPlayer._playerdata.activity?.TYPE_ACT53SIDE?.act53side as any;
    expect(act53).toBeDefined();
    // 官方形状：actCoin/campaignCnt/favorList（非通用 TYPE_ACT 的 coin/news）
    expect(act53.actCoin).toBe(0);
    expect(act53.campaignCnt).toBe(0);
    expect(Array.isArray(act53.favorList)).toBe(true);
    expect(act53.coin).toBeUndefined();
  });

  it("冻结到 ODC 窗口：播种 arkodc 主题（ODC 地图状态）", async () => {
    config.developer = { timestamp: 1785538800 };
    await unlockActivity(mockPlayer as any);

    const topic = mockPlayer._playerdata.arkodc?.topics?.["ark_odc_act53side"] as any;
    expect(topic).toBeDefined();
    expect(topic.varSeqs).toEqual({});
    expect(topic.rewards).toEqual({});
    expect(topic.position).toEqual({ x: 0, y: 0, z: 0 });
  });

  it("已播种的 ARK_HUB/arkodc 不覆盖（setdefault 语义）", async () => {
    config.developer = { timestamp: 1786176000 };
    mockPlayer._playerdata.activity!.ARK_HUB = {
      act1arkhub: { coin: 25, secretary: "char_1012_skadi2", squads: [] } as any,
    };
    mockPlayer._playerdata.arkodc = {
      topics: {
        ark_odc_act53side: {
          varSeqs: { q001_end: 1 },
          rewards: { q001: 1 },
          position: { x: 1, y: 2, z: 3 },
        },
      },
    };
    await unlockActivity(mockPlayer as any);

    const hub = mockPlayer._playerdata.activity!.ARK_HUB!.act1arkhub as any;
    expect(hub.coin).toBe(25);
    expect(hub.secretary).toBe("char_1012_skadi2");
    const topic = mockPlayer._playerdata.arkodc!.topics!["ark_odc_act53side"] as any;
    expect(topic.varSeqs).toEqual({ q001_end: 1 });
    expect(topic.position).toEqual({ x: 1, y: 2, z: 3 });
  });

  it("教程剧情已提交（flags 标记）但 varSeq bool_end_guide_done 缺失的旧存档——回填为 1", async () => {
    config.developer = { timestamp: 1785538800 };
    // 修复前漏洞存档：finishStory 只写 status.flags，未同步主题 varSeq →
    // logic_game_end_p1 每次进图重放新手教程（无限教程）
    mockPlayer._playerdata.status!.flags = {
      "activities/act53side/ark_odc_act53side_guide": 1,
    };
    mockPlayer._playerdata.arkodc = {
      topics: {
        ark_odc_act53side: {
          varSeqs: { q003_prog: 4, q003_banner_showed: 1 },
          rewards: {},
          position: { x: 0, y: 0, z: 0 },
        },
      },
    };
    await unlockActivity(mockPlayer as any);

    const topic = mockPlayer._playerdata.arkodc!.topics!["ark_odc_act53side"] as any;
    expect(topic.varSeqs.bool_end_guide_done).toBe(1);
    // 其他 varSeq 不被覆盖
    expect(topic.varSeqs.q003_prog).toBe(4);
  });

  it("教程未提交（无 flags 标记）不回填 bool_end_guide_done（保持待触发状态）", async () => {
    config.developer = { timestamp: 1785538800 };
    mockPlayer._playerdata.arkodc = {
      topics: {
        ark_odc_act53side: {
          varSeqs: { q003_prog: 4, q003_banner_showed: 1 },
          rewards: {},
          position: { x: 0, y: 0, z: 0 },
        },
      },
    };
    await unlockActivity(mockPlayer as any);

    const topic = mockPlayer._playerdata.arkodc!.topics!["ark_odc_act53side"] as any;
    expect(topic.varSeqs.bool_end_guide_done).toBeUndefined();
  });

  it("强制开启（forceOpen）播种窗口外 TYPE_ACT 活动 + 泛化播种其奖章组（含进阶章）", async () => {
    config.activities = { ...(config.activities ?? {}), forceOpen: ["act49side"] };
    config.developer = { timestamp: 1786176000 };
    await unlockActivity(mockPlayer as any);

    // TYPE_ACT 通用默认状态（coin/favorList/news）
    expect(mockPlayer._playerdata.activity?.TYPE_ACT9D0?.act49side).toBeDefined();
    expect((mockPlayer._playerdata.activity?.TYPE_ACT9D0?.act49side as any).coin).toBe(0);
    // 活动任务播种（CompleteAnyStage → target 1，value 0 走事件驱动）
    expect(mockPlayer._playerdata.mission?.missions?.ACTIVITY?.["49sideActivity_1"]).toEqual({
      state: 2, progress: [{ value: 0, target: 1 }],
    });
    // 奖章组泛化播种：groupData 内 01/04/10 + advancedMedal 追入的 105（除 act53side 特判外通用）
    const medals = mockPlayer._playerdata.medal?.medals ?? {};
    expect(medals["medal_activity_49side_01"]).toEqual({ id: "medal_activity_49side_01", val: [[0, 0]], fts: 0, rts: -1 });
    expect(medals["medal_activity_49side_04"]).toEqual({ id: "medal_activity_49side_04", val: [[0, 11]], fts: 0, rts: -1 });
    expect(medals["medal_activity_49side_10"]).toEqual({ id: "medal_activity_49side_10", val: [[0, 1]], fts: 0, rts: -1 });
    // 进阶章（advancedMedal 从 medal_activity_49side_10 追入；PassStageWithSimpleCountLess 兜底 target=param[0]）
    expect(medals["medal_activity_49side_105"]).toEqual({ id: "medal_activity_49side_105", val: [[0, 3]], fts: 0, rts: -1 });
  });
});
