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
        },
        missionGroup: [{ id: "act5d0", type: "SANDBOX_PERM", rewards: [], missionIds: ["act5d0_1", "act5d0_2"] }],
        missionData: [],
        activity: {
          bOSS_RUSH: {
            act6bossrush: { relicList: [{ relicId: "act6bossrush_relic_01", sortId: 1 }] },
          },
          tYPE_ACT5D0: {},
        },
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

  it("真实时间模式（timestamp -1）不做任何改动", async () => {
    config.developer = { timestamp: -1 };
    await unlockActivity(mockPlayer as any);
    // 无播种：活动条目原样、无任务、无关卡
    expect(mockPlayer._playerdata.activity?.TYPE_ACT9D0?.act40side).toEqual({
      coin: 131, favorList: [], news: {},
    });
    expect(Object.keys(mockPlayer._playerdata.activity?.TYPE_ACT5D0 ?? {})).toEqual(["act_expired"]);
    expect(mockPlayer._playerdata.mission?.missions?.ACTIVITY).toEqual({});
    expect(Object.keys(mockPlayer._playerdata.dungeon?.stages ?? {})).toHaveLength(0);
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
});
