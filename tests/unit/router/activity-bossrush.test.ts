import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({
    completeState: 3,
    battleId: "b1",
    battleData: { stats: { extraBattleInfo: { bossrush_finished_wave: 3 } } },
  }),
}));

vi.mock("@game/service/player/AccountManager", () => ({
  accountManager: {
    getBattleInfo: vi.fn().mockResolvedValue({ stageId: "act6bossrush_01" }),
  },
}));

// 单元测试不跑 excel.init()，只 mock 尖灭结算用到的表：
// - StageTable：标准战斗结算（battle.finish 被 mock，不读）
// - ActivityTable.bossRush[actId]：尖灭活动详情（stageDropDataMap 驱动 milestone/token 加值）
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    StageTable: {
      stages: {
        act6bossrush_01: {
          zoneId: "act6bossrush_zone1",
          stageDropInfo: {
            displayDetailRewards: [],
          },
        },
        act6bossrush_02: {
          zoneId: "act6bossrush_zone2",
          stageDropInfo: {
            displayDetailRewards: [],
          },
        },
      },
    },
    ActivityTable: {
      basicInfo: {
        act1bossrush: { id: "act1bossrush", type: "BOSS_RUSH", name: "test" },
      },
      zoneToActivity: {
        act6bossrush_zone1: "act1bossrush",
        act6bossrush_zone2: "other_act", // 不属于 act1bossrush → 归属校验应拒绝
      },
      activity: {
        bossRush: {
          act1bossrush: {
            relicList: [
              { relicId: "act1bossrush_relic_01" },
              { relicId: "act1bossrush_relic_02" },
            ],
            relicLevelInfoDataMap: {
              act1bossrush_relic_01: {
                levelInfos: {
                  1: { needItemCount: 20 },
                  2: { needItemCount: 20 },
                  3: { needItemCount: 20 },
                },
              },
              act1bossrush_relic_02: {
                levelInfos: {
                  1: { needItemCount: 30 },
                  2: { needItemCount: 30 },
                },
              },
            },
            mileStoneList: [
              { mileStoneId: "mileStone_1", mileStoneLvl: 1, needPointCnt: 1000 },
            ],
            stageAdditionDataMap: {
              act6bossrush_01: {
                stageId: "act6bossrush_01",
                stageType: "NORMAL",
                stageGroupId: "act6bossrush_group01",
                teamIdList: ["1"],
              },
              act6bossrush_02: {
                stageId: "act6bossrush_02",
                stageType: "NORMAL",
                stageGroupId: "act6bossrush_group02",
                teamIdList: [],
              },
            },
            teamDataMap: {
              "1": { teamId: "1", teamName: "测试编队" },
            },
            stageDropDataMap: {
              act6bossrush_01: {
                3: {
                  clearWaveCount: 3,
                  displayDetailRewards: [
                    { id: "act1bossrush_milestone_point", dropCount: 25 },
                    { id: "act1bossrush_token_relic", dropCount: 10 },
                  ],
                },
              },
            },
          },
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import activityRouter from "../../../app/game/domain/activity";
import { mockPlayerData } from "../../helpers";
import { BossRushManager } from "../../../app/game/domain/activity/bossRush/bossrush";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("bossRush（尖灭测试）路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" } as any,
      pushFlags: { status: 1234567890 } as any,
      dungeon: {
        stages: {
          act6bossrush_01: {
            stageId: "act6bossrush_01",
            completeTimes: 0,
            startTimes: 0,
            practiceTimes: 0,
            state: 0,
            hasBattleReplay: 0,
            noCostCnt: 1,
          },
        },
      } as any,
      activity: {
        BOSS_RUSH: {
          act1bossrush: {
            milestone: { point: 100, got: [] },
            relic: {
              token: { current: 20, total: 10 },
              unlockedRelicLevelDic: {
                act1bossrush_relic_01: 1,
                act1bossrush_relic_02: 1,
              },
              selectingRelicId: "act1bossrush_relic_01",
            },
            bestWaveDic: {},
          },
        },
      } as any,
    });
    player.battle = {
      start: vi.fn().mockResolvedValue({
        result: 0,
        battleId: "b1",
        apFailReturn: 0,
        isApProtect: 0,
        inApProtectPeriod: false,
        notifyPowerScoreNotEnoughIfFailed: false,
      }),
      finish: vi.fn().mockResolvedValue({
        apFailReturn: 0,
        expScale: 1,
        goldScale: 1,
        rewards: [],
        firstRewards: [],
        unlockStages: [],
        unusualRewards: [],
        additionalRewards: [],
        furnitureRewards: [],
        alert: [],
        suggestFriend: false,
        pryResult: [],
      }),
    };
    // 注入真实 BossRushManager（复用 mock update/_playerdata/battle），校验逻辑走真实现
    player.bossRush = new BossRushManager(player, player._trigger);
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    activityRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /bossRush/battleStart 应复用 battle.start 并透传 squad/assistFriend", async () => {
    const ownSlots = { slots: [{ charInstId: 1, level: 90 }] };
    await call("/bossRush/battleStart", {
      activityId: "act1bossrush",
      stageId: "act6bossrush_01",
      teamId: "1",
      ownSlots,
      assistFriend: null,
    });
    expect(player.battle.start).toHaveBeenCalledWith(
      expect.objectContaining({
        stageId: "act6bossrush_01",
        squad: ownSlots,
        usePracticeTicket: 0,
        assistFriend: null,
      })
    );
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        result: 0,
        battleId: "b1",
        playerDataDelta: {},
      })
    );
  });

  it("POST /bossRush/battleStart 编队不合法（teamId 不在 teamIdList）应返回 result=1", async () => {
    await call("/bossRush/battleStart", {
      activityId: "act1bossrush",
      stageId: "act6bossrush_01",
      teamId: "999",
      ownSlots: { slots: [] },
      assistFriend: null,
    });
    expect(player.battle.start).not.toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 1 })
    );
  });

  it("POST /bossRush/battleStart 进行中互斥：未结算再次开战应返回 result=1", async () => {
    const body = {
      activityId: "act1bossrush",
      stageId: "act6bossrush_01",
      teamId: "1",
      ownSlots: { slots: [] },
      assistFriend: null,
    };
    await call("/bossRush/battleStart", body);
    expect(player.battle.start).toHaveBeenCalledTimes(1);
    // 第二次开战：进行中未结算 → 互斥拒绝
    await call("/bossRush/battleStart", body);
    expect(player.battle.start).toHaveBeenCalledTimes(1); // 未再调用标准 battle.start
    const last = res.send.mock.calls.at(-1)![0];
    expect(last).toMatchObject({ result: 1, playerDataDelta: {} });
  });

  it("POST /bossRush/battleStart 跨活动关卡（zone 归属不符）应返回 result=1", async () => {
    await call("/bossRush/battleStart", {
      activityId: "act1bossrush",
      stageId: "act6bossrush_02", // zone2 归属 other_act ≠ act1bossrush
      teamId: "1",
      ownSlots: { slots: [] },
      assistFriend: null,
    });
    expect(player.battle.start).not.toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 1 })
    );
  });

  it("POST /bossRush/battleFinish 应解析 wave 并更新 bestWaveDic/milestone/token", async () => {
    await call("/bossRush/battleFinish", {
      activityId: "act1bossrush",
      data: "fake",
      battleData: { isCheat: "0", completeTime: 100 },
    });
    expect(player.battle.finish).toHaveBeenCalledWith({
      data: "fake",
      battleData: { isCheat: "0", completeTime: 100 },
    });
    // wave 更新 bestWaveDic；stageDropDataMap 驱动 milestone/token 加值（milestone_point +25 / token_relic +10）
    const br = player._playerdata.activity.BOSS_RUSH.act1bossrush;
    expect(br.bestWaveDic["act6bossrush_01"]).toBe(3);
    expect(br.milestone.point).toBe(125); // 100 + 25
    expect(br.relic.token.total).toBe(20); // 10 + 10
    expect(br.relic.token.current).toBe(30); // 20 + 10
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        wave: 3,
        milestoneBefore: 100,
        milestoneAdd: 25,
        isMilestoneMax: false,
        tokenAdd: 10,
        isTokenMax: false,
        playerDataDelta: {},
      })
    );
  });

  it("POST /bossRush/battleFinish 同一 battleId 重复结算应拒绝（battle.finish 仅一次）", async () => {
    const body = {
      activityId: "act1bossrush",
      data: "fake",
      battleData: { isCheat: "0", completeTime: 100 },
    };
    // 第一次结算成功（未先 battleStart，进行中为空 → 放行）
    await call("/bossRush/battleFinish", body);
    expect(player.battle.finish).toHaveBeenCalledTimes(1);
    const br = player._playerdata.activity.BOSS_RUSH.act1bossrush;
    expect(br.milestone.point).toBe(125); // 已累计
    // 同一 battleId 重复结算 → 防重拒绝，不再调用标准 battle.finish（不重复发奖）
    await call("/bossRush/battleFinish", body);
    expect(player.battle.finish).toHaveBeenCalledTimes(1);
    expect(br.milestone.point).toBe(125); // 未重复累计
    const last = res.send.mock.calls.at(-1)![0];
    expect(last).toMatchObject({ result: 1, playerDataDelta: {} });
  });

  it("POST /bossRush/relicSelect 应写入 selectingRelicId", async () => {
    await call("/bossRush/relicSelect", {
      activityId: "act1bossrush",
      relicId: "act1bossrush_relic_02",
    });
    expect(
      player._playerdata.activity.BOSS_RUSH.act1bossrush.relic.selectingRelicId
    ).toBe("act1bossrush_relic_02");
    expect(res.send).toHaveBeenCalledWith({ playerDataDelta: {} });
  });

  it("POST /bossRush/relicSelect 未解锁遗物应返回 result=1", async () => {
    await call("/bossRush/relicSelect", {
      activityId: "act1bossrush",
      relicId: "act1bossrush_relic_99",
    });
    expect(
      player._playerdata.activity.BOSS_RUSH.act1bossrush.relic.selectingRelicId
    ).toBe("act1bossrush_relic_01"); // 保持原选择
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 1 })
    );
  });

  it("POST /bossRush/relicUpgrade 应等级 +1 并数据驱动消耗 20 代币", async () => {
    await call("/bossRush/relicUpgrade", {
      activityId: "act1bossrush",
      relicId: "act1bossrush_relic_01",
    });
    const relic = player._playerdata.activity.BOSS_RUSH.act1bossrush.relic;
    expect(relic.unlockedRelicLevelDic["act1bossrush_relic_01"]).toBe(2);
    expect(relic.token.current).toBe(0); // 20 - 20
    expect(res.send).toHaveBeenCalledWith({ playerDataDelta: {} });
  });

  it("POST /bossRush/relicUpgrade 代币不足应拒绝升级", async () => {
    await call("/bossRush/relicUpgrade", {
      activityId: "act1bossrush",
      relicId: "act1bossrush_relic_02",
    });
    const relic = player._playerdata.activity.BOSS_RUSH.act1bossrush.relic;
    expect(relic.unlockedRelicLevelDic["act1bossrush_relic_02"]).toBe(1); // 等级不变
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 1 })
    );
  });

  it("POST /activity/rewardMilestone 对 BOSS_RUSH 活动应写入 milestone.got 而非 MILESTONE_ONLY", async () => {
    await call("/rewardMilestone", {
      activityId: "act1bossrush",
      milestoneId: "mileStone_1",
    });
    const activity: any = player._playerdata.activity;
    expect(activity.BOSS_RUSH.act1bossrush.milestone.got).toContain("mileStone_1");
    expect(activity.MILESTONE_ONLY).toBeUndefined();
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ item: [], playerDataDelta: {} })
    );
  });
});
