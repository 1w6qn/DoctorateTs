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

vi.mock("@game/manager/AccountManger", () => ({
  accountManager: {
    getBattleInfo: vi.fn().mockResolvedValue({ stageId: "act6bossrush_01" }),
  },
}));

// 单元测试不跑 excel.init()，只 mock bossRush 结算用到的 StageTable（掉落配置驱动 milestone/token 加值）
vi.mock("@excel/excel", () => ({
  default: {
    StageTable: {
      stages: {
        act6bossrush_01: {
          stageDropInfo: {
            displayDetailRewards: [
              { id: "milestone_point", dropCount: 25 },
              { id: "token_relic", dropCount: 10 },
            ],
          },
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import activityRouter from "../../../app/game/router/activity";
import { mockPlayerData } from "../../helpers";

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
      activity: {
        BOSS_RUSH: {
          act1bossrush: {
            milestone: { point: 100, got: [] },
            relic: {
              token: { current: 20, total: 10 },
              level: { act1bossrush_relic_01: 1 },
              select: "act1bossrush_relic_01",
            },
            best: {},
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

  it("POST /bossRush/battleFinish 应解析 wave 并更新 best/milestone/token", async () => {
    await call("/bossRush/battleFinish", {
      activityId: "act1bossrush",
      data: "fake",
      battleData: { isCheat: "0", completeTime: 100 },
    });
    expect(player.battle.finish).toHaveBeenCalledWith({
      data: "fake",
      battleData: { isCheat: "0", completeTime: 100 },
    });
    // wave 更新 best；掉落配置驱动 milestone/token 加值（milestone_point +25 / token_relic +10）
    const br = player._playerdata.activity.BOSS_RUSH.act1bossrush;
    expect(br.best["act6bossrush_01"]).toBe(3);
    expect(br.milestone.point).toBe(125); // 100 + 25
    expect(br.relic.token.total).toBe(20); // 10 + 10
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

  it("POST /bossRush/relicSelect 应写入 relic.select", async () => {
    await call("/bossRush/relicSelect", {
      activityId: "act1bossrush",
      relicId: "act1bossrush_relic_02",
    });
    expect(
      player._playerdata.activity.BOSS_RUSH.act1bossrush.relic.select
    ).toBe("act1bossrush_relic_02");
    expect(res.send).toHaveBeenCalledWith({ playerDataDelta: {} });
  });

  it("POST /bossRush/relicUpgrade 应等级 +1 并消耗 20 代币", async () => {
    await call("/bossRush/relicUpgrade", {
      activityId: "act1bossrush",
      relicId: "act1bossrush_relic_01",
    });
    const relic = player._playerdata.activity.BOSS_RUSH.act1bossrush.relic;
    expect(relic.level["act1bossrush_relic_01"]).toBe(2);
    expect(relic.token.current).toBe(0); // 20 - 20
    expect(res.send).toHaveBeenCalledWith({ playerDataDelta: {} });
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
