import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// 第一档（纯领奖类）最小 excel mock：
// checkinOnly（CHECKIN_ONLY 签到）/ loginOnly（登录奖励）/ switchOnly（开关奖励）/
// checkinVs（签到对决）/ checkinAllPlayer（全服签到）——键用规范小写（activityDictKey 不敏感匹配）
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    ActivityTable: {
      // 活动起始时间表（占位；用例内按需注入 startTime 以启用「天数门槛」）
      basicInfo: {},
      activity: {
        checkinOnly: {
          act60sign: {
            checkInList: {
              "0": {
                itemList: [{ id: "4003", count: 100, type: "DIAMOND_SHD" }],
                order: 1,
                isDynItem: false,
              },
              "1": {
                itemList: [
                  { id: "4003", count: 200, type: "DIAMOND_SHD" },
                  { id: "7001", count: 5, type: "TKT_RECRUIT" },
                ],
                order: 2,
                isDynItem: false,
              },
              "2": {
                itemList: [],
                order: 3,
                isDynItem: true,
              },
            },
            dynCheckInData: {
              dynItemDict: {
                options9: [
                  { id: "furni_MA_mooncake_S_03", count: 1, type: "FURN" },
                  { id: "ap_supply_lt_120_2024_4", count: 1, type: "AP_SUPPLY" },
                ],
              },
            },
          },
        },
        loginOnly: {
          act28login: {
            itemList: [
              { id: "LIMITED_TKT_GACHA_10_7601", count: 1, type: "LIMITED_TKT_GACHA_10" },
            ],
          },
        },
        switchOnly: {
          act9switch: {
            rewards: {
              act9switch_reward_50W: [
                { id: "furni_littlePony_diary_01", count: 1, type: "FURN" },
                { id: "3401", count: 500, type: "MATERIAL" },
              ],
            },
          },
        },
        checkinVs: {
          act4signvs: {
            checkInDict: {
              "1": {
                rewardList: [
                  { id: "ap_supply_lt_120", count: 1, type: "AP_SUPPLY" },
                  { id: "4001", count: 30000, type: "GOLD" },
                ],
                order: 1,
              },
              "2": {
                rewardList: [
                  { id: "4003", count: 200, type: "DIAMOND_SHD" },
                  { id: "7001", count: 5, type: "TKT_RECRUIT" },
                ],
                order: 2,
              },
            },
          },
        },
        checkinAllPlayer: {
          act1checkin: {
            checkInList: {
              "0": {
                itemList: [{ id: "4003", count: 100, type: "DIAMOND_SHD" }],
                order: 1,
              },
              "1": {
                itemList: [
                  { id: "4003", count: 200, type: "DIAMOND_SHD" },
                  { id: "7001", count: 5, type: "TKT_RECRUIT" },
                ],
                order: 2,
              },
            },
          },
        },
      },
    },
  },
}));

import httpContext from "express-http-context2";
import excel from "@excel/excel";
import activityRouter from "@game/modules/activities";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("第一档：纯领奖类活动真实发奖", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    // 活动起始时间表逐用例重置（天数门槛用例会注入 startTime）
    (excel.ActivityTable as any).basicInfo = {};
    player = mockPlayerData({
      status: { uid: "1" } as any,
      activity: {} as any,
    });
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    activityRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("getActivityCheckInReward 应按 index 从 checkInList 发放奖励并标记 history", async () => {
    await call("/getActivityCheckInReward", { activityId: "act60sign", index: 1 });
    const sent = res.send.mock.calls[0][0];
    expect(sent.items).toEqual([
      { id: "4003", count: 200, type: "DIAMOND_SHD" },
      { id: "7001", count: 5, type: "TKT_RECRUIT" },
    ]);
    const act = player._playerdata.activity.CHECKIN_ONLY.act60sign;
    expect(act.history[1]).toBe(0);
    expect(act.lastTs).toBeGreaterThan(0);
  });

  it("getActivityCheckInReward 动态签到日（isDynItem）应按 dynOpt 从 dynItemDict 发放", async () => {
    await call("/getActivityCheckInReward", {
      activityId: "act60sign",
      index: 2,
      dynOpt: "options9",
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.items).toEqual([
      { id: "furni_MA_mooncake_S_03", count: 1, type: "FURN" },
      { id: "ap_supply_lt_120_2024_4", count: 1, type: "AP_SUPPLY" },
    ]);
  });

  it("getActivityCheckInReward 已领取的 index 不再重复发奖", async () => {
    player._playerdata.activity = {
      CHECKIN_ONLY: { act60sign: { lastTs: 123, history: [1, 0] } },
    } as any;
    await call("/getActivityCheckInReward", { activityId: "act60sign", index: 1 });
    const sent = res.send.mock.calls[0][0];
    expect(sent.items).toEqual([]);
  });

  // ===== Round 27：活动签到天数门槛（§5.6-7） =====

  it("getActivityCheckInReward：index 超过已过天数时被拒（原实现可一次领完全部 index）", async () => {
    const excel = (await import("@excel/excel")).default as any;
    const today = Math.floor(Date.now() / 1000);
    excel.ActivityTable.basicInfo = { act60sign: { startTime: today } }; // 活动首日
    await call("/getActivityCheckInReward", { activityId: "act60sign", index: 1 });
    expect(res.send.mock.calls[0][0].items).toEqual([]);
    expect(
      player._playerdata.activity.CHECKIN_ONLY?.act60sign?.history?.[1],
    ).toBeUndefined();
    // 第 0 档（当天）可领
    await call("/getActivityCheckInReward", { activityId: "act60sign", index: 0 });
    expect(res.send.mock.calls[1][0].items).toEqual([
      { id: "4003", count: 100, type: "DIAMOND_SHD" },
    ]);
  });

  it("getActivityCheckInReward：同一自然日只能签到一次（读 lastTs）", async () => {
    const excel = (await import("@excel/excel")).default as any;
    const today = Math.floor(Date.now() / 1000);
    excel.ActivityTable.basicInfo = { act60sign: { startTime: today - 5 * 86400 } };
    await call("/getActivityCheckInReward", { activityId: "act60sign", index: 0 });
    expect(res.send.mock.calls[0][0].items).toHaveLength(1);
    // 同日再签另一档 → 被拒（原实现无 lastTs 校验，可连领）
    await call("/getActivityCheckInReward", { activityId: "act60sign", index: 1 });
    expect(res.send.mock.calls[1][0].items).toEqual([]);
    // 昨日签到过 → 今日可再签
    const act = player._playerdata.activity.CHECKIN_ONLY.act60sign;
    act.lastTs = Math.floor(Date.now() / 1000) - 86400;
    await call("/getActivityCheckInReward", { activityId: "act60sign", index: 1 });
    expect(res.send.mock.calls[2][0].items).toHaveLength(2);
  });

  it("checkinAllPlayer 签到：同样受天数门槛约束", async () => {
    const excel = (await import("@excel/excel")).default as any;
    const today = Math.floor(Date.now() / 1000);
    excel.ActivityTable.basicInfo = { act1checkin: { startTime: today } }; // 活动首日
    // 第 2 档（index 1）尚未到 → 拒绝
    await call("/checkinAllPlayer/getActivityCheckInReward", {
      activityId: "act1checkin",
      index: 1,
    });
    expect(res.send.mock.calls[0][0].items).toEqual([]);
    // 第 1 档（index 0）可领
    await call("/checkinAllPlayer/getActivityCheckInReward", {
      activityId: "act1checkin",
      index: 0,
    });
    expect(res.send.mock.calls[1][0].items).toEqual([
      { id: "4003", count: 100, type: "DIAMOND_SHD" },
    ]);
  });

  it("loginOnly/getReward 应发放 itemList 并标记 LOGIN_ONLY reward 已领", async () => {
    await call("/loginOnly/getReward", { activityId: "act28login" });
    const sent = res.send.mock.calls[0][0];
    expect(sent.reward).toEqual([
      { id: "LIMITED_TKT_GACHA_10_7601", count: 1, type: "LIMITED_TKT_GACHA_10" },
    ]);
    expect(player._playerdata.activity.LOGIN_ONLY.act28login.reward).toBe(0);
  });

  it("getSwitchOnlyReward 应发放 switchOnly.rewards[reward] 并标记已领", async () => {
    await call("/getSwitchOnlyReward", {
      activityId: "act9switch",
      reward: "act9switch_reward_50W",
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.items).toEqual([
      { id: "furni_littlePony_diary_01", count: 1, type: "FURN" },
      { id: "3401", count: 500, type: "MATERIAL" },
    ]);
    expect(player._playerdata.activity.SWITCH_ONLY.act9switch.act9switch_reward_50W).toBe(0);
  });

  it("actCheckinvs/sign 应按已签天数从 checkInDict 发放对应日奖励（非硬编码）", async () => {
    await call("/actCheckinvs/sign", { actId: "act4signvs", tasteChoice: 1 });
    const sent = res.send.mock.calls[0][0];
    expect(sent.items).toEqual([
      { id: "ap_supply_lt_120", count: 1, type: "AP_SUPPLY" },
      { id: "4001", count: 30000, type: "GOLD" },
    ]);
  });

  it("checkinAllPlayer/getActivityCheckInReward 应按 index 发放 checkInList 奖励", async () => {
    await call("/checkinAllPlayer/getActivityCheckInReward", {
      activityId: "act1checkin",
      index: 1,
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.items).toEqual([
      { id: "4003", count: 200, type: "DIAMOND_SHD" },
      { id: "7001", count: 5, type: "TKT_RECRUIT" },
    ]);
  });

  it("checkinAllPlayer/syncBehaviorData 返回空增量（行为统计 TODO）", async () => {
    await call("/checkinAllPlayer/syncBehaviorData", { activityId: "act1checkin" });
    expect(res.send).toHaveBeenCalled();
    expect(res.send.mock.calls[0][0]).toEqual({ playerDataDelta: {} });
  });

  it("checkinAllPlayer/getAllBehaviorReward 返回空 items（行为奖励 TODO）", async () => {
    await call("/checkinAllPlayer/getAllBehaviorReward", { activityId: "act1checkin" });
    const sent = res.send.mock.calls[0][0];
    expect(sent.items).toEqual([]);
  });

  it("excel 无配置时签到/登录/开关/对决均容错返回空奖励（不 500）", async () => {
    await call("/getActivityCheckInReward", { activityId: "act_none", index: 1 });
    expect(res.send.mock.calls[0][0].items).toEqual([]);

    await call("/loginOnly/getReward", { activityId: "act_none" });
    expect(res.send.mock.calls[1][0].reward).toEqual([]);

    await call("/getSwitchOnlyReward", {
      activityId: "act_none",
      reward: "r1",
    });
    expect(res.send.mock.calls[2][0].items).toEqual([]);
  });

  it("excel 无配置时签到对决/全服签到容错返回空奖励（不 500）", async () => {
    await call("/actCheckinvs/sign", { actId: "act_none", tasteChoice: 1 });
    expect(res.send.mock.calls[0][0].items).toEqual([]);

    await call("/checkinAllPlayer/getActivityCheckInReward", {
      activityId: "act_none",
      index: 1,
    });
    expect(res.send.mock.calls[1][0].items).toEqual([]);
  });

  it("prayOnly/loginOnlyUnique/checkinVideo 保留 stub 路由（excel 无数据源，返回空增量不 404）", async () => {
    await call("/prayOnly/getReward", { activityId: "act6pray" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);

    await call("/loginOnlyUnique/getReward", { activityId: "act5unique" });
    expect(res.send.mock.calls[1][0].reward).toEqual([]);

    await call("/getActivityCheckInVideoReward", { activityId: "act3video" });
    expect(res.send.mock.calls[2][0].items).toEqual([]);
  });
});
