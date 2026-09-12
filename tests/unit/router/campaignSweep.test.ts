import { describe, it, expect, vi } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string) { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) {
      return type ? { id, count, type } : { id, count };
    },
    StageTable: {
      stages: {
        camp_01: { stageId: "camp_01", stageType: "CAMPAIGN", apCost: 20 },
      },
    },
    CampaignTable: {
      campaignMissions: {
        exterminateActivity_1: {
          id: "exterminateActivity_1",
          param: ["200", "100"],
          breakFeeAdd: 25,
        },
      },
      campaigns: {
        camp_01: {
          stageId: "camp_01",
          breakLadders: [
            {
              killCnt: 100,
              breakFeeAdd: 0,
              rewards: [{ id: "4001", count: 4000, type: "GOLD" }],
            },
            {
              killCnt: 400,
              breakFeeAdd: 50,
              rewards: [{ id: "4005", count: 4, type: "LGG_SHD" }],
            },
          ],
        },
      },
    },
    ItemTable: { items: {} },
  },
}));
vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import campaignRouter from "@game/modules/campaignV2/routes";
import httpContext from "express-http-context2";
import { mockGainItem } from "../../helpers";

/**
 * 剿灭作战扫荡路由测试
 *
 * 修复前：固定发 1 合成玉、不校验歼灭记录、不扣理智与代理指挥卡（可无限刷）。
 */
describe("campaignV2 battleSweep", () => {
  // 必须落在「当前周」内——否则服务端的跨周重置会把 currentFee 归零（这本身是被测行为之一）
  const TS_WEEK = Math.floor(Date.now() / 1000);

  function mockRes() {
    return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
  }

  function mockPlayer(campaignsV2: any) {
    const data: any = { campaignsV2 };
    return {
      delta: {},
      _playerdata: data,
      _trigger: { emit: vi.fn().mockResolvedValue(undefined) },
      gainItem: mockGainItem(),
      update: vi.fn(async (recipe: (d: any) => any) => {
        const draft = JSON.parse(JSON.stringify(data));
        const out = await recipe(draft);
        Object.assign(data, draft);
        return out;
      }),
    };
  }

  async function call(req: any, res: any) {
    campaignRouter(req, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
    return res;
  }

  it("无歼灭记录时应拒绝结算且不发合成玉", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 0,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      instances: {},
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/battleSweep",
        body: { stageId: "camp_01", itemId: "EXTERMINATION_AGENT", instId: 1 },
      },
      res,
    );
    const arg = res.send.mock.calls[0][0];
    expect(arg.result).toBe(1);
    expect(arg.diamondMaterialRewards).toEqual([]);
    // 未消耗代理指挥卡、未扣理智
    expect(player._trigger.emit).not.toHaveBeenCalled();
  });

  it("有歼灭记录但未携带代理指挥卡时应拒绝", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 0,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      instances: { camp_01: { maxKills: 400, rewardStatus: [] } },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    const res = mockRes();
    await call(
      { method: "POST", url: "/campaignV2/battleSweep", body: { stageId: "camp_01" } },
      res,
    );
    const arg = res.send.mock.calls[0][0];
    expect(arg.result).toBe(1);
    expect(player._trigger.emit).not.toHaveBeenCalled();
  });

  it("有记录且携带代理指挥卡时应扣券扣理智并按歼灭数发合成玉", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 1200,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      instances: { camp_01: { maxKills: 400, rewardStatus: [] } },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/battleSweep",
        body: { stageId: "camp_01", itemId: "EXTERMINATION_AGENT", instId: 7 },
      },
      res,
    );
    const arg = res.send.mock.calls[0][0];
    expect(arg.result).toBe(0);
    // 每周剩余 600 → 只发 400（本次歼灭数）
    expect(arg.diamondMaterialRewards).toEqual([
      { type: "DIAMOND_SHD", id: "4003", count: 400 },
    ]);
    expect(arg.currentFeeBefore).toBe(1200);
    expect(arg.currentFeeAfter).toBe(1600);
    // 消耗代理指挥卡 + 扣 20 理智（物品增减已收敛到 player.gainItem 管道）
    expect(player.gainItem.use).toHaveBeenCalled();
    const apAdd = (player.gainItem.add as any).mock.calls.find(
      (c: any[]) => (c[0] as any)?.type === "AP_GAMEPLAY",
    );
    expect(apAdd).toBeTruthy();
    expect((apAdd as any[])[0].count).toBe(-20);
    // currentFee 落盘
    expect(player._playerdata.campaignsV2.campaignCurrentFee).toBe(1600);
  });

  it("getBreakReward：达标档位应发奖并入账 feeAdd，全部领完发任务/勋章事件", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 0,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      instances: { camp_01: { maxKills: 400, rewardStatus: [] } },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/getBreakReward",
        body: { stageId: "camp_01", indexList: [] },
      },
      res,
    );
    const arg = res.send.mock.calls[0][0];
    expect(arg.items).toHaveLength(2);
    expect(arg.feeAdd).toBe(50);
    // 奖励与 feeAdd 均经物品管道入账
    expect(player.gainItem.add).toHaveBeenCalled();
    expect(player.gainItem.handle).toHaveBeenCalled();
    // 全部领完 → CompleteBreakReward（guide_60）+ CampaignsComplete（蚀刻章）
    const calls = player._trigger.emit.mock.calls;
    expect(calls.some((c: any[]) => c[0] === "CompleteBreakReward")).toBe(true);
    expect(calls.some((c: any[]) => c[0] === "CampaignsComplete")).toBe(true);
    // rewardStatus 落盘
    expect(player._playerdata.campaignsV2.instances.camp_01.rewardStatus).toEqual([
      1, 1,
    ]);
  });

  it("getBreakReward：未达标档位不发奖", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 0,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      instances: { camp_01: { maxKills: 120, rewardStatus: [] } },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/getBreakReward",
        body: { stageId: "camp_01", indexList: [1] },
      },
      res,
    );
    const arg = res.send.mock.calls[0][0];
    expect(arg.items).toEqual([]);
    expect(arg.feeAdd).toBe(0);
    const calls = player._trigger.emit.mock.calls;
    expect(calls.some((c: any[]) => c[0] === "CompleteBreakReward")).toBe(false);
  });

  it("getExMissionReward：达标任务可领，feeAdd 入账并置已领", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 0,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      missions: { exterminateActivity_1: 1 },
      instances: {},
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/getExMissionReward",
        body: { id: "exterminateActivity_1" },
      },
      res,
    );
    const arg = res.send.mock.calls[0][0];
    expect(arg.feeAdd).toBe(25);
    expect(player._playerdata.campaignsV2.missions.exterminateActivity_1).toBe(2);
    expect(player.gainItem.add).toHaveBeenCalled();
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("getExMissionReward：未达标任务应拒绝", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 0,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      missions: {},
      instances: {},
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/getExMissionReward",
        body: { id: "exterminateActivity_1" },
      },
      res,
    );
    const arg = res.send.mock.calls[0][0];
    expect(arg.feeAdd).toBe(0);
    expect(player._playerdata.campaignsV2.missions.exterminateActivity_1).toBeUndefined();
    // 未入账任何物品、未派发领域事件
    expect(player.gainItem.add).not.toHaveBeenCalled();
    expect(player._trigger.emit).not.toHaveBeenCalled();
  });

  it("本周额度用尽时不再发放合成玉", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 1800,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      instances: { camp_01: { maxKills: 400, rewardStatus: [] } },
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/battleSweep",
        body: { stageId: "camp_01", itemId: "EXTERMINATION_AGENT", instId: 7 },
      },
      res,
    );
    const arg = res.send.mock.calls[0][0];
    expect(arg.diamondMaterialRewards).toEqual([]);
    expect(arg.currentFeeAfter).toBe(1800);
    // 额度用尽 → 不再发合成玉（扣卡/扣理智仍发生，与官服行为一致）
    const diaAdd = (player.gainItem.add as any).mock.calls.find(
      (c: any[]) => (c[0] as any)?.type === "DIAMOND_SHD",
    );
    expect(diaAdd).toBeUndefined();
  });
});
