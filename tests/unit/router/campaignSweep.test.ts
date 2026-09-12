import { describe, it, expect, vi } from "vitest";

/** excel mock 行形状（本文件用到的字段子集） */
interface ExcelRowMock {
  name?: string;
}

/** 干员行夹具形状（本文件用到的字段子集） */
interface ExcelCharRowMock {
  charId?: string;
  rarity?: string;
  profession?: string;
}

vi.mock("@excel/excel", () => ({
  default: {
    getItem(id: string): ExcelRowMock | undefined { return this.ItemTable?.items?.[id]; },
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
    ItemTable: { items: {} as Record<string, ExcelRowMock> },
  },
}));
vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import type { Response } from "express";
import campaignRouter from "@game/modules/campaignV2/routes";
import httpContext from "express-http-context2";
import { mockGainItem } from "../../helpers";

/** 剿灭请求体视图（本文件各端点字段合集） */
interface CampaignBody {
  stageId?: string;
  itemId?: string;
  instId?: number;
  indexList?: number[];
  id?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: CampaignBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

/**
 * 剿灭存档夹具视图
 *
 * `campaignV2` 存档子树由本文件的手搓替身承载（不接 helpers 的组合根），
 * 字段面即各用例写入的字段集合。
 */
interface CampaignsV2Fixture {
  campaignCurrentFee?: number;
  campaignTotalFee?: number;
  lastRefreshTs?: number;
  instances?: { [stageId: string]: { maxKills?: number; rewardStatus?: number[] } };
  missions?: { [missionId: string]: number };
}

type RouterReq = Parameters<typeof campaignRouter>[0];

/**
 * 剿灭作战扫荡路由测试
 *
 * 修复前：固定发 1 合成玉、不校验歼灭记录、不扣理智与代理指挥卡（可无限刷）。
 */
describe("campaignV2 battleSweep", () => {
  // 必须落在「当前周」内——否则服务端的跨周重置会把 currentFee 归零（这本身是被测行为之一）
  const TS_WEEK = Math.floor(Date.now() / 1000);

  function mockRes(): MockRes {
    return {
      send: vi.fn<Response["send"]>(),
      status: vi.fn<Response["status"]>().mockReturnThis(),
      sendStatus: vi.fn<Response["sendStatus"]>(),
      json: vi.fn<Response["json"]>(),
    };
  }

  function mockPlayer(campaignsV2: CampaignsV2Fixture) {
    const data = { campaignsV2 };
    return {
      delta: {},
      _playerdata: data,
      _trigger: { emit: vi.fn().mockResolvedValue(undefined) },
      gainItem: mockGainItem(),
      update: vi.fn(async (recipe: (d: typeof data) => void) => {
        const draft = JSON.parse(JSON.stringify(data)) as typeof data;
        const out = await recipe(draft);
        Object.assign(data, draft);
        return out;
      }),
    };
  }

  async function call(req: MockReq, res: MockRes): Promise<MockRes> {
    // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
    campaignRouter(req as RouterReq, res as Response, () => {});
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
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/battleSweep",
        body: { stageId: "camp_01", itemId: "EXTERMINATION_AGENT", instId: 1 },
      },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
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
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      { method: "POST", url: "/campaignV2/battleSweep", body: { stageId: "camp_01" } },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
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
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/battleSweep",
        body: { stageId: "camp_01", itemId: "EXTERMINATION_AGENT", instId: 7 },
      },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.result).toBe(0);
    // 每周剩余 600 → 只发 400（本次歼灭数）
    expect(arg.diamondMaterialRewards).toEqual([
      { type: "DIAMOND_SHD", id: "4003", count: 400 },
    ]);
    expect(arg.currentFeeBefore).toBe(1200);
    expect(arg.currentFeeAfter).toBe(1600);
    // 消耗代理指挥卡 + 扣 20 理智（物品增减已收敛到 player.gainItem 管道）
    expect(player.gainItem.use).toHaveBeenCalled();
    const apAdd = player.gainItem.add.mock.calls.find((c) => c[0].type === "AP_GAMEPLAY");
    expect(apAdd).toBeTruthy();
    expect(apAdd![0].count).toBe(-20);
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
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/getBreakReward",
        body: { stageId: "camp_01", indexList: [] },
      },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.items).toHaveLength(2);
    expect(arg.feeAdd).toBe(50);
    // 奖励与 feeAdd 均经物品管道入账
    expect(player.gainItem.add).toHaveBeenCalled();
    expect(player.gainItem.handle).toHaveBeenCalled();
    // 全部领完 → CompleteBreakReward（guide_60）+ CampaignsComplete（蚀刻章）
    const calls = player._trigger.emit.mock.calls;
    expect(calls.some((c) => c[0] === "CompleteBreakReward")).toBe(true);
    expect(calls.some((c) => c[0] === "CampaignsComplete")).toBe(true);
    // rewardStatus 落盘
    expect(player._playerdata.campaignsV2.instances!.camp_01.rewardStatus).toEqual([
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
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/getBreakReward",
        body: { stageId: "camp_01", indexList: [1] },
      },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.items).toEqual([]);
    expect(arg.feeAdd).toBe(0);
    const calls = player._trigger.emit.mock.calls;
    expect(calls.some((c) => c[0] === "CompleteBreakReward")).toBe(false);
  });

  it("getExMissionReward：达标任务可领，feeAdd 入账并置已领", async () => {
    const player = mockPlayer({
      campaignCurrentFee: 0,
      campaignTotalFee: 1800,
      lastRefreshTs: TS_WEEK,
      missions: { exterminateActivity_1: 1 },
      instances: {},
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/getExMissionReward",
        body: { id: "exterminateActivity_1" },
      },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.feeAdd).toBe(25);
    expect(player._playerdata.campaignsV2.missions!.exterminateActivity_1).toBe(2);
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
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/getExMissionReward",
        body: { id: "exterminateActivity_1" },
      },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.feeAdd).toBe(0);
    expect(player._playerdata.campaignsV2.missions!.exterminateActivity_1).toBeUndefined();
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
    vi.mocked(httpContext.get).mockReturnValue(player);
    const res = mockRes();
    await call(
      {
        method: "POST",
        url: "/campaignV2/battleSweep",
        body: { stageId: "camp_01", itemId: "EXTERMINATION_AGENT", instId: 7 },
      },
      res,
    );
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.diamondMaterialRewards).toEqual([]);
    expect(arg.currentFeeAfter).toBe(1800);
    // 额度用尽 → 不再发合成玉（扣卡/扣理智仍发生，与官服行为一致）
    const diaAdd = player.gainItem.add.mock.calls.find((c) => c[0].type === "DIAMOND_SHD");
    expect(diaAdd).toBeUndefined();
  });
});
