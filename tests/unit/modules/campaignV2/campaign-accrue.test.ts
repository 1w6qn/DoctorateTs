import { describe, it, expect } from "vitest";
import {
  accrueCampaignKills,
  campaignMaxKills,
  campaignWeeklyBudget,
  claimCampaignBreakRewards,
  claimCampaignMissionReward,
  ensureCampaignsV2State,
  refreshCampaignMissions,
} from "@game/modules/campaignV2/public";
import type {
  BreakLadder,
  CampaignMissionCfg,
  CampaignsV2State,
} from "@game/modules/campaignV2/public";

/**
 * campaignsV2 存档视图
 *
 * `missions`（委托任务达标状态）是服务端扩展字段，存档模型与 `CampaignsV2State` 均未声明
 * （生产侧 accrue.ts 以就地窄化 `{ missions?: Record<string, number> }` 承载）；
 * 本视图与生产侧同源，其余字段仍受 `CampaignsV2State` 约束。
 */
type CampaignsV2View = CampaignsV2State & { missions?: Record<string, number> };

/** 用例草稿视图：夹具总是提供 campaignsV2，故此处收为必填 */
type DraftWithCampaigns = { campaignsV2: CampaignsV2View };

/**
 * 剿灭作战（campaignV2）每周经济单元测试
 *
 * 修复前的行为：battleSweep 固定发 1 合成玉、不校验歼灭记录、无每周上限。
 */
describe("campaignV2 每周经济", () => {
  const TS = 1_788_000_000; // 固定时间戳（2026-09）

  it("ensureCampaignsV2State 应补齐结构并按周重置 currentFee", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: { campaignCurrentFee: 1800, campaignTotalFee: 1800, lastRefreshTs: 1 },
    };
    const root = ensureCampaignsV2State(draft, TS);
    expect(root.campaignTotalFee).toBe(1800);
    expect(root.campaignCurrentFee).toBe(0); // 跨周重置
    expect(root.lastRefreshTs).toBe(TS);
    expect(root.instances).toEqual({});
  });

  it("同一周内不应重复重置", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: { campaignCurrentFee: 300, campaignTotalFee: 1800, lastRefreshTs: TS },
    };
    const root = ensureCampaignsV2State(draft, TS + 60);
    expect(root.campaignCurrentFee).toBe(300);
  });

  it("accrueCampaignKills 应记录 maxKills 并按击杀累计合成玉", () => {
    const draft: DraftWithCampaigns = { campaignsV2: { lastRefreshTs: TS } };
    const first = accrueCampaignKills(draft, "camp_01", 400, TS + 10);
    expect(first.gained).toBe(400);
    expect(first.after).toBe(400);
    expect(campaignMaxKills(draft.campaignsV2, "camp_01")).toBe(400);
    // 第二次击杀更少 → maxKills 不回退，但仍按本次击杀计费
    const second = accrueCampaignKills(draft, "camp_01", 120, TS + 20);
    expect(campaignMaxKills(draft.campaignsV2, "camp_01")).toBe(400);
    expect(second.gained).toBe(120);
    expect(second.after).toBe(520);
  });

  it("每周上限 campaignTotalFee 应封顶（超出部分不发）", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: { campaignCurrentFee: 1700, campaignTotalFee: 1800, lastRefreshTs: TS },
    };
    const r = accrueCampaignKills(draft, "camp_02", 400, TS + 30);
    expect(r.gained).toBe(100); // 仅剩 100 额度
    expect(r.after).toBe(1800);
    // 额度用尽后再打不发
    const r2 = accrueCampaignKills(draft, "camp_02", 400, TS + 40);
    expect(r2.gained).toBe(0);
  });

  it("campaignWeeklyBudget 应给出本周剩余额度", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: { campaignCurrentFee: 1200, campaignTotalFee: 1800, lastRefreshTs: TS },
    };
    const budget = campaignWeeklyBudget(draft, TS + 5);
    expect(budget.before).toBe(1200);
    expect(budget.total).toBe(1800);
    expect(budget.remaining).toBe(600);
  });

  it("无歼灭记录时 campaignMaxKills 返回 0（扫荡据此拒绝发奖）", () => {
    expect(campaignMaxKills({ instances: {} }, "camp_99")).toBe(0);
    expect(campaignMaxKills(undefined, "camp_99")).toBe(0);
  });
});
describe("campaignV2 突破奖励（进度奖励）", () => {
  const TS = Math.floor(Date.now() / 1000);
  const ladders: BreakLadder[] = [
    {
      killCnt: 100,
      breakFeeAdd: 0,
      rewards: [{ id: "4001", count: 4000, type: "GOLD" }],
    },
    {
      killCnt: 200,
      breakFeeAdd: 50,
      rewards: [{ id: "4005", count: 4, type: "LGG_SHD" }],
    },
  ];

  it("未达标档位不可领，达标档位可领并入账", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: {
        campaignCurrentFee: 0,
        campaignTotalFee: 1800,
        lastRefreshTs: TS,
        instances: { camp_01: { maxKills: 150, rewardStatus: [] } },
      },
    };
    const r = claimCampaignBreakRewards(draft, "camp_01", [0, 1], ladders, TS);
    expect(r.claimed).toEqual([0]);
    expect(r.items).toEqual([{ id: "4001", count: 4000, type: "GOLD" }]);
    expect(r.allClaimed).toBe(false);
    expect(draft.campaignsV2.instances!.camp_01!.rewardStatus).toEqual([1, 0]);
  });

  it("一键领取（indexList 为空）应领完所有可领档位并回报 allClaimed", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: {
        campaignCurrentFee: 0,
        campaignTotalFee: 1800,
        lastRefreshTs: TS,
        instances: { camp_01: { maxKills: 400, rewardStatus: [] } },
      },
    };
    const r = claimCampaignBreakRewards(draft, "camp_01", [], ladders, TS);
    expect(r.claimed).toEqual([0, 1]);
    expect(r.allClaimed).toBe(true);
    // breakFeeAdd=50 计入本周进度（额外合成玉）
    expect(r.feeGain).toBe(50);
    expect(draft.campaignsV2.campaignCurrentFee).toBe(50);
  });

  it("重复领取不重复发放（rewardStatus 幂等）", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: {
        campaignCurrentFee: 0,
        campaignTotalFee: 1800,
        lastRefreshTs: TS,
        instances: { camp_01: { maxKills: 400, rewardStatus: [] } },
      },
    };
    claimCampaignBreakRewards(draft, "camp_01", [], ladders, TS);
    const again = claimCampaignBreakRewards(draft, "camp_01", [], ladders, TS);
    expect(again.claimed).toEqual([]);
    expect(again.items).toEqual([]);
    expect(again.feeGain).toBe(0);
    expect(again.allClaimed).toBe(true);
  });

  it("feeAdd 受每周上限约束", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: {
        campaignCurrentFee: 1790,
        campaignTotalFee: 1800,
        lastRefreshTs: TS,
        instances: { camp_01: { maxKills: 400, rewardStatus: [] } },
      },
    };
    const r = claimCampaignBreakRewards(draft, "camp_01", [], ladders, TS);
    expect(r.feeGain).toBe(10); // 仅剩 10 额度
    expect(draft.campaignsV2.campaignCurrentFee).toBe(1800);
  });
});
describe("campaignV2 委托任务（campaignMissions）", () => {
  const TS = Math.floor(Date.now() / 1000);
  const missions: Record<string, CampaignMissionCfg> = {
    exterminateActivity_1: { id: "exterminateActivity_1", param: ["200", "100"], breakFeeAdd: 25 },
    exterminateActivity_2: { id: "exterminateActivity_2", param: ["300", "150"], breakFeeAdd: 25 },
  };

  it("刷新达标：最高单次歼灭数跨委托取最大值，达标任务置 1", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: {
        campaignCurrentFee: 0,
        campaignTotalFee: 1800,
        lastRefreshTs: TS,
        missions: {},
        instances: {
          camp_01: { maxKills: 250, rewardStatus: [] },
          camp_02: { maxKills: 120, rewardStatus: [] },
        },
      },
    };
    const achieved = refreshCampaignMissions(draft, missions, TS);
    expect(achieved).toEqual(["exterminateActivity_1"]); // 250 ≥ 200，但 < 300
    expect(draft.campaignsV2.missions).toEqual({ exterminateActivity_1: 1 });
  });

  it("领取委托奖励：feeAdd 计入本周进度并置 2（不可重复领）", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: {
        campaignCurrentFee: 100,
        campaignTotalFee: 1800,
        lastRefreshTs: TS,
        missions: { exterminateActivity_1: 1 },
        instances: {},
      },
    };
    const r = claimCampaignMissionReward(draft, "exterminateActivity_1", missions, TS);
    expect(r.ok).toBe(true);
    expect(r.feeGain).toBe(25);
    expect(draft.campaignsV2.campaignCurrentFee).toBe(125);
    expect(draft.campaignsV2.missions!.exterminateActivity_1).toBe(2);
    // 重复领取被拒
    const again = claimCampaignMissionReward(draft, "exterminateActivity_1", missions, TS);
    expect(again.ok).toBe(false);
    expect(again.feeGain).toBe(0);
  });

  it("未达标（state=0）不可领取", () => {
    const draft: DraftWithCampaigns = {
      campaignsV2: {
        campaignCurrentFee: 0,
        campaignTotalFee: 1800,
        lastRefreshTs: TS,
        missions: {},
        instances: {},
      },
    };
    const r = claimCampaignMissionReward(draft, "exterminateActivity_2", missions, TS);
    expect(r.ok).toBe(false);
    expect(draft.campaignsV2.missions!.exterminateActivity_2).toBeUndefined();
  });
});