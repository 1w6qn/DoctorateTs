import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * 信物回收（/activity/recycleCharms）
 *
 * 修复（2026-09-09）：
 * 1. 龙门币（id 4001 / itemType GOLD）余额在 status.gold，不在 inventory ——
 *    原实现写 draft.inventory["4001"]，玩家实际拿不到钱、存档多出幽灵键；
 * 2. 返还额改为数据驱动 CharmTable.charmList[].price（原硬编码 1）。
 */
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));

vi.mock("@excel/excel", () => ({
  default: {
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
    CharmTable: {
      charmList: [
        { id: "level_cost_1", name: "多索雷斯游客章", price: 15 },
        { id: "level_cost_2", name: "徽章", price: 30 },
      ],
    },
  },
}));

import httpContext from "express-http-context2";
import charmRouter from "@game/modules/activities/charm/router";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("信物回收（recycleCharms）", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1", gold: 100 } as any,
      inventory: {} as any,
      charm: { charms: { level_cost_1: 2 }, squad: [] } as any,
      pushFlags: {} as any,
    });
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(body: any) {
    charmRouter({ method: "POST", url: "/recycleCharms", body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 30));
  }

  it("回收信物返还龙门币到 status.gold（按 CharmTable.price），不写 inventory[4001]", async () => {
    await call({ charmIds: ["level_cost_1"] });
    expect((player._playerdata.status as any).gold).toBe(115); // 100 + 15
    expect((player._playerdata.inventory as any)["4001"]).toBeUndefined();
    expect((player._playerdata.charm as any).charms.level_cost_1).toBe(1);
    expect(res.send.mock.calls.at(-1)![0].recycleNum).toBe(1);
  });

  it("多次回收累计返还；未持有/未知信物不返还", async () => {
    await call({ charmIds: ["level_cost_1", "level_cost_1"] });
    // 只持有 2 个 level_cost_1 → 两次均回收（15×2）
    expect((player._playerdata.status as any).gold).toBe(130);
    expect((player._playerdata.charm as any).charms.level_cost_1).toBe(0);
    await call({ charmIds: ["level_cost_1", "unknown_charm"] });
    // 已持有 0 / 未知 id → 均不返还
    expect((player._playerdata.status as any).gold).toBe(130);
    expect(res.send.mock.calls.at(-1)![0].recycleNum).toBe(0);
  });
});
