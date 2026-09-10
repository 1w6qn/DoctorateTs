import { describe, it, expect, vi } from "vitest";

/**
 * 活动商店兑换（handleExchangeActivityShopItem）
 *
 * 修复（2026-09-09）：count 必须为正整数 —— 原实现 `body.count || 1` 直接透传负数，
 * recordPurchase 的 `existing.count += count` 会把已购数量减回去（甚至变负），
 * 从而绕过活动商店的限购判定再买一轮。
 */
vi.mock("@excel/excel", () => ({
  default: {
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
  },
}));

import { handleExchangeActivityShopItem } from "@game/modules/activities/milestone/logic";
import { mockPlayerData } from "../../../helpers";

function makePlayer(tshop: any = {}) {
  return mockPlayerData({
    tshop,
    pushFlags: {} as any,
  } as any);
}

describe("活动商店兑换 count 校验", () => {
  it("正数 count 正常记录购买", async () => {
    const player = makePlayer({});
    await handleExchangeActivityShopItem(player as any, {
      shopId: "s1",
      goodId: "g1",
      count: 2,
    } as any);
    expect((player._playerdata.tshop as any).s1.info).toEqual([{ id: "g1", count: 2 }]);
  });

  it("负数 count 应拒绝（不写购买记录）", async () => {
    const player = makePlayer({
      s1: { coin: 0, info: [{ id: "g1", count: 3 }], progressInfo: {} },
    });
    await handleExchangeActivityShopItem(player as any, {
      shopId: "s1",
      goodId: "g1",
      count: -2,
    } as any);
    // 原实现会把 3 减成 1（绕过限购）；现保持 3 不变
    expect((player._playerdata.tshop as any).s1.info).toEqual([{ id: "g1", count: 3 }]);
  });

  it("非整数/零 count 应拒绝", async () => {
    const player = makePlayer({});
    await handleExchangeActivityShopItem(player as any, { shopId: "s1", goodId: "g1", count: 0 } as any);
    // 拒绝即完全不写档（连 shop 条目都不创建）
    expect((player._playerdata.tshop as any).s1).toBeUndefined();
    const player2 = makePlayer({});
    await handleExchangeActivityShopItem(player2 as any, { shopId: "s1", goodId: "g1", count: 1.5 } as any);
    expect((player2._playerdata.tshop as any).s1).toBeUndefined();
  });
});
