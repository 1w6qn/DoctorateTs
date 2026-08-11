import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import httpContext from "express-http-context2";
import templateShopRouter from "../../../app/game/router/templateShop";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return {
    send: vi.fn(),
    status: vi.fn().mockReturnThis(),
    sendStatus: vi.fn(),
    json: vi.fn(),
  };
}

describe("templateShop 路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      inventory: {},
      status: { uid: "1", gold: 0 },
    } as any);
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    templateShopRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("getGoodList 应返回商店数据并自动补足货币（私服便利）", async () => {
    await call("/getGoodList", { shopId: "shop_act53side" });
    const send = res.send.mock.calls[0][0];
    expect(send.data.shopId).toBe("shop_act53side");
    // 玩家无活动代币 → 自动补足到可购全店一次（shop_act53side 总价 > 0）
    expect(player._playerdata.inventory["act53side_token_photo"]).toBeGreaterThan(0);
  });

  it("getGoodList 货币已足够时不应改动余额", async () => {
    player._playerdata.inventory["act53side_token_photo"] = 999999;
    await call("/getGoodList", { shopId: "shop_act53side" });
    expect(player._playerdata.inventory["act53side_token_photo"]).toBe(999999);
  });

  it("buyGood 应扣货币并发放商品（itemList 含发放物）", async () => {
    player._playerdata.inventory["act53side_token_photo"] = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_2", count: 1 });
    const send = res.send.mock.calls[0][0];
    // act53side_2 = char_337_utage@summer#4 皮肤，price 500
    expect(send.itemList).toEqual([
      { id: "char_337_utage@summer#4", type: "CHAR_SKIN", count: 1 },
    ]);
    expect(player._playerdata.inventory["act53side_token_photo"]).toBe(99999 - 500);
    expect(player._trigger.emit).toHaveBeenCalledWith("items:get", [
      [{ id: "char_337_utage@summer#4", type: "CHAR_SKIN", count: 1 }],
    ]);
  });

  it("buyGood 货币不足不应发放（itemList 空、不扣款）", async () => {
    player._playerdata.inventory["act53side_token_photo"] = 0;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_2", count: 1 });
    const send = res.send.mock.calls[0][0];
    expect(send.itemList).toEqual([]);
    expect(player._playerdata.inventory["act53side_token_photo"]).toBe(0);
  });

  it("buyGood PROGRESS 商品应按档位发放（第一档 price/item）", async () => {
    player._playerdata.inventory["act53side_token_photo"] = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 1 });
    const send = res.send.mock.calls[0][0];
    // act53side_1 为 PROGRESS 商品：第一档 price 200，item p_char_4236_tmslot
    expect(player._playerdata.inventory["act53side_token_photo"]).toBe(99999 - 200);
    expect(send.itemList).toEqual([
      { id: "p_char_4236_tmslot", type: "MATERIAL", count: 1 },
    ]);
  });

  it("buyGood 未知商品不应 500（itemList 空）", async () => {
    await call("/buyGood", { shopId: "shop_act53side", goodId: "not_exist", count: 1 });
    const send = res.send.mock.calls[0][0];
    expect(send.itemList).toEqual([]);
  });
});
