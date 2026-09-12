import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import httpContext from "express-http-context2";
import templateShopRouter from "@game/modules/templateShop/routes";
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
      activity: {
        TYPE_ACT53SIDE: {
          act53side: { actCoin: 0, campaignCnt: 0, favorList: [] },
        },
        ARK_HUB: { act1arkhub: { coin: 0 } },
      },
      tshop: {},
    } as any);
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    templateShopRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("getGoodList 应返回商店数据（含 allPriceDict）并自动补足活动币", async () => {
    await call("/getGoodList", { shopId: "shop_act53side" });
    const send = res.send.mock.calls[0][0];
    expect(send.data.shopId).toBe("shop_act53side");
    // 官服响应含 allPriceDict（购全店总额）
    expect(Array.isArray(send.data.allPriceDict)).toBe(true);
    expect(send.data.allPriceDict[0].maxPrice).toBeGreaterThan(0);
    // 玩家无活动代币 → 自动补足（活动币 actCoin 与 tshop 币同步，官服形状）
    expect(player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin).toBeGreaterThan(0);
    expect(player._playerdata.tshop["shop_act53side"].coin).toBe(
      player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin,
    );
  });

  it("getGoodList 货币已足够时不应改动余额", async () => {
    player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin = 999999;
    await call("/getGoodList", { shopId: "shop_act53side" });
    expect(player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin).toBe(999999);
  });

  it("buyGood 应扣活动币、记录 tshop.info 并发放商品（itemList 含发放物）", async () => {
    player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_2", count: 1 });
    const send = res.send.mock.calls[0][0];
    // act53side_2 = char_337_utage@summer#4 皮肤，price 500
    expect(send.itemList).toEqual([
      { id: "char_337_utage@summer#4", type: "CHAR_SKIN", count: 1 },
    ]);
    expect(player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin).toBe(99999 - 500);
    // 官服形状：购买记录写 tshop.{shopId}.info
    expect(player._playerdata.tshop["shop_act53side"].info).toEqual([
      { id: "act53side_2", count: 1 },
    ]);
    expect(player._playerdata.tshop["shop_act53side"].coin).toBe(99999 - 500);
    // 物品发放已收敛到 player.gainItem 管道（不再直发 items:get 事件）
    expect(player.gainItem.add).toHaveBeenCalledWith({
      id: "char_337_utage@summer#4",
      type: "CHAR_SKIN",
      count: 1,
    });
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("buyGood 枢纽店（shop_act1arkhub）应扣 ARK_HUB.coin", async () => {
    player._playerdata.activity.ARK_HUB.act1arkhub.coin = 500;
    await call("/buyGood", { shopId: "shop_act1arkhub", goodId: "act1arkhub_1", count: 1 });
    const send = res.send.mock.calls[0][0];
    // act1arkhub_1 = char_4051_akkord@summer#23 皮肤，price 500
    expect(send.itemList).toEqual([
      { id: "char_4051_akkord@summer#23", type: "CHAR_SKIN", count: 1 },
    ]);
    expect(player._playerdata.activity.ARK_HUB.act1arkhub.coin).toBe(0);
    expect(player._playerdata.tshop["shop_act1arkhub"].info).toEqual([
      { id: "act1arkhub_1", count: 1 },
    ]);
  });

  it("buyGood 货币不足不应发放（itemList 空、不扣款）", async () => {
    player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin = 0;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_2", count: 1 });
    const send = res.send.mock.calls[0][0];
    expect(send.itemList).toEqual([]);
    expect(player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin).toBe(0);
  });

  it("buyGood PROGRESS 商品应按档位发放（第一档 price/item）", async () => {
    player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 1 });
    const send = res.send.mock.calls[0][0];
    // act53side_1 为 PROGRESS 商品：第一档 price 200，item p_char_4236_tmslot
    expect(player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin).toBe(99999 - 200);
    expect(send.itemList).toEqual([
      { id: "p_char_4236_tmslot", type: "MATERIAL", count: 1 },
    ]);
  });

  it("buyGood 未知商品不应 500（itemList 空）", async () => {
    await call("/buyGood", { shopId: "shop_act53side", goodId: "not_exist", count: 1 });
    const send = res.send.mock.calls[0][0];
    expect(send.itemList).toEqual([]);
  });

  it("buyGood 无限池商品（availCount=-1）应可正常购买且不限购", async () => {
    // 修复：原 availCount=-1 被当成"恒超限"拒绝购买
    player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_40", count: 2 });
    const send = res.send.mock.calls[0][0];
    // act53side_40 = 30073 材料，price 25，无限购
    expect(send.itemList).toEqual([{ id: "30073", type: "MATERIAL", count: 2 }]);
    expect(player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin).toBe(99999 - 25 * 2);
    // 再次购买继续放行（无限池）
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_40", count: 3 });
    expect(player._playerdata.tshop["shop_act53side"].info).toEqual(
      expect.arrayContaining([{ id: "act53side_40", count: 5 }]),
    );
  });

  // Round 23：跨档计价修复（原实现取单档价再 ×count，跳过中间档位）
  it("buyGood PROGRESS 一次买多档：按逐档价格计费并逐档发放", async () => {
    player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 2 });
    const send = res.send.mock.calls[0][0];
    // char_tmslot_progress 档位价 = [200, 240, 280, 320, 360] → 前两档 440（旧实现 200×2=400）
    expect(player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin).toBe(99999 - 440);
    expect(send.itemList).toEqual([
      { id: "p_char_4236_tmslot", type: "MATERIAL", count: 1 },
      { id: "p_char_4236_tmslot", type: "MATERIAL", count: 1 },
    ]);
    expect(player._playerdata.tshop["shop_act53side"].progressInfo).toEqual({
      char_tmslot_progress: { order: 3, count: 0 },
    });
  });

  it("buyGood PROGRESS 超出剩余档位时整单拒绝（不扣币不发放）", async () => {
    player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 6 }); // 仅 5 档
    const send = res.send.mock.calls[0][0];
    expect(send.itemList).toEqual([]);
    expect(player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin).toBe(99999);
  });

  it("buyGood PROGRESS 商品应写入 progressInfo（阶段显示随购买推进）", async () => {
    // 修复：原漏写 progressInfo，购买后阶段显示不更新
    player._playerdata.activity.TYPE_ACT53SIDE.act53side.actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 1 });
    // 5 档进度商品（char_tmslot_progress）：第 1 档 price 200 → 下一档序号 2
    expect(player._playerdata.tshop["shop_act53side"].progressInfo).toEqual({
      char_tmslot_progress: { order: 2, count: 0 },
    });
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 1 });
    expect(player._playerdata.tshop["shop_act53side"].progressInfo).toEqual({
      char_tmslot_progress: { order: 3, count: 0 },
    });
  });
});
