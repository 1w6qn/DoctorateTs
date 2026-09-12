import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import type { Response } from "express";
import httpContext from "express-http-context2";
import templateShopRouter from "@game/modules/templateShop/routes";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";

/** 模板商店请求体视图（本文件各端点字段合集） */
interface TemplateShopBody {
  shopId?: string;
  goodId?: string;
  count?: number;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: TemplateShopBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

/**
 * 活动币子树读取视图
 *
 * `TYPE_ACT53SIDE` 未在 `scripts/playerdata-server-adapt.ts` 具名登记，其值类型为两层
 * `ServerPayload`（第三层 actCoin/coin 读不到）；ARK_HUB 同样只用到 coin。这里就地声明
 * 读取视图，键与值一字不改。
 */
interface Act53SideSlot {
  actCoin?: number;
  campaignCnt?: number;
  favorList?: string[];
}

interface TemplateShopActivityView {
  TYPE_ACT53SIDE?: { [actId: string]: Act53SideSlot };
  ARK_HUB?: { [actId: string]: { coin?: number } };
}

type RouterReq = Parameters<typeof templateShopRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

describe("templateShop 路由", () => {
  let player: MockPlayerDataManager;
  let res: MockRes;

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
    });
    res = mockRes();
    vi.mocked(httpContext.get).mockReturnValue(player);
  });

  /** 读取 act53side 活动槽（见 TemplateShopActivityView 的说明） */
  function act53(): Act53SideSlot {
    return (player._playerdata.activity as TemplateShopActivityView).TYPE_ACT53SIDE!.act53side!;
  }

  /** 读取 act1arkhub 活动槽（见 TemplateShopActivityView 的说明） */
  function arkHub(): { coin?: number } {
    return (player._playerdata.activity as TemplateShopActivityView).ARK_HUB!.act1arkhub!;
  }

  async function call(url: string, body: TemplateShopBody) {
    const req: MockReq = { method: "POST", url, body };
    // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
    templateShopRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("getGoodList 应返回商店数据（含 allPriceDict）并自动补足活动币", async () => {
    await call("/getGoodList", { shopId: "shop_act53side" });
    const send = vi.mocked(res.send).mock.calls[0][0];
    expect(send.data.shopId).toBe("shop_act53side");
    // 官服响应含 allPriceDict（购全店总额）
    expect(Array.isArray(send.data.allPriceDict)).toBe(true);
    expect(send.data.allPriceDict[0].maxPrice).toBeGreaterThan(0);
    // 玩家无活动代币 → 自动补足（活动币 actCoin 与 tshop 币同步，官服形状）
    expect(act53().actCoin).toBeGreaterThan(0);
    expect(player._playerdata.tshop["shop_act53side"].coin).toBe(
      act53().actCoin,
    );
  });

  it("getGoodList 货币已足够时不应改动余额", async () => {
    act53().actCoin = 999999;
    await call("/getGoodList", { shopId: "shop_act53side" });
    expect(act53().actCoin).toBe(999999);
  });

  it("buyGood 应扣活动币、记录 tshop.info 并发放商品（itemList 含发放物）", async () => {
    act53().actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_2", count: 1 });
    const send = vi.mocked(res.send).mock.calls[0][0];
    // act53side_2 = char_337_utage@summer#4 皮肤，price 500
    expect(send.itemList).toEqual([
      { id: "char_337_utage@summer#4", type: "CHAR_SKIN", count: 1 },
    ]);
    expect(act53().actCoin).toBe(99999 - 500);
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
    arkHub().coin = 500;
    await call("/buyGood", { shopId: "shop_act1arkhub", goodId: "act1arkhub_1", count: 1 });
    const send = vi.mocked(res.send).mock.calls[0][0];
    // act1arkhub_1 = char_4051_akkord@summer#23 皮肤，price 500
    expect(send.itemList).toEqual([
      { id: "char_4051_akkord@summer#23", type: "CHAR_SKIN", count: 1 },
    ]);
    expect(arkHub().coin).toBe(0);
    expect(player._playerdata.tshop["shop_act1arkhub"].info).toEqual([
      { id: "act1arkhub_1", count: 1 },
    ]);
  });

  it("buyGood 货币不足不应发放（itemList 空、不扣款）", async () => {
    act53().actCoin = 0;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_2", count: 1 });
    const send = vi.mocked(res.send).mock.calls[0][0];
    expect(send.itemList).toEqual([]);
    expect(act53().actCoin).toBe(0);
  });

  it("buyGood PROGRESS 商品应按档位发放（第一档 price/item）", async () => {
    act53().actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 1 });
    const send = vi.mocked(res.send).mock.calls[0][0];
    // act53side_1 为 PROGRESS 商品：第一档 price 200，item p_char_4236_tmslot
    expect(act53().actCoin).toBe(99999 - 200);
    expect(send.itemList).toEqual([
      { id: "p_char_4236_tmslot", type: "MATERIAL", count: 1 },
    ]);
  });

  it("buyGood 未知商品不应 500（itemList 空）", async () => {
    await call("/buyGood", { shopId: "shop_act53side", goodId: "not_exist", count: 1 });
    const send = vi.mocked(res.send).mock.calls[0][0];
    expect(send.itemList).toEqual([]);
  });

  it("buyGood 无限池商品（availCount=-1）应可正常购买且不限购", async () => {
    // 修复：原 availCount=-1 被当成"恒超限"拒绝购买
    act53().actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_40", count: 2 });
    const send = vi.mocked(res.send).mock.calls[0][0];
    // act53side_40 = 30073 材料，price 25，无限购
    expect(send.itemList).toEqual([{ id: "30073", type: "MATERIAL", count: 2 }]);
    expect(act53().actCoin).toBe(99999 - 25 * 2);
    // 再次购买继续放行（无限池）
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_40", count: 3 });
    expect(player._playerdata.tshop["shop_act53side"].info).toEqual(
      expect.arrayContaining([{ id: "act53side_40", count: 5 }]),
    );
  });

  // Round 23：跨档计价修复（原实现取单档价再 ×count，跳过中间档位）
  it("buyGood PROGRESS 一次买多档：按逐档价格计费并逐档发放", async () => {
    act53().actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 2 });
    const send = vi.mocked(res.send).mock.calls[0][0];
    // char_tmslot_progress 档位价 = [200, 240, 280, 320, 360] → 前两档 440（旧实现 200×2=400）
    expect(act53().actCoin).toBe(99999 - 440);
    expect(send.itemList).toEqual([
      { id: "p_char_4236_tmslot", type: "MATERIAL", count: 1 },
      { id: "p_char_4236_tmslot", type: "MATERIAL", count: 1 },
    ]);
    expect(player._playerdata.tshop["shop_act53side"].progressInfo).toEqual({
      char_tmslot_progress: { order: 3, count: 0 },
    });
  });

  it("buyGood PROGRESS 超出剩余档位时整单拒绝（不扣币不发放）", async () => {
    act53().actCoin = 99999;
    await call("/buyGood", { shopId: "shop_act53side", goodId: "act53side_1", count: 6 }); // 仅 5 档
    const send = vi.mocked(res.send).mock.calls[0][0];
    expect(send.itemList).toEqual([]);
    expect(act53().actCoin).toBe(99999);
  });

  it("buyGood PROGRESS 商品应写入 progressInfo（阶段显示随购买推进）", async () => {
    // 修复：原漏写 progressInfo，购买后阶段显示不更新
    act53().actCoin = 99999;
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
