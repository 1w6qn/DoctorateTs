import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

vi.mock("@excel/excel", () => ({
  default: {
    ShopTable: {
      skinGoodList: { goodList: [] },
      lowGoodList: { goodList: [], groups: [], shopEndTime: 0, newFlag: [] },
      highGoodList: { goodList: [], progressGoodList: {}, newFlag: [] },
      classicGoodList: { goodList: [], progressGoodList: {}, newFlag: [] },
      LMTGSGoodList: { goodList: [], newFlag: [] },
      EPGSGoodList: { goodList: [], newFlag: [] },
      REPGoodList: { goodList: [], newFlag: [] },
    },
    SkinTable: { charSkins: {} },
  },
}));

import httpContext from "express-http-context2";
import shopRouter from "../../../app/game/router/shop";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("shop 路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      shop: {
        LS: { info: [{ id: "LS_good_1", count: 2 }] },
        HS: { info: [] },
        GP: {
          oneTime: { info: [{ id: "GP_Once_330", count: 1 }] },
          weekly: { info: [] },
        },
        CASH: { info: [{ id: "CS_1_r1", count: 1 }] },
        SOCIAL: { info: [] },
        CLASSIC: { info: [] },
      } as any,
    });
    // 商店控制器（路由跨周期刷新依赖）
    player.shop = {
      todayLowShopId: () => "lggShdShopnumber88",
      todayExtraShopId: () => "xShdShopnumber5",
      monthlyRefresh: vi.fn(async () => {
        player._playerdata.shop.LS.curShopId = "lggShdShopnumber88";
        player._playerdata.shop.LS.info = [];
      }),
      refreshExtraShop: vi.fn(async () => {
        player._playerdata.shop.ES.curShopId = "xShdShopnumber5";
        player._playerdata.shop.ES.info = [];
      }),
      todaySocialShopId: () => "SOCIAL20260818",
      refreshSocialShop: vi.fn(async () => {}),
    };
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    shopRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("getGoodPurchaseState 应返回扁平 {goodId: 1|-1}（已购 -1 / 可购 1），对齐 CS 与抓包", async () => {
    await call("/getGoodPurchaseState", {
      goodIdMap: {
        LS: ["LS_good_1", "LS_not_bought"],
        GP: ["GP_Once_330"], // 嵌套结构（oneTime.info）
        CASH: ["CS_1_r1"],
        HS: [],
      },
    });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toEqual({
      LS_good_1: -1, // 已购买
      LS_not_bought: 1, // 可购买
      GP_Once_330: -1, // GP 嵌套信息正确识别
      CS_1_r1: -1,
    });
    expect(Object.keys(sent.result).length).toBe(4); // 只返回请求的 goodId，而非全部 info
  });

  it("getGoodPurchaseState 空 goodIdMap 应返回空 result", async () => {
    await call("/getGoodPurchaseState", { goodIdMap: {} });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toEqual({});
  });

  it("getSkinGoodList 应过滤皮肤表缺失条目并重排唯一 slotId", async () => {
    const excelMock = await import("@excel/excel");
    const excel = excelMock.default as any;
    // 构造含冲突 slotId + 无效皮肤的数据
    excel.ShopTable.skinGoodList = {
      goodList: [
        { goodId: "SS_skin_a#1", skinId: "skin_a#1", charId: "char_a", price: 18, slotId: 45 },
        { goodId: "SS_skin_b#1", skinId: "skin_b#1", charId: "char_b", price: 18, slotId: 45 }, // 与上冲突
        { goodId: "SS_bad#1", skinId: "not_in_table#1", charId: "char_b", price: 18, slotId: 46 }, // 皮肤表缺失
      ],
    };
    excel.SkinTable = {
      charSkins: {
        "skin_a#1": { charId: "char_a" },
        "skin_b#1": { charId: "char_b" },
      },
    };
    await call("/getSkinGoodList", {});
    const sent = res.send.mock.calls[0][0];
    // 无效皮肤被过滤（2 条）
    expect(sent.goodList).toHaveLength(2);
    // slotId 唯一连续（1..n），无冲突
    const ids = sent.goodList.map((g: any) => g.slotId);
    expect(new Set(ids).size).toBe(2);
    expect(ids.sort((a: number, b: number) => a - b)).toEqual([1, 2]);
  });

  it("getLowGoodList 旧月份 curShopId 应跨月重置（剩余时间不为负）", async () => {
    // 玩家 LS.curShopId 停留在旧月份（迁移数据）
    player._playerdata.shop.LS.curShopId = "lggShdShopnumber69";
    await call("/getLowGoodList", {});
    // 触发 monthlyRefresh → delta 更新当月 curShopId
    expect(player.shop.monthlyRefresh).toHaveBeenCalled();
    expect(player._playerdata.shop.LS.curShopId).toBe("lggShdShopnumber88");
    expect(player._playerdata.shop.LS.info).toEqual([]);
  });

  it("getExtraGoodList 旧年份 curShopId 应跨年重置（剩余时间不为负）", async () => {
    player._playerdata.shop.ES = { curShopId: "xShdShopnumber2", info: [{ id: "ES_xShdShopnumber2_1", count: 6 }] };
    await call("/getExtraGoodList", {});
    expect(player.shop.refreshExtraShop).toHaveBeenCalled();
    expect(player._playerdata.shop.ES.curShopId).toBe("xShdShopnumber5");
    expect(player._playerdata.shop.ES.info).toEqual([]);
  });
});
