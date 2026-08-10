import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    ShopTable: {
      lowGoodList: {
        goodList: [
          { goodId: "LS_1", item: { id: "30012", count: 2 }, price: 20 },
        ],
      },
      highGoodList: {
        goodList: [
          { goodId: "HS_1", item: { id: "30011", count: 1 }, price: 100 },
        ],
        progressGoodList: {},
      },
      skinGoodList: { goodList: [] },
    },
  },
}));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/shop", () => ({}));


import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { ShopController } from "@game/controller/shop";

describe("ShopController 每日刷新", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      shop: {
        LS: {
          curShopId: "lggShdShopnumber69",
          curGroupId: "lggShdShopnumber69_Group_2",
          info: [
            { id: "LS_1", count: 2 },
            { id: "LS_2", count: 5 },
          ],
        },
        HS: { curShopId: "", info: [{ id: "HS_1", count: 1 }] },
      } as any,
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("dailyRefresh 应清空低级商店每日限购记录", async () => {
    const controller = new ShopController(mockPlayer as any, mockTrigger as any);
    await controller.dailyRefresh();
    expect(mockPlayer._playerdata.shop!.LS.info).toEqual([]);
  });
});

describe("ShopController 购买", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      shop: {
        LS: { curShopId: "s69", curGroupId: "g2", info: [] },
        HS: { curShopId: "", info: [], progressInfo: {} },
      } as any,
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("buyLowGood 应记录购买并触发扣费与发物", async () => {
    const controller = new ShopController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const items = await controller.buyLowGood({ goodId: "LS_1", count: 2 });
    expect(items).toEqual([{ id: "30012", count: 4 }]);
    expect(mockPlayer._playerdata.shop!.LS.info).toContainEqual({ id: "LS_1", count: 2 });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "4005", count: 40 }]]);
    expect(emitSpy).toHaveBeenCalledWith("items:get", [[{ id: "30012", count: 4 }]]);
  });

  it("buyHighGood 应记录高级商店购买", async () => {
    const controller = new ShopController(mockPlayer as any, mockTrigger as any);
    const items = await controller.buyHighGood({ goodId: "HS_1", count: 1 });
    expect(items).toEqual([{ id: "30011", count: 1 }]);
    expect(mockPlayer._playerdata.shop!.HS.info).toContainEqual({ id: "HS_1", count: 1 });
  });
});

describe("buildLMTGSGoodList 自动生成限定商店", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({ shop: {} });
    // 扩展 excel mock：两个限定池（当前池 + 旧池）
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.GachaTable = {
      gachaPoolClient: [
        { gachaPoolId: "LIMITED_23_0_1", gachaRuleType: "LIMITED", gachaIndex: 5, LMTGSID: "LMTGS_COIN_2301", openTime: 1630000000, endTime: 1639999999 },
        { gachaPoolId: "LIMITED_76_0_1", gachaRuleType: "LIMITED", gachaIndex: 10, LMTGSID: "LMTGS_COIN_7601", openTime: 1700000000, endTime: 1799999999 },
      ],
    };
    excelMock.GachaDetailTable = {
      details: {
        "LIMITED_76_0_1": {
          upCharInfo: {
            perCharList: [
              { rarityRank: 5, charIdList: ["char_1015_aglna2"] },
              { rarityRank: 4, charIdList: ["char_4237_jcinta"] },
            ],
          },
        },
        "LIMITED_23_0_1": {
          upCharInfo: {
            perCharList: [{ rarityRank: 5, charIdList: ["char_1014_nearl2"] }],
          },
        },
      },
    };
  });

  it("应为当前限定池生成商品（限定六星 300/新五星 75/往期限定 300）", async () => {
    const controller = new ShopController(mockPlayer as any, mockTrigger as any);
    const goods = controller.buildLMTGSGoodList();
    const cur = goods.filter((g) => g.goodId.startsWith("LIMITED_76_0_1"));
    // 本池 UP 六星 → 300 本池凭证
    expect(
      cur.some(
        (g) =>
          g.item.id === "char_1015_aglna2" &&
          g.price.id === "LMTGS_COIN_7601" &&
          g.price.count === 300,
      ),
    ).toBe(true);
    // 本池新五星 → 75
    expect(
      cur.some((g) => g.item.id === "char_4237_jcinta" && g.price.count === 75),
    ).toBe(true);
    // 往期限定六星（LIMITED_23_0_1 的 UP）→ 300，进入 76 池商店
    expect(
      cur.some(
        (g) =>
          g.item.id === "char_1014_nearl2" &&
          g.price.id === "LMTGS_COIN_7601" &&
          g.price.count === 300,
      ),
    ).toBe(true);
  });

  it("buyLMTGSGood 应扣对应池凭证并带 type 发放（CHAR → char:get）", async () => {
    const controller = new ShopController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const items = await controller.buyLMTGSGood({ goodId: "LIMITED_76_0_1_1", count: 1 });
    expect(items).toEqual([{ id: "char_1015_aglna2", count: 1, type: "CHAR" }]);
    // 扣 LMTGS_COIN_7601（原硬编码 LMTGS_COIN 扣错货币）
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "LMTGS_COIN_7601", count: 300, type: "LMTGS_COIN" }],
    ]);
    // 带 type 发放（CHAR → char:get 入账干员）
    expect(emitSpy).toHaveBeenCalledWith("items:get", [
      [{ id: "char_1015_aglna2", count: 1, type: "CHAR" }],
    ]);
  });
});

describe("buildSocialGoodList / buySocialGood 信用商店", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      shop: { SOCIAL: { curShopId: "", info: [], charPurchase: {} } },
      status: { socialPoint: 500 },
    });
  });

  it("buildSocialGoodList 应按当天日期重定 goodId 前缀", async () => {
    const controller = new ShopController(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = {
      goodList: [
        {
          goodId: "SOCIAL20211106_T1_recruit_1_1",
          displayName: "招聘许可",
          originPrice: 160,
          price: 40,
          discount: 0.75,
          slotId: 1,
          availCount: 1,
          item: { id: "7001", count: 1, type: "TKT_RECRUIT" },
        },
      ],
      charPurchase: {},
    };
    const list = controller.buildSocialGoodList();
    expect(list.goodList[0].goodId).toMatch(/^SOCIAL\d{8}_T1_recruit_1_1$/);
    // 日期前缀 = 当天
    const t = new Date();
    const p = (n: number) => String(n).padStart(2, "0");
    expect(list.goodList[0].goodId.startsWith(`SOCIAL${t.getFullYear()}${p(t.getMonth() + 1)}${p(t.getDate())}`)).toBe(true);
  });

  it("buySocialGood 应扣 socialPoint 并记录购买 + 发放", async () => {
    const controller = new ShopController(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = {
      goodList: [
        {
          goodId: "SOCIAL20211106_T1_recruit_1_1",
          displayName: "招聘许可",
          originPrice: 160,
          price: 40,
          discount: 0.75,
          slotId: 1,
          availCount: 1,
          item: { id: "7001", count: 1, type: "TKT_RECRUIT" },
        },
      ],
      charPurchase: {},
    };
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    // 客户端回传的是 buildSocialGoodList 重定日期后的 goodId
    const goodId = controller.buildSocialGoodList().goodList[0].goodId;
    const items = await controller.buySocialGood({ goodId, count: 1 });
    expect(items).toEqual([{ id: "7001", count: 1, type: "TKT_RECRUIT" }]);
    // 信用扣除 + 发放
    const status = mockPlayer._playerdata.status as any;
    expect(status.socialPoint).toBe(460);
    expect(emitSpy).toHaveBeenCalledWith("items:get", [
      [{ id: "7001", count: 1, type: "TKT_RECRUIT" }],
    ]);
    // 购买记录
    const social = (mockPlayer._playerdata.shop as any).SOCIAL;
    expect(social.info).toContainEqual({ id: goodId, count: 1 });
  });

  it("buySocialGood 未知商品应返回空（不 500）", async () => {
    const controller = new ShopController(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: [], charPurchase: {} };
    const items = await controller.buySocialGood({ goodId: "NOPE", count: 1 });
    expect(items).toEqual([]);
  });
});
