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


import { mockPlayerData, mockTypedEventEmitter } from "../../../helpers";
import { ShopManager } from "@game/domain/shop/logic";

describe("ShopManager 每日刷新", () => {
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
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    await controller.dailyRefresh();
    expect(mockPlayer._playerdata.shop!.LS.info).toEqual([]);
  });
});

describe("ShopManager 购买", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      status: {
        lggShard: 5000,
        hggShard: 5000,
        socialPoint: 500,
        gold: 100000,
        androidDiamond: 1000,
      } as any,
      inventory: {
        "3401": 10000,
        "4006": 10000,
        EPGS_COIN: 10000,
        REP_COIN: 10000,
      },
      shop: {
        LS: { curShopId: "s69", curGroupId: "g2", info: [] },
        HS: { curShopId: "", info: [], progressInfo: {} },
        CLASSIC: { info: [], progressInfo: {} },
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
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const items = await controller.buyLowGood({ goodId: "LS_1", count: 2 });
    expect(items).toEqual([{ id: "30012", count: 4 }]);
    expect(mockPlayer._playerdata.shop!.LS.info).toContainEqual({ id: "LS_1", count: 2 });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "4005", count: 40 }]]);
    expect(emitSpy).toHaveBeenCalledWith("items:get", [[{ id: "30012", count: 4 }]]);
  });

  it("buyHighGood 应记录高级商店购买", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
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
    mockPlayer = mockPlayerData({
      shop: {},
      status: { hggShard: 0, lggShard: 0, androidDiamond: 1000 } as any,
      // 限时凭证（对应池）
      inventory: { LMTGS_COIN_7601: 3000, LMTGS_COIN_2301: 3000 },
    });
    // 扩展 excel mock：两个限定池（当前池 + 旧池）
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.GachaTable = {
      gachaPoolClient: [
        { gachaPoolId: "LIMITED_23_0_1", gachaRuleType: "LIMITED", gachaIndex: 5, lMTGSID: "LMTGS_COIN_2301", openTime: 1630000000, endTime: 1639999999 },
        { gachaPoolId: "LIMITED_76_0_1", gachaRuleType: "LIMITED", gachaIndex: 10, lMTGSID: "LMTGS_COIN_7601", openTime: 1700000000, endTime: 1799999999 },
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
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
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
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const items = await controller.buyLMTGSGood({ goodId: "LIMITED_76_0_1_1", count: 1 });
    // 干员（CHAR）经 char:get 入账并返回带 instId（获得干员效果；测试环境无 char:get 订阅 → 0）
    expect(items).toEqual([{ id: "char_1015_aglna2", count: 1, type: "CHAR", instId: 0 }]);
    // 扣 LMTGS_COIN_7601（原硬编码 LMTGS_COIN 扣错货币）
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "LMTGS_COIN_7601", count: 300, type: "LMTGS_COIN" }],
    ]);
    // 干员走 char:get 事件（非 items:get 裸发放）
    expect(emitSpy).toHaveBeenCalledWith(
      "char:get",
      ["char_1015_aglna2", { from: "SHOP" }, expect.any(Function)],
    );
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

  it("buildSocialGoodList 无干员时应生成 10 个当天前缀的随机物资", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: [], charPurchase: {} };
    const list = controller.buildSocialGoodList();
    // 无干员购买记录 → 无干员合同 → 10 个随机物资
    expect(list.goodList).toHaveLength(10);
    const t = new Date();
    const p = (n: number) => String(n).padStart(2, "0");
    const prefix = `SOCIAL${t.getFullYear()}${p(t.getMonth() + 1)}${p(t.getDate())}`;
    for (const g of list.goodList) {
      // 物资商品 goodId 均带当天日期前缀
      expect(g.goodId).toMatch(/^SOCIAL\d{8}_T2_goods_\d+_\d+$/);
      expect(g.goodId.startsWith(prefix)).toBe(true);
    }
  });

  it("信用交易所物资：同日稳定、折扣高优先排前、价格=原价×(1-折扣)、特价仅限允许物资", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: [], charPurchase: {} };
    // 候选池允许的全部物品 id
    const allowed = new Set([
      "4001", "2001", "2002", "3003", "3112", "3113",
      "30011", "30012", "30021", "30022", "30031", "30032",
      "30041", "30042", "30051", "30052", "30061", "30062",
      "3301", "3302", "3401", "7001", "7002",
    ]);
    const g1 = controller.buildSocialGoodList().goodList;
    const g2 = controller.buildSocialGoodList().goodList;
    // 同日稳定（同一日期种子 → 多次请求一致）
    expect(g1).toEqual(g2);
    expect(g1).toHaveLength(10);
    // 折扣高优先排前（折扣序列非递增）
    const discounts = g1.map((g) => g.discount);
    for (let i = 1; i < discounts.length; i++) {
      expect(discounts[i - 1]).toBeGreaterThanOrEqual(discounts[i]);
    }
    for (const g of g1) {
      // 物品都是候选池内的有效物资
      expect(allowed.has(g.item.id)).toBe(true);
      // 折扣档位合法，价格 = 原价 × (1 - 折扣)
      expect([0, 0.5, 0.75, 0.95, 0.99]).toContain(g.discount);
      expect(g.price).toBe(Math.round(g.originPrice * (1 - g.discount)));
      // -95%/-99% 特价仅出现在允许的物资上
      if (g.discount >= 0.9) {
        const ok95 =
          g.item.id === "2001" ||
          (g.item.id === "4001" && g.item.count === 1800);
        const ok99 =
          g.item.id === "2002" ||
          (g.item.id === "4001" && g.item.count === 3600);
        expect(ok95 || ok99).toBe(true);
      }
    }
  });

  it("buySocialGood 应扣 socialPoint 并记录购买 + 发放", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: [], charPurchase: {} };
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    // 取当日生成的第 1 个物资回传购买（goodId 为 buildSocialGoodList 动态生成）
    const good = controller.buildSocialGoodList().goodList[0];
    const goodId = good.goodId;
    const items = await controller.buySocialGood({ goodId, count: 1 });
    expect(items).toEqual([good.item]);
    // 信用扣除（按该商品价格）+ 发放
    const status = mockPlayer._playerdata.status as any;
    expect(status.socialPoint).toBe(500 - good.price);
    expect(emitSpy).toHaveBeenCalledWith("items:get", [[good.item]]);
    // 购买记录
    const social = (mockPlayer._playerdata.shop as any).SOCIAL;
    expect(social.info).toContainEqual({ id: goodId, count: 1 });
  });

  it("常规物资 availCount 应为 1（每日限购 1 次，修复前 -1 显示为无限）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: [], charPurchase: {} };
    const list = controller.buildSocialGoodList();
    // 官服抓包（R-1787479734940-0470 等）：信用交易所每个常规商品 availCount=1
    for (const g of list.goodList) {
      expect(g.availCount).toBe(1);
    }
  });

  it("buySocialGood 同一商品每日限购 1 次（第二次购买抛 ShopError）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: [], charPurchase: {} };
    const good = controller.buildSocialGoodList().goodList[0];
    const goodId = good.goodId;
    // 第一次购买成功
    await controller.buySocialGood({ goodId, count: 1 });
    // 第二次购买同一商品 → 已购 1 + 本次 1 > availCount(1) → 拒绝
    await expect(
      controller.buySocialGood({ goodId, count: 1 }),
    ).rejects.toThrow("已达限购");
  });

  it("buySocialGood 未知商品应返回空（不 500）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: [], charPurchase: {} };
    const items = await controller.buySocialGood({ goodId: "NOPE", count: 1 });
    expect(items).toEqual([]);
  });
});

describe("buyFurniGroup 整组购买家具", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      status: { lggShard: 0, hggShard: 0 } as any,
      inventory: { "3401": 10000 },
      shop: { FURNI: { info: [], groupInfo: {} } },
    });
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.ShopTable.furniGoodList = {
      goods: [
        { goodId: "s1_01_1", furniId: "furni_s1_bed_01", priceCoin: 250, priceDia: 0 },
        { goodId: "cafe_01_1", furniId: "furni_cafe_table_01", priceCoin: 100, priceDia: 0 },
      ],
      groups: [],
    };
  });

  it("应结算组内每个家具（扣家具币 + 发放 + 记录）并跳过未知商品", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const items = await controller.buyFurniGroup({
      groupId: "test_group",
      goods: [
        { id: "s1_01_1", count: 1 },
        { id: "cafe_01_1", count: 2 },
        { id: "unknown_good", count: 1 }, // 数据版本错位 → 跳过不 500
      ],
    });
    expect(items).toEqual([
      { id: "furni_s1_bed_01", type: "FURN", count: 1 },
      { id: "furni_cafe_table_01", type: "FURN", count: 2 },
    ]);
    // 扣家具币（逐件扣：250×1 + 100×2）
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "3401", count: 250 }]]);
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "3401", count: 200 }]]);
    // 记录 shop.FURNI.info
    const furni = (mockPlayer._playerdata.shop as any).FURNI;
    expect(furni.info).toContainEqual({ id: "s1_01_1", count: 1 });
    expect(furni.info).toContainEqual({ id: "cafe_01_1", count: 2 });
    expect(furni.info.some((i: any) => i.id === "unknown_good")).toBe(false);
  });

  it("空商品列表应返回空", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const items = await controller.buyFurniGroup({ groupId: "g", goods: [] });
    expect(items).toEqual([]);
  });
});

describe("ShopManager 进度商品（buyClassicGood/buyHighGood progressGoodId）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      status: { lggShard: 0, hggShard: 10000 } as any,
      shop: {
        CLASSIC: { info: [], progressInfo: {} },
        HS: { info: [], progressInfo: {} },
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
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.ShopTable.classicGoodList = {
      goodList: [{ goodId: "CL_1", item: { id: "30011", count: 1 }, price: 0, progressGoodId: "clp1" }],
      progressGoodList: {
        clp1: [
          { order: 1, price: 10, item: { id: "30011", count: 1 } },
          { order: 2, price: 20, item: { id: "30012", count: 1 } },
          { order: 3, price: 30, item: { id: "30013", count: 1 } },
        ],
      },
      newFlag: [],
    };
    excelMock.ShopTable.highGoodList = {
      goodList: [{ goodId: "HS_P1", item: null, price: 0, progressGoodId: "hsp1" }],
      progressGoodList: {
        hsp1: [
          { order: 1, price: 100, item: { id: "4004", count: 5 } },
          { order: 2, price: 200, item: { id: "4004", count: 10 } },
        ],
      },
      newFlag: [],
    };
  });

  it("buyClassicGood 进度商品首次购买不崩（修复 progressInfo 判空顺序）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const items = await controller.buyClassicGood({ goodId: "CL_1", count: 1 });
    // 首次购买按第 1 档发放/计价
    expect(items).toEqual([{ id: "30011", count: 1 }]);
    const classic = (mockPlayer._playerdata.shop as any).CLASSIC;
    expect(classic.progressInfo.clp1.order).toBe(2);
    // 第二次购买推进到第 2 档（mock update 浅合并会替换 shop 引用，需重新取）
    const items2 = await controller.buyClassicGood({ goodId: "CL_1", count: 1 });
    expect(items2).toEqual([{ id: "30012", count: 1 }]);
    expect(((mockPlayer._playerdata.shop as any).CLASSIC).progressInfo.clp1.order).toBe(3);
  });

  it("buyHighGood 进度商品按档位扣费发放（非硬编码 5 档）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const items = await controller.buyHighGood({ goodId: "HS_P1", count: 1 });
    expect(items).toEqual([{ id: "4004", count: 5 }]);
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "4004", count: 100 }]]);
    // 第二档
    await controller.buyHighGood({ goodId: "HS_P1", count: 1 });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "4004", count: 200 }]]);
  });
});

describe("ShopManager 余额/限购校验", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      status: { lggShard: 50, hggShard: 1000, socialPoint: 30, androidDiamond: 10 } as any,
      inventory: { "3401": 100, "4006": 100 },
      shop: {
        LS: { curShopId: "s69", curGroupId: "g2", info: [] },
        SOCIAL: { curShopId: "", info: [], charPurchase: {} },
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
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.ShopTable.lowGoodList = {
      goodList: [
        // 限购 1 次的商品
        { goodId: "LS_LIMIT", item: { id: "30012", count: 2 }, price: 20, availCount: 1 },
        // 不限购商品
        { goodId: "LS_FREE", item: { id: "30012", count: 2 }, price: 20, availCount: -1 },
      ],
      groups: [],
      shopEndTime: 0,
      newFlag: [],
    };
  });

  it("余额不足应抛 ShopError（不扣费不发放）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    // lggShard=50，价格 20×3=60 不足
    await expect(
      controller.buyLowGood({ goodId: "LS_FREE", count: 3 }),
    ).rejects.toThrow();
    // 未发生任何扣费/发放副作用
    expect(emitSpy).not.toHaveBeenCalledWith("items:use", expect.anything());
    expect(emitSpy).not.toHaveBeenCalledWith("items:get", expect.anything());
    expect((mockPlayer._playerdata.shop as any).LS.info).toEqual([]);
  });

  it("信用不足应拒绝购买（socialPoint 不扣成负数）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: [], charPurchase: {} };
    mockPlayer._playerdata.status.socialPoint = 0;
    // 信用 0 < 任意商品价格 → 拒绝，且不扣成负数
    await expect(
      controller.buySocialGood({
        goodId: controller.buildSocialGoodList().goodList[0].goodId,
        count: 1,
      }),
    ).rejects.toThrow();
    expect((mockPlayer._playerdata.status as any).socialPoint).toBe(0);
  });

  it("超过 availCount 限购应抛 ShopError", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    // 第一次购买（限购 1）
    await controller.buyLowGood({ goodId: "LS_LIMIT", count: 1 });
    // 第二次购买 → 超限购
    await expect(
      controller.buyLowGood({ goodId: "LS_LIMIT", count: 1 }),
    ).rejects.toThrow();
  });
});

describe("buyGoodWithTicket 礼包（周度礼包匹配 + 限购记录）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      shop: { GP: { oneTime: { info: [], valid: [], curGroupId: "" } } } as any,
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
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.ShopTable.GPGoodList = {
      weeklyGroup: {
        groupId: "wk",
        startDateTime: 0,
        endDateTime: 0,
        packages: {
          GP_gW_1_W_1: { goodId: "GP_gW_1_W_1", availCount: 1, items: [{ id: "4002", count: 1 }] },
        },
      },
      monthlyGroup: { groupId: "m", startDateTime: 0, endDateTime: 0, packages: {} },
      monthlySub: null,
      levelGP: null,
      oneTimeGP: [{ goodId: "GP_Once_1", availCount: 1, items: [{ id: "4002", count: 2 }] }],
      chooseGroup: null,
    } as any;
  });

  it("周度礼包（GP_gW_*）应正常发放（修复原 'Wk' 永不匹配）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const items = await controller.buyGoodWithTicket({
      ticketId: "ticket",
      goodId: "GP_gW_1_W_1",
    });
    expect(items).toEqual([{ id: "4002", count: 1 }]);
  });

  it("一次性礼包超限购应抛 ShopError", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    await controller.buyGoodWithTicket({ ticketId: "t", goodId: "GP_Once_1" });
    await expect(
      controller.buyGoodWithTicket({ ticketId: "t", goodId: "GP_Once_1" }),
    ).rejects.toThrow();
    // 已购记录写入 shop.GP.oneTime.info
    const gp = (mockPlayer._playerdata.shop as any).GP;
    expect(gp.oneTime.info).toContainEqual({ id: "GP_Once_1", count: 1 });
  });

  it("null 数据字段（chooseGroup 等）应防御不 500", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    // NpOne 类型请求遇到 chooseGroup=null → 空结果不崩溃
    const items = await controller.buyGoodWithTicket({
      ticketId: "t",
      goodId: "GP_NpOne_1",
    });
    expect(items).toEqual([]);
  });
});

describe("buySkinGood 校验", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      status: { androidDiamond: 100 } as any,
      skin: { characterSkins: { skin_already_owned: 1 } },
      shop: { SKIN: { info: [], gachaGood: { info: [] } } } as any,
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
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.ShopTable.skinGoodList = {
      goodList: [
        { goodId: "SKIN_1", skinId: "skin_1", price: 18 },
        { goodId: "SKIN_OWNED", skinId: "skin_already_owned", price: 18 },
        { goodId: "SKIN_BAD", skinId: "skin_not_in_table", price: 18 },
      ],
    };
    // 皮肤表存在性校验数据
    excelMock.SkinTable = {
      charSkins: {
        skin_1: { charId: "char_x" },
        skin_already_owned: { charId: "char_x" },
      },
    };
  });

  it("皮肤表不存在的皮肤拒绝购买（数据错位防御）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    await expect(
      controller.buySkinGood({ goodId: "SKIN_BAD" }),
    ).rejects.toThrow();
  });

  it("玩家存档无 shop.SKIN 时购买皮肤不 500（_shopDraft 兜底创建）", async () => {
    delete (mockPlayer._playerdata.shop as any).SKIN;
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    await controller.buySkinGood({ goodId: "SKIN_1" });
    // SKIN 被兜底创建且 info 记录写入
    const skin = (mockPlayer._playerdata.shop as any).SKIN;
    expect(skin).toBeTruthy();
    expect(skin.info).toContainEqual({ id: "SKIN_1", count: 1 });
  });

  it("shop.SKIN 已存在但 info 缺失时购买不 500（字段补全）", async () => {
    (mockPlayer._playerdata.shop as any).SKIN = { curShopId: "", gachaGood: { info: [] } };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    await controller.buySkinGood({ goodId: "SKIN_1" });
    const skin = (mockPlayer._playerdata.shop as any).SKIN;
    expect(skin.info).toContainEqual({ id: "SKIN_1", count: 1 });
  });

  it("已拥有皮肤拒绝重复购买", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    await expect(
      controller.buySkinGood({ goodId: "SKIN_OWNED" }),
    ).rejects.toThrow();
  });

  it("正常购买应扣源石并记录 SKIN.info", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    await controller.buySkinGood({ goodId: "SKIN_1" });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "4002", type: "DIAMOND", count: 18 }],
    ]);
    const skin = (mockPlayer._playerdata.shop as any).SKIN;
    expect(skin.info).toContainEqual({ id: "SKIN_1", count: 1 });
  });

  it("源石不足拒绝购买", async () => {
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.ShopTable.skinGoodList.goodList.push({
      goodId: "SKIN_2",
      skinId: "skin_2",
      price: 9999,
    });
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    await expect(controller.buySkinGood({ goodId: "SKIN_2" })).rejects.toThrow();
  });
});

describe("ShopManager 根据卡池自动生成（HS 高级凭证区 / CLASSIC 通用凭证区）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      status: { lggShard: 0, hggShard: 100000 } as any,
      shop: {
        HS: { info: [], progressInfo: {} },
        CLASSIC: { info: [], progressInfo: {} },
        LS: { curShopId: "s69", curGroupId: "g2", info: [{ id: "LS_1", count: 2 }] },
        SOCIAL: { curShopId: "", info: [{ id: "SOCIAL20260101_T1_recruit_1_1", count: 1 }], charPurchase: {} },
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
    const excelMock = (await import("@excel/excel")).default as any;
    // 当前活跃标准池（gachaRuleType 数字 0）+ 中坚池（CLASSIC）
    excelMock.GachaTable = {
      gachaPoolClient: [
        {
          gachaPoolId: "NORM_76_0_1",
          gachaRuleType: 0,
          gachaIndex: 100,
          openTime: 1700000000,
          endTime: 1900000000,
        },
        {
          gachaPoolId: "CLASSIC_76_0_1",
          gachaRuleType: "CLASSIC",
          gachaIndex: 200,
          openTime: 1700000000,
          endTime: 1900000000,
        },
      ],
    };
    excelMock.GachaDetailTable = {
      details: {
        NORM_76_0_1: {
          availCharInfo: {
            perAvailList: [
              { rarityRank: 5, charIdList: ["char_6s", "char_6s2"], totalPercent: 0.02 },
              { rarityRank: 4, charIdList: ["char_5s", "char_5s2"], totalPercent: 0.08 },
            ],
          },
        },
        CLASSIC_76_0_1: {
          upCharInfo: {
            perCharList: [
              { rarityRank: 5, charIdList: ["char_old6"], percent: 0.25, count: 2 },
              { rarityRank: 4, charIdList: ["char_old5"], percent: 0.16, count: 3 },
            ],
          },
        },
      },
    };
    excelMock.CharacterTable = {
      char_6s: { name: "六星甲" },
      char_6s2: { name: "六星乙" },
      char_5s: { name: "五星甲" },
      char_old6: { name: "老六星" },
      char_old5: { name: "老五星" },
    };
    excelMock.ShopTable.highGoodList = {
      goodList: [{ goodId: "HS_MAT", item: { id: "32001", count: 1 }, price: 20, progressGoodId: "" }],
      progressGoodList: {},
      newFlag: [],
    };
    excelMock.ShopTable.classicGoodList = {
      goodList: [{ goodId: "KS_PROG", item: null, price: 0, progressGoodId: "AAA1" }],
      progressGoodList: { AAA1: [] },
      newFlag: [],
    };
  });

  it("buildHighCharGoods 按当前标准池生成 6★180/5★45", () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const goods = controller.buildHighCharGoods();
    // 6★ → 180
    expect(goods.find((g) => g.item.id === "char_6s")?.price).toBe(180);
    expect(goods.find((g) => g.item.id === "char_6s2")?.price).toBe(180);
    // 5★ → 45
    expect(goods.find((g) => g.item.id === "char_5s")?.price).toBe(45);
    // goodId 稳定且带池前缀
    expect(goods[0].goodId.startsWith("HS_NORM_76_0_1_")).toBe(true);
    // 时间窗 = 池时间
    expect(goods[0].goodStartTime).toBe(1700000000);
  });

  it("buildClassicCharGoods 按当前中坚池生成 6★2000/5★500", () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const goods = controller.buildClassicCharGoods();
    expect(goods.find((g) => g.item.id === "char_old6")?.price).toBe(2000);
    expect(goods.find((g) => g.item.id === "char_old5")?.price).toBe(500);
    expect(goods[0].goodId.startsWith("KS_CLASSIC_76_0_1_")).toBe(true);
  });

  it("buildHighGoodList 合并动态干员 + 静态材料区", () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const list = controller.buildHighGoodList();
    const ids = list.goodList.map((g) => g.goodId);
    expect(ids.some((id) => id.startsWith("HS_NORM_76_0_1_"))).toBe(true);
    expect(ids).toContain("HS_MAT");
  });

  it("buyHighGood 支持购买动态生成商品（按池扣高级凭证）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const good = controller.buildHighCharGoods().find((g) => g.item.id === "char_6s")!;
    const items = await controller.buyHighGood({ goodId: good.goodId, count: 1 });
    expect(items).toEqual([{ id: "char_6s", count: 1, type: "CHAR", instId: 0 }]);
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "4004", count: 180 }],
    ]);
  });

  it("buyClassicGood 支持购买动态生成商品（按池扣 2000）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const good = controller.buildClassicCharGoods().find((g) => g.item.id === "char_old6")!;
    const items = await controller.buyClassicGood({ goodId: good.goodId, count: 1 });
    expect(items).toEqual([{ id: "char_old6", count: 1, type: "CHAR", instId: 0 }]);
  });

  it("refreshSocialShop 手动刷新信用交易所（重置 LS/SOCIAL 购买记录）", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    await controller.refreshSocialShop();
    const shop = mockPlayer._playerdata.shop as any;
    expect(shop.LS.info).toEqual([]);
    expect(shop.SOCIAL.info).toEqual([]);
    // SOCIAL.curShopId 更新为当天
    const t = new Date();
    const p = (n: number) => String(n).padStart(2, "0");
    expect(shop.SOCIAL.curShopId).toBe(`SOCIAL${t.getFullYear()}${p(t.getMonth() + 1)}${p(t.getDate())}`);
  });

  it("无活跃池时回退最近一期标准池", async () => {
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.GachaTable.gachaPoolClient = [
      { gachaPoolId: "NORM_74_0_5", gachaRuleType: 0, gachaIndex: 90, openTime: 1700000000, endTime: 1710000000 },
      { gachaPoolId: "CLASSIC_74_0_1", gachaRuleType: "CLASSIC", gachaIndex: 190, openTime: 1700000000, endTime: 1710000000 },
    ];
    excelMock.GachaDetailTable.details = {
      NORM_74_0_5: {
        availCharInfo: { perAvailList: [{ rarityRank: 5, charIdList: ["char_old6b"], totalPercent: 0.02 }] },
      },
      CLASSIC_74_0_1: {
        upCharInfo: { perCharList: [{ rarityRank: 5, charIdList: ["char_old6c"], percent: 0.25, count: 1 }] },
      },
    };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    // 已过期池（now > endTime）仍作为最近一期回退
    expect(controller.buildHighCharGoods().some((g) => g.item.id === "char_old6b")).toBe(true);
    expect(controller.buildClassicCharGoods().some((g) => g.item.id === "char_old6c")).toBe(true);
  });

  it("空窗期回退已结束池时商品不受池过期时间影响（goodEndTime 顺延为未来，客户端不判过期）", async () => {
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.GachaTable.gachaPoolClient = [
      { gachaPoolId: "NORM_74_0_5", gachaRuleType: 0, gachaIndex: 90, openTime: 1700000000, endTime: 1710000000 },
      { gachaPoolId: "CLASSIC_74_0_1", gachaRuleType: "CLASSIC", gachaIndex: 190, openTime: 1700000000, endTime: 1710000000 },
    ];
    excelMock.GachaDetailTable.details = {
      NORM_74_0_5: {
        availCharInfo: { perAvailList: [{ rarityRank: 5, charIdList: ["char_old6b"], totalPercent: 0.02 }] },
      },
      CLASSIC_74_0_1: {
        upCharInfo: { perCharList: [{ rarityRank: 5, charIdList: ["char_old6c"], percent: 0.25, count: 1 }] },
      },
    };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    // 回退池已结束（endTime=1710000000 < now），商品 goodEndTime 应顺延为未来，避免客户端按过期时间下架
    const nowSec = Math.floor(Date.now() / 1000);
    for (const g of [
      ...controller.buildHighCharGoods(),
      ...controller.buildClassicCharGoods(),
    ]) {
      // goodStartTime 仍取自池 openTime（过去）
      expect(g.goodStartTime).toBe(1700000000);
      // goodEndTime 不再取已结束池的 endTime，而是未来（持续开放）
      expect(g.goodEndTime).toBeGreaterThan(nowSec);
    }
  });
});

describe("ShopManager 中坚甄选券（FESCLASSIC 自选卡池）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;
  let excelMock: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      // 预留足够高级凭证，供购买甄选券扣费
      status: { hggShard: 100000 } as any,
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
    excelMock = (await import("@excel/excel")).default;
    // 当期活跃中坚甄选池（FESCLASSIC）+ 一个标准池（保持 altre 方法可运行）
    excelMock.GachaTable = {
      gachaPoolClient: [
        {
          gachaPoolId: "NORM_76_0_1",
          gachaRuleType: 0,
          gachaIndex: 100,
          openTime: 1700000000,
          endTime: 1999999999,
        },
        {
          gachaPoolId: "FESCLASSIC_76_0_2",
          gachaRuleType: "FESCLASSIC",
          gachaIndex: 201,
          openTime: 1700000000,
          endTime: 1999999999,
        },
      ],
    };
    excelMock.GachaDetailTable = { details: {} };
    excelMock.ShopTable.highGoodList = {
      goodList: [{ goodId: "HS_MAT", item: { id: "32001", count: 1 }, price: 20, progressGoodId: "" }],
      progressGoodList: {},
      newFlag: [],
    };
    excelMock.ShopTable.classicGoodList = {
      goodList: [{ goodId: "KS_PROG", item: null, price: 0, progressGoodId: "AAA1" }],
      progressGoodList: { AAA1: [] },
      newFlag: [],
    };
  });

  it("buildFesPickGoods 生成 6/5★ 甄选券（HS 180/45，KS 1800/450，item 用官服池化 id）", () => {
    // item_table 收录当期池券 id → 直接采用官服规则 id
    excelMock.ItemTable = {
      items: {
        classic_fes_pick_tier_6_7601: { name: "中坚甄选6星干员" },
        classic_fes_pick_tier_5_7601: { name: "中坚甄选5星干员" },
      },
    };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const hs = controller.buildFesPickGoods("HS");
    expect(hs).toHaveLength(2);
    expect(hs[0]).toMatchObject({
      displayName: "中坚甄选6星干员",
      goodType: "NORMAL",
      price: 180,
      availCount: 1,
      item: { id: "classic_fes_pick_tier_6_7601", count: 1, type: "CLASSIC_FES_PICK_TIER_6" },
    });
    expect(hs[0].goodId).toContain("HS_FESPICK6_");
    expect(hs[1]).toMatchObject({
      displayName: "中坚甄选5星干员",
      price: 45,
      item: { id: "classic_fes_pick_tier_5_7601", type: "CLASSIC_FES_PICK_TIER_5" },
    });
    const ks = controller.buildFesPickGoods("KS");
    expect(ks[0].price).toBe(1800);
    expect(ks[1].price).toBe(450);
    expect(ks[0].goodId).toContain("KS_FESPICK6_");
  });

  it("item_table 未收录当期券时回退到已收录同稀有度券（取后缀最大）", () => {
    excelMock.ItemTable = {
      items: {
        classic_fes_pick_tier_6_3801: { name: "中坚甄选6星干员" },
        classic_fes_pick_tier_6_4401: { name: "中坚甄选6星干员" },
      },
    };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const hs = controller.buildFesPickGoods("HS");
    // 池 76 的券未收录 → 回退到已收录的后缀最大的 6★ 券
    expect(hs[0].item.id).toBe("classic_fes_pick_tier_6_4401");
    // 5★ 完全未收录 → 按官服规则生成池化 id
    expect(hs[1].item.id).toBe("classic_fes_pick_tier_5_7601");
  });

  it("buildHighGoodList / buildClassicGoodList 合并甄选券商品", () => {
    excelMock.ItemTable = {
      items: {
        classic_fes_pick_tier_6_7601: {},
        classic_fes_pick_tier_5_7601: {},
      },
    };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const high = controller.buildHighGoodList();
    expect(high.goodList.some((g) => g.item.type === "CLASSIC_FES_PICK_TIER_6")).toBe(true);
    expect(high.goodList.some((g) => g.goodId.startsWith("HS_FESPICK6_"))).toBe(true);
    const classic = controller.buildClassicGoodList();
    expect(classic.goodList.some((g) => g.item.type === "CLASSIC_FES_PICK_TIER_5")).toBe(true);
    expect(classic.goodList.some((g) => g.goodId.startsWith("KS_FESPICK6_"))).toBe(true);
  });

  it("buyHighGood / buyClassicGood 可购买甄选券并发放券（items:get，非干员）", async () => {
    excelMock.ItemTable = {
      items: {
        classic_fes_pick_tier_6_7601: {},
        classic_fes_pick_tier_5_7601: {},
      },
    };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    const hsGood = controller.buildFesPickGoods("HS").find((g) => g.goodId.startsWith("HS_FESPICK6_"))!;
    const items = await controller.buyHighGood({ goodId: hsGood.goodId, count: 1 });
    expect(items).toEqual([{ id: "classic_fes_pick_tier_6_7601", count: 1, type: "CLASSIC_FES_PICK_TIER_6" }]);
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "4004", count: 180 }]]);
    expect(emitSpy).toHaveBeenCalledWith("items:get", [[{ id: "classic_fes_pick_tier_6_7601", count: 1, type: "CLASSIC_FES_PICK_TIER_6" }]]);
    // 余额不足拒绝（result:1 业务错误）
    (mockPlayer._playerdata.status as any).hggShard = 0;
    const ksGood = controller.buildFesPickGoods("KS").find((g) => g.goodId.startsWith("KS_FESPICK6_"))!;
    await expect(controller.buyClassicGood({ goodId: ksGood.goodId, count: 1 })).rejects.toThrow();
  });

  it("无 FESCLASSIC 池时商店不生成甄选券", () => {
    excelMock.GachaTable = {
      gachaPoolClient: [
        { gachaPoolId: "NORM_76_0_1", gachaRuleType: 0, gachaIndex: 100, openTime: 1700000000, endTime: 1999999999 },
      ],
    };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    expect(controller.buildFesPickGoods("HS")).toEqual([]);
    expect(controller.buildFesPickGoods("KS")).toEqual([]);
  });

  it("FESCLASSIC 池商店干员区反映玩家自选 UP（选择反映在商店）", () => {
    excelMock.GachaDetailTable.details = {
      FESCLASSIC_76_0_2: {
        upCharInfo: {
          perCharList: [
            { rarityRank: 5, charIdList: ["static6"], percent: 0.25, count: 2 },
            { rarityRank: 4, charIdList: ["static5"], percent: 0.1667, count: 3 },
          ],
        },
        availCharInfo: { perAvailList: [] },
      },
    };
    // 模拟玩家在 FESCLASSIC 池的 choosePoolUp 自选（resolveEffectiveUpPerCharList 读取 gacha.fesClassic[poolId].upChar）
    (mockPlayer as any)._playerdata.gacha = {
      fesClassic: {
        FESCLASSIC_76_0_2: {
          upChar: { 5: ["sel_6"], 4: ["sel_5"] },
        },
      },
    };
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const goods = controller.buildClassicCharGoods();
    expect(goods.some((g) => g.item.id === "sel_6" && g.price === 2000)).toBe(true);
    expect(goods.some((g) => g.item.id === "sel_5" && g.price === 500)).toBe(true);
    expect(goods.some((g) => g.item.id === "static6")).toBe(false);
  });
});

describe("LMTGS 按当期卡池代币过滤 + REP 剩余数量", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      shop: { REP: { info: [{ id: "good_REP_1", count: 500 }] } } as any,
      inventory: { LMTGS_COIN_7601: 3000 },
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
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.GachaTable = {
      gachaPoolClient: [
        // 当期活跃限定池
        { gachaPoolId: "LIMITED_76_0_1", gachaRuleType: "LIMITED", gachaIndex: 10, lMTGSID: "LMTGS_COIN_7601", openTime: 1700000000, endTime: 1900000000 },
        // 历史限定池（不应出现在当期商店）
        { gachaPoolId: "LIMITED_23_0_1", gachaRuleType: "LIMITED", gachaIndex: 5, lMTGSID: "LMTGS_COIN_2301", openTime: 1630000000, endTime: 1639999999 },
      ],
    };
    excelMock.GachaDetailTable = {
      details: {
        LIMITED_76_0_1: {
          upCharInfo: {
            perCharList: [
              { rarityRank: 5, charIdList: ["char_1015_aglna2"], percent: 0.35, count: 2 },
              { rarityRank: 4, charIdList: ["char_4237_jcinta"], percent: 0.5, count: 1 },
            ],
          },
        },
        LIMITED_23_0_1: {
          upCharInfo: {
            perCharList: [{ rarityRank: 5, charIdList: ["char_1014_nearl2"], percent: 0.35, count: 2 }],
          },
        },
      },
    };
    excelMock.ShopTable.REPGoodList = {
      goodList: [
        { goodId: "good_REP_1", goodType: "NORMAL", startTime: 0, item: { id: "4003", count: 100, type: "DIAMOND_SHD" }, price: 20, sortId: 1, availCount: 460 },
        { goodId: "good_REP_2", goodType: "NORMAL", startTime: 0, item: { id: "30064", count: 1, type: "MATERIAL" }, price: 85, sortId: 2, availCount: 12 },
      ],
      newFlag: [],
    };
    excelMock.ShopTable.LMTGSGoodList = {
      goodList: [
        // 当期池静态商品（goodId 前缀匹配）
        { goodId: "LIMITED_76_0_1_x", startTime: 0, endTime: 0, availCount: -1, item: { id: "char_special", count: 1, type: "CHAR" }, price: { id: "LMTGS_COIN_7601", count: 300, type: "LMTGS_COIN" }, sortId: 9 },
        // 历史池静态商品（应被过滤）
        { goodId: "LIMITED_23_0_1_y", startTime: 0, endTime: 0, availCount: -1, item: { id: "char_old", count: 1, type: "CHAR" }, price: { id: "LMTGS_COIN_2301", count: 300, type: "LMTGS_COIN" }, sortId: 9 },
      ],
      newFlag: [],
    };
  });

  it("buildLMTGSGoodList 只生成当期池商品（跨池商品不存在）", () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const goods = controller.buildLMTGSGoodList();
    expect(goods.length).toBeGreaterThan(0);
    // 全部商品属于当期池且代币为当期池
    for (const g of goods) {
      expect(g.goodId.startsWith("LIMITED_76_0_1_")).toBe(true);
      expect(g.price.id).toBe("LMTGS_COIN_7601");
    }
    // 历史池 UP（nearl2）作为"历史限定六星"进入当期池（代币仍是当期池）
    expect(goods.some((g) => g.item.id === "char_1014_nearl2" && g.price.id === "LMTGS_COIN_7601")).toBe(true);
    // 不存在非当期池代币
    expect(goods.some((g) => g.price.id !== "LMTGS_COIN_7601")).toBe(false);
  });

  it("currentLimitedPool 无活跃池回退最近一期", async () => {
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.GachaTable.gachaPoolClient = excelMock.GachaTable.gachaPoolClient.map((p: any) => ({
      ...p,
      openTime: 1600000000,
      endTime: 1610000000,
    }));
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    // 全部过期 → 回退最近一期（LIMITED_76_0_1 openTime 更大）
    expect(controller.currentLimitedPool()?.gachaPoolId).toBe("LIMITED_76_0_1");
  });

  it("buildREPGoodList 已购超限时 availCount 抬升（剩余不为负）", () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    const list = controller.buildREPGoodList();
    // good_REP_1 已购 500 > 静态 460 → availCount 抬升到 500，剩余 = 0 不为负
    const g1 = list.goodList.find((g) => g.goodId === "good_REP_1")!;
    expect(g1.availCount).toBe(500);
    // good_REP_2 未购 → 保持静态 12
    const g2 = list.goodList.find((g) => g.goodId === "good_REP_2")!;
    expect(g2.availCount).toBe(12);
  });
});

describe("信用交易所干员合同（点击干员进度不卡死）", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      status: { socialPoint: 500 } as any,
      shop: {
        SOCIAL: {
          curShopId: "",
          info: [],
          // 已购信物：黑角 2 个、坚雷 6 个（满潜）
          charPurchase: { char_198_blackd: 2, char_260_durnar: 6 },
        },
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
    const excelMock = (await import("@excel/excel")).default as any;
    excelMock.ShopTable.skinGoodList = { goodList: [] };
    excelMock.ShopClientTable = {
      creditUnlockGroup: {
        creditGroup1: {
          id: "creditGroup1",
          charDict: [
            { sortId: 1, unlockNum: 0, charId: "char_198_blackd" },
            { sortId: 2, unlockNum: 200, charId: "char_187_ccheal" },
            { sortId: 3, unlockNum: 500, charId: "char_198_blackd" },
            { sortId: 4, unlockNum: 500, charId: "char_187_ccheal" },
            { sortId: 5, unlockNum: 1000, charId: "char_198_blackd" },
            { sortId: 6, unlockNum: 1000, charId: "char_187_ccheal" },
            { sortId: 7, unlockNum: 1500, charId: "char_198_blackd" },
            { sortId: 8, unlockNum: 1500, charId: "char_187_ccheal" },
          ],
        },
        creditGroup2: {
          id: "creditGroup2",
          charDict: [
            { sortId: 1, unlockNum: 4000, charId: "char_260_durnar" },
            { sortId: 2, unlockNum: 5000, charId: "char_260_durnar" },
            { sortId: 3, unlockNum: 6000, charId: "char_260_durnar" },
          ],
        },
      },
    };
    // 基座商品
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = {
      goodList: [
        {
          goodId: "SOCIAL20211106_T2_goods_19_2",
          displayName: "碳素",
          originPrice: 200,
          price: 50,
          discount: 0.75,
          slotId: 2,
          availCount: 1,
          item: { id: "3113", count: 3, type: "MATERIAL" },
        },
      ],
      charPurchase: { char_187_ccheal: 1 },
    };
  });

  it("buildSocialGoodList 生成干员合同商品并补 creditGroup/costSocialPoint", () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = {
      goodList: [
        {
          goodId: "SOCIAL20211106_T2_goods_19_2",
          displayName: "碳素",
          originPrice: 200,
          price: 50,
          discount: 0.75,
          slotId: 2,
          availCount: 1,
          item: { id: "3113", count: 3, type: "MATERIAL" },
        },
      ],
      charPurchase: { char_187_ccheal: 1 },
    };
    const list = controller.buildSocialGoodList() as any;
    // 干员合同：只生成 1 个"当前干员"（黑角已购 2 → 剩余 6-2=4，上限固定 6）
    const chars = list.goodList.filter((g: any) => g.item?.type === "CHAR");
    expect(chars).toHaveLength(1);
    const blackd = chars[0];
    expect(blackd.item.id).toBe("char_198_blackd");
    expect(blackd.availCount).toBe(4);
    // 坚雷已满潜（6）→ 不再生成合同
    expect(list.goodList.find((g: any) => g.item?.id === "char_260_durnar")).toBeFalsy();
    // 有干员合同 → 共 1 干员 + 9 随机物资 = 10 个
    expect(list.goodList).toHaveLength(10);
    expect(list.goodList.filter((g: any) => g.item?.type !== "CHAR")).toHaveLength(9);
    // 干员合同占第 1 栏位
    expect(list.goodList[0].item.type).toBe("CHAR");
    // 其余 9 个为当日候选池随机物资（goodId 为 _T2_goods）
    for (const g of list.goodList.slice(1)) {
      expect(g.goodId).toMatch(/^SOCIAL\d{8}_T2_goods_\d+_\d+$/);
    }
    // 关键修复字段：creditGroup/costSocialPoint 非空
    expect(list.creditGroup).toBe("creditGroup2"); // 有 creditGroup2 干员（坚雷）
    expect(list.costSocialPoint).toBeGreaterThan(0);
    // charPurchase 合并（静态嘉维尔 1 + 玩家黑角 2/坚雷 6）
    expect(list.charPurchase).toMatchObject({
      char_198_blackd: 2,
      char_260_durnar: 6,
      char_187_ccheal: 1,
    });
  });

  it("buySocialGood 购买干员合同更新 charPurchase 并累计消费", async () => {
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = {
      goodList: [
        {
          goodId: "SOCIAL20211106_T2_goods_19_2",
          displayName: "碳素",
          originPrice: 200,
          price: 50,
          discount: 0.75,
          slotId: 2,
          availCount: 1,
          item: { id: "3113", count: 3, type: "MATERIAL" },
        },
      ],
      charPurchase: { char_187_ccheal: 1 },
    };
    const list = controller.buildSocialGoodList() as any;
    const blackd = list.goodList.find((g: any) => g.item?.id === "char_198_blackd");
    // 价格 = 按已购 2 档（unlockNum 500 档）→ 140
    await controller.buySocialGood({ goodId: blackd.goodId, count: 1 });
    const social = (mockPlayer._playerdata.shop as any).SOCIAL;
    expect(social.charPurchase.char_198_blackd).toBe(3);
    // 累计信用消费累计（price 140）
    expect(social.costSocialPoint).toBe(140);
  });

  it("全部干员满潜（6）→ 无干员合同，10 个常规商品（若已换完）", async () => {
    // 玩家 3 干员全满潜
    const excelMock = (await import("@excel/excel")).default as any;
    mockPlayer._playerdata.shop.SOCIAL.charPurchase = {
      char_198_blackd: 6,
      char_187_ccheal: 6,
      char_260_durnar: 6,
    };
    // 基座 10 个常规商品
    const baseGoods = Array.from({ length: 10 }, (_, i) => ({
      goodId: `SOCIAL20211106_T2_goods_${i}_${i + 1}`,
      displayName: `材料${i}`,
      originPrice: 100,
      price: 50,
      discount: 0.5,
      slotId: i + 1,
      availCount: 1,
      item: { id: `3001${i}`, count: 1, type: "MATERIAL" },
    }));
    const controller = new ShopManager(mockPlayer as any, mockTrigger as any);
    controller.socialGoodList = { goodList: baseGoods, charPurchase: {} };
    void excelMock;
    const list = controller.buildSocialGoodList() as any;
    // 无干员合同，10 个常规商品
    expect(list.goodList.filter((g: any) => g.item?.type === "CHAR")).toHaveLength(0);
    expect(list.goodList.length).toBe(10);
    // creditGroup 仍为玩家所在组
    expect(list.creditGroup).toBe("creditGroup2");
  });
});
