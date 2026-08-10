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
