import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({ default: {} }));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/shop", () => ({}));
vi.mock("@excel/types_auto_gen", () => ({}));

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
