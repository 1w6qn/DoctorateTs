import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import httpContext from "express-http-context2";
import payRouter from "../../../app/game/router/pay";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("pay 路由", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    player = {
      delta: { playerDataDelta: { modified: {}, deleted: {} } },
      shop: {
        buyCashGood: vi
          .fn()
          .mockResolvedValue([{ id: "4002", type: "DIAMOND", count: 6 }]),
      },
    };
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    payRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /createOrder 应生成订单并返回对齐抓包的 extension JSON（storeId=49 → 6元开采源石）", async () => {
    await call("/createOrder", { storeId: 49, goodId: "CS_1_r1" });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toBe(0);
    expect(typeof sent.orderId).toBe("string");
    expect(sent.alertMinor).toBe(0);
    const ext = JSON.parse(sent.extension);
    expect(ext.amount).toBe(600);
    expect(ext.productName).toBe("6元开采源石");
    expect(ext.extension.appStoreProductId).toBe("CS_1_r1");
    expect(ext.outOrderId).toBe(sent.orderId);
    expect(ext.platform).toBe(1);
    expect(String(ext.uid)).toMatch(/^\d{13}$/);
    expect(ext.sign).toMatch(/^[0-9a-f]{32}$/);
  });

  it("POST /confirmOrder 现金包应复用 shop.buyCashGood 发放钻石", async () => {
    // 先创建订单（内存订单表）
    await call("/createOrder", { storeId: 49, goodId: "CS_1_r1" });
    const orderId = res.send.mock.calls[0][0].orderId;

    await call("/confirmOrder", { orderId, enterTs: 0 });
    expect(player.shop.buyCashGood).toHaveBeenCalledWith({ goodId: "CS_1_r1" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        result: 0,
        goodId: "CS_1_r1",
        receiveItems: {
          items: [{ id: "4002", type: "DIAMOND", count: 6 }],
          checkInItems: [],
        },
        playerDataDelta: { modified: {}, deleted: {} },
      })
    );
  });

  it("POST /confirmOrder 未知订单应返回 result 1 不发放", async () => {
    await call("/confirmOrder", { orderId: "not-exist", enterTs: 0 });
    expect(player.shop.buyCashGood).not.toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 1, goodId: "" })
    );
  });
});
