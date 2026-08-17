import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// AllProductList 商品表（vi.mock 工厂提升，数据须内联）
vi.mock("../../../app/utils/file", () => ({
  readJsonSync: vi.fn(() => ({
    productList: [
      { store_id: 49, product_id: "CS_1", name: "6元开采源石", price: 600 },
      { store_id: 297, product_id: "CS_1_r1", name: "6元开采源石", price: 600 },
    ],
  })),
}));

// 支付订单存储 mock（内存数组，测试可控）
const orderStore: any[] = [];
vi.mock("../../../app/game/pay-store", () => ({
  loadOrders: vi.fn(() => orderStore),
  saveOrders: vi.fn(() => {}),
  markPaid: vi.fn((orderId: string) => {
    const o = orderStore.find((x) => x.orderId === orderId);
    if (o && o.status !== "delivered") {
      if (o.status !== "paid") {
        o.status = "paid";
        o.paidAt = 1700000000;
      }
      return o;
    }
    return null;
  }),
  deliverOrder: vi.fn(async (_player: any, order: any) => {
    if (order.goodId.startsWith("CS_")) {
      return [{ id: "4002", type: "DIAMOND", count: 3 }];
    }
    return [];
  }),
}));

import httpContext from "express-http-context2";
import payRouter from "../../../app/game/router/pay";
import config from "../../../app/config";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), json: vi.fn() };
}

describe("pay 路由（完整支付流程 + fake/real 模式）", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    orderStore.length = 0;
    player = mockPlayerData({
      shop: { CASH: { info: [] } } as any,
    });
    res = mockRes();
    (vi.mocked(httpContext.get) as any).mockReturnValue(player);
    // 恢复 fake 模式
    (config as any).pay = { mode: "fake" };
  });

  async function call(url: string, body: any) {
    payRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("createOrder 创建订单并持久化（extension 含 orderId）", async () => {
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toBe(0);
    expect(sent.orderId).toBeTruthy();
    const ext = JSON.parse(sent.extension);
    expect(ext.amount).toBe(600);
    expect(ext.outOrderId).toBe(sent.orderId);
    // 订单落库（uid 归属 + created 状态）
    expect(orderStore.length).toBe(1);
    expect(orderStore[0].uid).toBe(player.uid);
    expect(orderStore[0].status).toBe("created");
  });

  it("fake 模式：confirmOrderAlipay 标记 paid，confirmOrder 发货", async () => {
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = res.send.mock.calls[0][0].orderId;
    await call("/confirmOrderAlipay", { orderId });
    expect(orderStore[0].status).toBe("paid");
    await call("/confirmOrder", { orderId, enterTs: 0 });
    // send 调用序：0=createOrder, 1=confirmOrderAlipay, 2=confirmOrder
    const sent = res.send.mock.calls[2][0];
    expect(sent.result).toBe(0);
    expect(sent.receiveItems.items).toEqual([{ id: "4002", type: "DIAMOND", count: 3 }]);
    expect(orderStore[0].status).toBe("delivered");
  });

  it("防重复发货：delivered 订单再次 confirmOrder 返回 result:1", async () => {
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = res.send.mock.calls[0][0].orderId;
    await call("/confirmOrderAlipay", { orderId });
    await call("/confirmOrder", { orderId, enterTs: 0 });
    await call("/confirmOrder", { orderId, enterTs: 0 });
    // send 调用序：0=createOrder, 1=alipay, 2=首次 confirmOrder, 3=重复 confirmOrder
    const sent = res.send.mock.calls[3][0];
    expect(sent.result).toBe(1);
    expect(sent.receiveItems.items).toEqual([]);
  });

  it("real 模式：created 订单 confirmOrder 拒绝（未支付）", async () => {
    (config as any).pay = { mode: "real" };
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = res.send.mock.calls[0][0].orderId;
    await call("/confirmOrder", { orderId, enterTs: 0 });
    const sent = res.send.mock.calls[1][0];
    expect(sent.result).toBe(1); // 未支付拒绝
    expect(orderStore[0].status).toBe("created");
  });

  it("real 模式：notify 回调标记 paid 后 confirmOrder 发货", async () => {
    (config as any).pay = { mode: "real" };
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = res.send.mock.calls[0][0].orderId;
    // 渠道异步回调
    await call("/notify", { out_trade_no: orderId, trade_status: "TRADE_SUCCESS" });
    expect(orderStore[0].status).toBe("paid");
    await call("/confirmOrder", { orderId, enterTs: 0 });
    const sent = res.send.mock.calls[2][0];
    expect(sent.result).toBe(0);
    expect(sent.receiveItems.items).toHaveLength(1);
    expect(orderStore[0].status).toBe("delivered");
  });

  it("getUnconfirmedOrderIdList 返回该 uid 未交付订单", async () => {
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = res.send.mock.calls[0][0].orderId;
    await call("/getUnconfirmedOrderIdList", {});
    const sent = res.send.mock.calls[1][0];
    expect(sent.orderIdList).toContain(orderId);
  });

  it("GP_ 无发放配置订单 confirmOrder 拒绝（不误标已购）", async () => {
    orderStore.push({
      orderId: "GP_ORDER_1",
      uid: player.uid,
      storeId: 52,
      goodId: "GP_mCard_1",
      amount: 3000,
      productName: "月卡",
      status: "paid",
      createdAt: 1700000000,
    });
    await call("/confirmOrder", { orderId: "GP_ORDER_1", enterTs: 0 });
    const sent = res.send.mock.calls[0][0];
    expect(sent.result).toBe(1);
    expect(orderStore[0].status).toBe("paid"); // 订单保留
  });
});
