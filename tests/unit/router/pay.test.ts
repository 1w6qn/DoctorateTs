import { describe, it, expect, vi, beforeEach } from "vitest";
import { createHmac } from "node:crypto";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

// AllProductList 商品表（vi.mock 工厂提升，数据须内联）
vi.mock("@utils/file", () => ({
  readJsonSync: vi.fn(() => ({
    productList: [
      { store_id: 49, product_id: "CS_1", name: "6元开采源石", price: 600 },
      { store_id: 297, product_id: "CS_1_r1", name: "6元开采源石", price: 600 },
    ],
  })),
}));

/** 支付订单夹具形状（测试可控的内存订单） */
interface PayOrderFixture {
  orderId?: string;
  uid?: string | number;
  storeId?: number;
  goodId: string;
  amount?: number;
  productName?: string;
  status?: string;
  createdAt?: number;
  paidAt?: number;
}

/** 支付配置服务端扩展键视图（notifySecret 未在 config 类型声明，见 pay/routes.ts） */
interface PayConfigExt {
  mode?: "fake" | "real";
  notifySecret?: string;
}

// 支付订单存储 mock（内存数组，测试可控）
const orderStore: PayOrderFixture[] = [];
vi.mock("@game/modules/pay/pay-store", () => ({
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
  deliverOrder: vi.fn(async (_player: MockPlayerDataManager, order: PayOrderFixture) => {
    if (order.goodId.startsWith("CS_")) {
      return [{ id: "4002", type: "DIAMOND", count: 3 }];
    }
    return [];
  }),
}));

import type { Response } from "express";
import httpContext from "express-http-context2";
import payRouter from "@game/modules/pay/routes";
import config from "@core/config/index";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";

/** 支付请求体视图（本文件各端点字段合集） */
interface PayBody {
  storeId?: number;
  goodId?: string;
  orderId?: string;
  enterTs?: number;
  out_trade_no?: string;
  trade_status?: string;
  sign?: string;
  total_amount?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: PayBody;
}

/** 路由测试响应视图（只声明被测分支读到的三个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof payRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    json: vi.fn<Response["json"]>(),
  };
}

/** 覆写支付配置（config.pay 的服务端扩展键，见 app/game/modules/pay/routes.ts#notifySecret） */
function setPayConfig(pay: PayConfigExt): void {
  (config as { pay?: PayConfigExt }).pay = pay;
}

describe("pay 路由（完整支付流程 + fake/real 模式）", () => {
  let player: MockPlayerDataManager;
  let res: MockRes;

  beforeEach(() => {
    vi.clearAllMocks();
    orderStore.length = 0;
    player = mockPlayerData({
      shop: { CASH: { info: [] } },
    });
    res = mockRes();
    vi.mocked(httpContext.get).mockReturnValue(player);
    // 恢复 fake 模式
    setPayConfig({ mode: "fake" });
  });

  async function call(url: string, body: PayBody) {
    const req: MockReq = { method: "POST", url, body };
    // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
    payRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("createOrder 创建订单并持久化（extension 含 orderId）", async () => {
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const sent = vi.mocked(res.send).mock.calls[0][0];
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
    const orderId = vi.mocked(res.send).mock.calls[0][0].orderId;
    await call("/confirmOrderAlipay", { orderId });
    expect(orderStore[0].status).toBe("paid");
    await call("/confirmOrder", { orderId, enterTs: 0 });
    // send 调用序：0=createOrder, 1=confirmOrderAlipay, 2=confirmOrder
    const sent = vi.mocked(res.send).mock.calls[2][0];
    expect(sent.result).toBe(0);
    expect(sent.receiveItems.items).toEqual([{ id: "4002", type: "DIAMOND", count: 3 }]);
    expect(orderStore[0].status).toBe("delivered");
  });

  it("防重复发货：delivered 订单再次 confirmOrder 返回 result:1", async () => {
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = vi.mocked(res.send).mock.calls[0][0].orderId;
    await call("/confirmOrderAlipay", { orderId });
    await call("/confirmOrder", { orderId, enterTs: 0 });
    await call("/confirmOrder", { orderId, enterTs: 0 });
    // send 调用序：0=createOrder, 1=alipay, 2=首次 confirmOrder, 3=重复 confirmOrder
    const sent = vi.mocked(res.send).mock.calls[3][0];
    expect(sent.result).toBe(1);
    expect(sent.receiveItems.items).toEqual([]);
  });

  it("real 模式：created 订单 confirmOrder 拒绝（未支付）", async () => {
    setPayConfig({ mode: "real" });
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = vi.mocked(res.send).mock.calls[0][0].orderId;
    await call("/confirmOrder", { orderId, enterTs: 0 });
    const sent = vi.mocked(res.send).mock.calls[1][0];
    expect(sent.result).toBe(1); // 未支付拒绝
    expect(orderStore[0].status).toBe("created");
  });

  it("real 模式：notify 回调（验签+金额一致）标记 paid 后 confirmOrder 发货", async () => {
    setPayConfig({ mode: "real", notifySecret: "test-secret" });
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = vi.mocked(res.send).mock.calls[0][0].orderId;
    // 渠道异步回调：签名 = HMAC-SHA256(`${orderId}|${amountCents}`, secret)
    const sign = createHmac("sha256", "test-secret")
      .update(`${orderId}|600`)
      .digest("hex");
    await call("/notify", {
      out_trade_no: orderId,
      trade_status: "TRADE_SUCCESS",
      sign,
      total_amount: "6.00",
    });
    expect(orderStore[0].status).toBe("paid");
    await call("/confirmOrder", { orderId, enterTs: 0 });
    const sent = vi.mocked(res.send).mock.calls[2][0];
    expect(sent.result).toBe(0);
    expect(sent.receiveItems.items).toHaveLength(1);
    expect(orderStore[0].status).toBe("delivered");
  });

  it("getUnconfirmedOrderIdList 返回该 uid 未交付订单", async () => {
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = vi.mocked(res.send).mock.calls[0][0].orderId;
    await call("/getUnconfirmedOrderIdList", {});
    const sent = vi.mocked(res.send).mock.calls[1][0];
    expect(sent.orderIdList).toContain(orderId);
  });

  it("real 模式：notify 未验签应拒绝（订单保持 created）", async () => {
    setPayConfig({ mode: "real", notifySecret: "test-secret" });
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = vi.mocked(res.send).mock.calls[0][0].orderId;
    await call("/notify", { out_trade_no: orderId, trade_status: "TRADE_SUCCESS" });
    expect(orderStore[0].status).toBe("created");
  });

  it("real 模式：notify 金额不符应拒绝", async () => {
    setPayConfig({ mode: "real", notifySecret: "test-secret" });
    await call("/createOrder", { storeId: 49, goodId: "CS_1" });
    const orderId = vi.mocked(res.send).mock.calls[0][0].orderId;
    const sign = createHmac("sha256", "test-secret")
      .update(`${orderId}|600`)
      .digest("hex");
    await call("/notify", {
      out_trade_no: orderId,
      trade_status: "TRADE_SUCCESS",
      sign,
      total_amount: "1.00", // 与订单 600 分不符
    });
    expect(orderStore[0].status).toBe("created");
  });

  it("createOrder：goodId 与 storeId 不匹配应拒绝且不建单", async () => {
    await call("/createOrder", { storeId: 49, goodId: "GP_gW_10_W_1" });
    const sent = vi.mocked(res.send).mock.calls[0][0];
    expect(sent.result).toBe(1);
    expect(orderStore).toHaveLength(0);
  });

  it("createOrder：未知 storeId 应拒绝且不建单", async () => {
    await call("/createOrder", { storeId: 9999, goodId: "CS_1" });
    const sent = vi.mocked(res.send).mock.calls[0][0];
    expect(sent.result).toBe(1);
    expect(orderStore).toHaveLength(0);
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
    const sent = vi.mocked(res.send).mock.calls[0][0];
    expect(sent.result).toBe(1);
    expect(orderStore[0].status).toBe("paid"); // 订单保留
  });
});
