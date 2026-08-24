/**
 * 支付路由（完整支付流程 + 可配置真实/虚假支付）
 *
 * 支付流程：createOrder（创建订单，持久化 data/pay/orders.json）→
 * createOrderAlipay/Wechat（生成支付宝/微信支付参数）→ confirmOrderAlipay/Wechat（支付确认）→
 * confirmOrder（发货：CS_ 现金包 → 钻石（含首充双倍），GP_ 礼包 → 礼包物品）。
 * 订单状态机：created → paid → delivered（防重复发货；持久化 JSON，重启不丢）。
 *
 * 支付模式 config.pay.mode：
 * - "fake"（缺省）：虚假支付——confirmOrderAlipay/Wechat 直接标记 paid（模拟渠道确认），
 *   confirmOrder 立即发货，全程免费（私服测试用）
 * - "real"：真实支付——confirmOrderAlipay/Wechat 仅走客户端流程占位，须支付渠道异步回调
 *   /pay/notify（或管理端 `pay order <id> confirm` 手动确认）标记 paid 后，confirmOrder 才发货。
 *   支付宝/微信支付参数可配（config.pay.alipay.appId / wechat.mchId 等）。
 *
 * 请求/响应类型见 @game/model/protocol/pay（参考 CS 2.7.61 协议类 + DoctoratePy pay.py）。
 */
import { Router } from "express";
import { getPlayer, getPlayerOptional } from "../request-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import { readJsonSync } from "@utils/file";
import { logger } from "@utils/logger";
import config from "../../config";
import { validateBody } from "../model/protocol/validate-body";
import {
  confirmOrderAlipaySchema,
  confirmOrderSchema,
  confirmOrderWechatSchema,
  createOrderAlipaySchema,
  createOrderSchema,
  createOrderWechatSchema,
  getUnconfirmedOrderListSchema,
  notifySchema,
} from "../model/protocol/pay.schema";
import {
  loadOrders,
  saveOrders,
  markPaid,
  deliverOrder,
} from "../pay-store";
import {
  PayGetUnconfirmedOrderListRequest,
  PayGetUnconfirmedOrderListResponse,
  PayCreateOrderRequest,
  PayCreateOrderResponse,
  PayCreateOrderAlipayRequest,
  PayCreateOrderAlipayResponse,
  PayCreateOrderWechatRequest,
  PayCreateOrderWechatResponse,
  PayConfirmOrderRequest,
  PayConfirmOrderResponse,
  PayConfirmOrderAlipayRequest,
  PayConfirmOrderAlipayResponse,
  PayConfirmOrderWechatRequest,
  PayConfirmOrderWechatResponse,
  PayNotifyRequest,
  PayNotifyResponse,
  PaySuccessResponse,
} from "../model/protocol/pay";

const router = Router();

/** 生成订单号（参考 DoctoratePy：日期时间 + 18 位随机数） */
function genOrderId(): string {
  const ts = new Date()
    .toISOString()
    .replace(/[-T:.Z]/g, "")
    .slice(0, 14);
  let rand = "";
  for (let i = 0; i < 18; i++) rand += Math.floor(Math.random() * 10);
  return ts + rand;
}

/** 生成 n 位随机十六进制串（对齐抓包 extension 的 appCode/sign 形状） */
function randomHex(len: number): string {
  const hex = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < len; i++) out += hex[Math.floor(Math.random() * 16)];
  return out;
}

/** 生成 n 位随机数字串（对齐抓包 extension 的 uid 形状） */
function randomDigits(len: number): string {
  let out = "";
  for (let i = 0; i < len; i++) out += Math.floor(Math.random() * 10);
  return out;
}

/** 支付模式（config.pay.mode，缺省 fake） */
function payMode(): "fake" | "real" {
  return config.pay?.mode === "real" ? "real" : "fake";
}

/** 商品信息（AllProductList 按 store_id） */
function productInfo(storeId: number): {
  amount: number;
  productName: string;
} {
  try {
    const list = readJsonSync<{ productList?: { store_id: number; price: number; name: string }[] }>(
      "./data/shop/AllProductList.json",
    );
    const p = (list.productList ?? []).find(
      (x) => Number(x.store_id) === Number(storeId),
    );
    return { amount: p?.price ?? 0, productName: p?.name ?? "" };
  } catch {
    return { amount: 0, productName: "" };
  }
}

/** 未确认订单列表（该 uid 未交付的订单 id） */
router.post("/getUnconfirmedOrderIdList", validateBody(getUnconfirmedOrderListSchema), async (req, res) => {
  const player = getPlayer();
  req.body as PayGetUnconfirmedOrderListRequest;
  const orders = loadOrders().filter(
    (o) => o.uid === player.uid && o.status !== "delivered",
  );
  res.send({
    orderIdList: orders.map((o) => o.orderId),
    ...player.delta,
  } satisfies PayGetUnconfirmedOrderListResponse);
});

/**
 * 创建订单（CS: PayCreateOrderRequest { storeId, goodId }）
 * 从 AllProductList.json 查商品生成订单（持久化，status=created），返回 extension JSON 字符串
 * （形状对齐抓包 tmp/pay_createOrder_res_1016.json）。
 */
router.post("/createOrder", validateBody(createOrderSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as PayCreateOrderRequest;
  const { amount, productName } = productInfo(body.storeId);
  const orderId = genOrderId();
  const orders = loadOrders();
  orders.push({
    orderId,
    uid: player.uid,
    storeId: body.storeId,
    goodId: body.goodId,
    amount,
    productName,
    status: "created",
    createdAt: now(),
  });
  saveOrders(orders);
  const extension = JSON.stringify({
    appCode: randomHex(16),
    amount,
    productName,
    extension: { appStoreProductId: body.goodId },
    uid: randomDigits(13),
    outOrderId: orderId,
    ts: now(),
    platform: 1,
    sign: randomHex(32),
  });
  res.send({
    result: 0,
    orderId,
    extension,
    alertMinor: 0,
    ...player.delta,
  } satisfies PayCreateOrderResponse);
});

/**
 * 创建支付宝订单（DoctoratePy 兼容：H5/扫码支付）
 * fake 模式返回占位参数；real 模式按 config.pay.alipay 生成（未配置则占位）
 */
router.post("/createOrderAlipay", validateBody(createOrderAlipaySchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as PayCreateOrderAlipayRequest;
  const order = loadOrders().find((o) => o.orderId === body.orderId);
  if (!order) {
    return res.send({
      result: 1,
      orderId: body.orderId,
      qs: "",
      prcie: 0,
      pagePay: null,
      returnUrl: "",
      ...player.delta,
    } satisfies PayCreateOrderAlipayResponse);
  }
  const alipay = config.pay?.alipay;
  const qs = new URLSearchParams({
    app_id: alipay?.appId || randomDigits(16),
    biz_content: JSON.stringify({
      body: order.productName,
      subject: "DoctorateTs",
      out_trade_no: order.orderId,
      timeout_express: "90m",
      total_amount: ((order.amount || 1) / 100).toFixed(2),
      product_code: "FAST_INSTANT_TRADE_PAY",
    }),
    charset: "utf-8",
    format: "JSON",
    method: "alipay.trade.page.pay",
    notify_url: alipay?.notifyUrl || "",
    return_url: "",
    timestamp: new Date().toISOString().replace("T", " ").slice(0, 19),
    sign: randomHex(32),
  }).toString();
  res.send({
    result: 0,
    orderId: order.orderId,
    qs,
    prcie: order.amount,
    pagePay: null,
    returnUrl: "",
    ...player.delta,
  } satisfies PayCreateOrderAlipayResponse);
});

/**
 * 创建微信订单（DoctoratePy 兼容：H5/扫码支付）
 * fake 模式返回占位参数；real 模式按 config.pay.wechat 生成（未配置则占位）
 */
router.post("/createOrderWechat", validateBody(createOrderWechatSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as PayCreateOrderWechatRequest;
  const order = loadOrders().find((o) => o.orderId === body.orderId);
  if (!order) {
    return res.send({
      orderId: body.orderId,
      price: 0,
      requestObj: null,
      ...player.delta,
    } satisfies PayCreateOrderWechatResponse);
  }
  const wechat = config.pay?.wechat;
  res.send({
    orderId: order.orderId,
    price: order.amount,
    requestObj: {
      appid: wechat?.appId || `wx${randomHex(16)}`,
      partnerid: wechat?.mchId || randomDigits(10),
      prepayid: `wx${randomHex(32)}`,
      package: "Sign=WXPay",
      noncestr: `${now()}${randomDigits(7)}`,
      timestamp: now(),
      sign: randomHex(32),
    },
    ...player.delta,
  } satisfies PayCreateOrderWechatResponse);
});

/**
 * 支付宝支付确认（DoctoratePy 兼容）
 * fake 模式：直接标记订单 paid（模拟支付渠道确认，免费成功）
 * real 模式：仅返回占位 status（支付状态由 /pay/notify 渠道回调或管理端确认）
 */
router.post("/confirmOrderAlipay", validateBody(confirmOrderAlipaySchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as PayConfirmOrderAlipayRequest;
  if (payMode() === "fake" && body.orderId) {
    markPaid(body.orderId);
  }
  res.send({
    status: 0,
    ...player.delta,
  } satisfies PayConfirmOrderAlipayResponse);
});

/**
 * 微信支付确认（DoctoratePy 兼容，同 confirmOrderAlipay）
 */
router.post("/confirmOrderWechat", validateBody(confirmOrderWechatSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as PayConfirmOrderWechatRequest;
  if (payMode() === "fake" && body.orderId) {
    markPaid(body.orderId);
  }
  res.send({
    status: 0,
    ...player.delta,
  } satisfies PayConfirmOrderWechatResponse);
});

/**
 * 确认订单（CS: PayConfirmOrderRequest { orderId, enterTs }）
 *
 * 状态机：delivered → 已发货拒绝（防重复发货）；fake 模式 created/paid 均可发货；
 * real 模式仅 paid（支付渠道已确认）才发货，created → result:1 未支付。
 */
router.post("/confirmOrder", validateBody(confirmOrderSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as PayConfirmOrderRequest;
  const orders = loadOrders();
  const order = orders.find((o) => o.orderId === body.orderId);
  if (!order || order.uid !== player.uid) {
    return res.send({
      result: 1,
      goodId: "",
      receiveItems: { items: [], checkInItems: [] },
      ...player.delta,
    } satisfies PayConfirmOrderResponse);
  }
  // 防重复发货
  if (order.status === "delivered") {
    return res.send({
      result: 1,
      goodId: order.goodId,
      receiveItems: { items: [], checkInItems: [] },
      ...player.delta,
    } satisfies PayConfirmOrderResponse);
  }
  // real 模式：未支付拒绝
  if (payMode() === "real" && order.status !== "paid") {
    return res.send({
      result: 1,
      goodId: order.goodId,
      receiveItems: { items: [], checkInItems: [] },
      ...player.delta,
    } satisfies PayConfirmOrderResponse);
  }
  let items: ItemBundle[];
  try {
    items = await deliverOrder(player, order);
  } catch (e) {
    // 修复：发货异常（礼包限购/未知商品等 ShopError）不直接 500——否则客户端弹"服务异常"，
    // 回滚到未发货（订单保留，可重试）；此前部分发放已写入但响应失败，需重启才"到账"。
    logger.warn("pay", `订单 ${order.orderId} 发货失败：${(e as Error)?.message}`);
    return res.send({
      result: 1,
      goodId: order.goodId,
      receiveItems: { items: [], checkInItems: [] },
      ...player.delta,
    } satisfies PayConfirmOrderResponse);
  }
  // GP_ 月卡等无发放配置 → 拒绝（订单保留，不误标已购）
  if (order.goodId.startsWith("GP_") && items.length === 0) {
    return res.send({
      result: 1,
      goodId: order.goodId,
      receiveItems: { items: [], checkInItems: [] },
      ...player.delta,
    } satisfies PayConfirmOrderResponse);
  }
  order.status = "delivered";
  order.deliveredAt = now();
  saveOrders(orders);
  res.send({
    result: 0,
    goodId: order.goodId,
    receiveItems: { items, checkInItems: [] },
    ...player.delta,
  } satisfies PayConfirmOrderResponse);
});

/**
 * 支付渠道异步回调（real 模式核心——支付宝/微信 notify_url 指向此端点）
 * body 支持 out_trade_no 或 orderId；标记订单 paid。
 * 真实渠道接入时在此处验签（config.pay.alipay.privateKey / wechat.apiKey）。
 */
router.post("/notify", validateBody(notifySchema), async (req, res) => {
  const body = (req.body ?? {}) as PayNotifyRequest;
  const orderId = body.orderId || body.out_trade_no || "";
  const ok = orderId ? markPaid(orderId) !== null : false;
  // 支付宝 notify 期望纯文本 "success"；此处统一 JSON（私服内部使用）
  res.send({
    result: ok ? 0 : 1,
    ...(ok ? {} : { errMsg: "order not found" }),
  } satisfies PayNotifyResponse);
});

/** 支付成功页（DoctoratePy paySuccess 兼容；H5 支付跳转返回） */
router.get("/success", async (_req, res) => {
  res.send({
    status: 0,
    message: "DoctorateTs",
  } satisfies PaySuccessResponse);
});

export default router;
