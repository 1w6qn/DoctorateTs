/**
 * 支付路由
 *
 * 私服支付简化：订单列表为空（参考 DoctoratePy pay.py payGetUnconfirmedOrderIdList）；
 * createOrder/confirmOrder 模拟支付成功并发放商品（现金包 CS_ → 钻石，
 * 参考 DoctoratePy payConfirmOrder + 本项目 shop buyCashGood 首充双倍逻辑）。
 * 请求/响应类型见 @game/model/protocol/pay（参考 CS 2.7.61 协议类 + 抓包）。
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import { readJson } from "@utils/file";
import {
  PayGetUnconfirmedOrderListRequest,
  PayGetUnconfirmedOrderListResponse,
  PayCreateOrderRequest,
  PayCreateOrderResponse,
  PayConfirmOrderRequest,
  PayConfirmOrderResponse,
} from "../model/protocol/pay";

const router = Router();

/** 内存订单表（参考 DoctoratePy TemporaryData.order_data_list）——重启即失效，私服可接受 */
const orderDataList: { [orderId: string]: { storeId: number; goodId: string } } = {};

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

/** 未确认订单列表（私服无真实支付——返回空） */
router.post("/getUnconfirmedOrderIdList", async (req, res) => {
  httpContext.get<PlayerDataManager>("playerData");
  req.body as PayGetUnconfirmedOrderListRequest;
  res.send({
    orderIdList: [],
    playerDataDelta: { deleted: {}, modified: {} },
  } satisfies PayGetUnconfirmedOrderListResponse);
});

/**
 * 创建订单（CS: PayCreateOrderRequest { storeId, goodId }）
 * 从 AllProductList.json 查商品生成订单，返回 extension JSON 字符串
 * （形状对齐抓包 tmp/pay_createOrder_res_1016.json）。
 */
router.post("/createOrder", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as PayCreateOrderRequest;
  const productList = (await readJson("./data/shop/AllProductList.json")) as {
    productList?: { store_id: number; price: number; name: string }[];
  };
  const product = (productList.productList ?? []).find(
    (p) => Number(p.store_id) === Number(body.storeId),
  );
  const orderId = genOrderId();
  orderDataList[orderId] = { storeId: body.storeId, goodId: body.goodId };
  const extension = JSON.stringify({
    appCode: randomHex(16),
    amount: product?.price ?? 0,
    productName: product?.name ?? "",
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
 * 确认订单（CS: PayConfirmOrderRequest { orderId, enterTs }）
 * 私服模拟支付成功：现金包（CS_）复用 shop.buyCashGood 发放钻石
 * （含首充双倍 + shop.CASH.info 购买计数），返回 receiveItems。
 */
router.post("/confirmOrder", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as PayConfirmOrderRequest;
  const order = orderDataList[body.orderId];
  if (!order) {
    return res.send({
      result: 1,
      goodId: "",
      receiveItems: { items: [], checkInItems: [] },
      ...player.delta,
    } satisfies PayConfirmOrderResponse);
  }
  let items: ItemBundle[] = [];
  if (order.goodId.startsWith("CS_")) {
    items = await player.shop.buyCashGood({ goodId: order.goodId });
  } else if (order.goodId.startsWith("GP_")) {
    // 修复：GP_ 礼包（月卡/通行证等 362 款）无发放实现——原实现返回成功但不发任何
    // 东西（客户端标记已购、玩家白花钱）；按参考实现返回失败，避免误标已购
    return res.send({
      result: 1,
      goodId: order.goodId,
      receiveItems: { items: [], checkInItems: [] },
      ...player.delta,
    } satisfies PayConfirmOrderResponse);
  }
  delete orderDataList[body.orderId];
  res.send({
    result: 0,
    goodId: order.goodId,
    receiveItems: { items, checkInItems: [] },
    ...player.delta,
  } satisfies PayConfirmOrderResponse);
});

export default router;
