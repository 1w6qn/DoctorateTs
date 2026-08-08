/**
 * 支付路由
 *
 * 私服支付简化：订单列表为空（参考 DoctoratePy pay.py payGetUnconfirmedOrderIdList）
 * 请求/响应类型见 @game/model/protocol/pay（参考 CS 2.7.61 协议类）。
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  PayGetUnconfirmedOrderListRequest,
  PayGetUnconfirmedOrderListResponse,
} from "../model/protocol/pay";

const router = Router();

/** 未确认订单列表（私服无真实支付——返回空） */
router.post("/getUnconfirmedOrderIdList", async (req, res) => {
  httpContext.get<PlayerDataManager>("playerData");
  req.body as PayGetUnconfirmedOrderListRequest;
  res.send({
    orderIdList: [],
    playerDataDelta: { deleted: {}, modified: {} },
  } satisfies PayGetUnconfirmedOrderListResponse);
});

export default router;
