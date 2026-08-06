/**
 * 支付路由
 *
 * 私服支付简化：订单列表为空（参考 DoctoratePy pay.py payGetUnconfirmedOrderIdList）
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/** 未确认订单列表（私服无真实支付——返回空） */
router.post("/getUnconfirmedOrderIdList", async (req, res) => {
  httpContext.get<PlayerDataManager>("playerData");
  res.send({
    orderIdList: [],
    playerDataDelta: { deleted: {}, modified: {} },
  });
});

export default router;
