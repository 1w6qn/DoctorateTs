/**
 * 模板商店路由模块
 * 
 * 处理模板商店相关的 HTTP 请求，包括商品列表查询和购买操作。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/**
 * 获取商品列表
 * @route POST /templateShop/getGoodList
 * @param req.body.shopId - 商店ID
 * @returns 商品数据、下次同步时间和玩家增量数据
 */
router.post("/getGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { shopId } = req.body;

  res.send({
    data: {},
    nextSyncTime: -1,
    playerDataDelta: {
      modified: {},
      deleted: {},
    },
  });
});

/**
 * 购买商品
 * @route POST /templateShop/buyGood
 * @returns 请求数据
 */
router.post("/buyGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send(req.body);
});

export default router;