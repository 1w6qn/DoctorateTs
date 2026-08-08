/**
 * 模板商店路由模块
 * 
 * 处理模板商店相关的 HTTP 请求，包括商品列表查询和购买操作。
 * 请求/响应类型见 @game/model/protocol/templateShop（参考 CS 2.7.61 协议类）。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  TemplateBuyGoodRequest,
  TemplateBuyGoodResponse,
  TemplateGetGoodListRequest,
  TemplateGetGoodListResponse,
} from "../model/protocol/templateShop";

const router = Router();

/**
 * 获取商品列表
 * @route POST /templateShop/getGoodList
 * @param req.body.shopId - 商店ID
 * @returns 商品数据、下次同步时间和玩家增量数据
 */
router.post("/getGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { shopId } = req.body as TemplateGetGoodListRequest;

  res.send({
    data: {},
    nextSyncTime: -1,
    playerDataDelta: {
      modified: {},
      deleted: {},
    },
  } satisfies TemplateGetGoodListResponse);
});

/**
 * 购买商品
 * @route POST /templateShop/buyGood
 * @returns 请求数据
 */
router.post("/buyGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as TemplateBuyGoodRequest;

  res.send(req.body satisfies TemplateBuyGoodResponse);
});

export default router;
