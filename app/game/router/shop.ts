/**
 * 商店路由模块
 * 
 * 处理商店相关的 HTTP 请求，包括商品列表查询和各类商店的购买操作。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import excel from "@excel/excel";

const router = Router();

/**
 * 分解潜能物品
 * @route POST /shop/decomposePotentialItem
 * @param req.body - 分解参数
 * @returns 分解获得的物品和玩家增量数据
 */
router.post("/decomposePotentialItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    items: await player.troop.decomposePotentialItem(req.body),
    ...player.delta,
  });
});

/**
 * 分解经典潜能物品
 * @route POST /shop/decomposeClassicPotentialItem
 * @param req.body - 分解参数
 * @returns 分解获得的物品和玩家增量数据
 */
router.post("/decomposeClassicPotentialItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    items: await player.troop.decomposeClassicPotentialItem(req.body),
    ...player.delta,
  });
});

/**
 * 获取商品购买状态
 * @route POST /shop/getGoodPurchaseState
 * @returns 购买状态和玩家增量数据
 */
router.post("/getGoodPurchaseState", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: {},
    ...player.delta,
  });
});

/**
 * 获取低级商店商品列表
 * @route POST /shop/getLowGoodList
 * @returns 低级商店商品列表和玩家增量数据
 */
router.post("/getLowGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.lowGoodList,
    ...player.delta,
  });
});

/**
 * 获取高级商店商品列表
 * @route POST /shop/getHighGoodList
 * @returns 高级商店商品列表和玩家增量数据
 */
router.post("/getHighGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.highGoodList,
    ...player.delta,
  });
});

/**
 * 获取经典商店商品列表
 * @route POST /shop/getClassicGoodList
 * @returns 经典商店商品列表和玩家增量数据
 */
router.post("/getClassicGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.classicGoodList,
    ...player.delta,
  });
});

/**
 * 获取联合行动商店商品列表
 * @route POST /shop/getEPGSGoodList
 * @returns 联合行动商店商品列表和玩家增量数据
 */
router.post("/getEPGSGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.EPGSGoodList,
    ...player.delta,
  });
});

/**
 * 获取限定商店商品列表
 * @route POST /shop/getLMTGSGoodList
 * @returns 限定商店商品列表和玩家增量数据
 */
router.post("/getLMTGSGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.LMTGSGoodList,
    ...player.delta,
  });
});

/**
 * 获取额外商店商品列表
 * @route POST /shop/getExtraGoodList
 * @returns 额外商店商品列表和玩家增量数据
 */
router.post("/getExtraGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.extraGoodList,
    ...player.delta,
  });
});

/**
 * 获取声望商店商品列表
 * @route POST /shop/getREPGoodList
 * @returns 声望商店商品列表和玩家增量数据
 */
router.post("/getREPGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.REPGoodList,
    ...player.delta,
  });
});

/**
 * 获取皮肤商店商品列表
 * @route POST /shop/getSkinGoodList
 * @returns 皮肤商店商品列表和玩家增量数据
 */
router.post("/getSkinGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.skinGoodList,
    ...player.delta,
  });
});

/**
 * 获取现金商店商品列表
 * @route POST /shop/getCashGoodList
 * @returns 现金商店商品列表和玩家增量数据
 */
router.post("/getCashGoodList", (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.cashGoodList,
    ...player.delta,
  });
});

/**
 * 获取信用商店商品列表
 * @route POST /shop/getGPGoodList
 * @returns 信用商店商品列表和玩家增量数据
 */
router.post("/getGPGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.GPGoodList,
    ...player.delta,
  });
});

/**
 * 获取社交商店商品列表
 * @route POST /shop/getSocialGoodList
 * @returns 社交商店商品列表和玩家增量数据
 */
router.post("/getSocialGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...player.shop.socialGoodList,
    ...player.delta,
  });
});

/**
 * 获取家具商店商品列表
 * @route POST /shop/getFurniGoodList
 * @returns 家具商店商品列表和玩家增量数据
 */
router.post("/getFurniGoodList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...excel.ShopTable.furniGoodList,
    ...player.delta,
  });
});

/**
 * 购买低级商店商品
 * @route POST /shop/buyLowGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyLowGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    items: await player.shop.buyLowGood(req.body),
    ...player.delta,
  });
});

/**
 * 购买高级商店商品
 * @route POST /shop/buyHighGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyHighGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    items: await player.shop.buyHighGood(req.body),
    ...player.delta,
  });
});

/**
 * 购买额外商店商品
 * @route POST /shop/buyExtraGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyExtraGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    items: await player.shop.buyExtraGood(req.body),
    ...player.delta,
  });
});

/**
 * 购买现金商店商品
 * @route POST /shop/buyCashGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyCashGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.shop.buyCashGood(req.body);
  res.send({
    result: 0,
    ...player.delta,
  });
});

/**
 * 购买联合行动商店商品
 * @route POST /shop/buyEPGSGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyEPGSGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    items: await player.shop.buyEPGSGood(req.body),
    ...player.delta,
  });
});

/**
 * 购买声望商店商品
 * @route POST /shop/buyREPGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyREPGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    items: await player.shop.buyREPGood(req.body),
    ...player.delta,
  });
});

/**
 * 购买经典商店商品
 * @route POST /shop/buyClassicGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyClassicGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    items: await player.shop.buyClassicGood(req.body),
    ...player.delta,
  });
});

/**
 * 购买限定商店商品
 * @route POST /shop/buyLMTGSGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyLMTGSGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    items: await player.shop.buyLMTGSGood(req.body),
    ...player.delta,
  });
});

/**
 * 购买家具商店商品
 * @route POST /shop/buyFurniGood
 * @param req.body - 购买参数
 * @returns 购买结果和玩家增量数据
 */
router.post("/buyFurniGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    items: await player.shop.buyFurniGood(req.body),
    ...player.delta,
  });
});

/**
 * 购买皮肤商店商品
 * @route POST /shop/buySkinGood
 * @param req.body - 购买参数
 * @returns 玩家增量数据
 */
router.post("/buySkinGood", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.shop.buySkinGood(req.body);
  res.send({
    ...player.delta,
  });
});

export default router;