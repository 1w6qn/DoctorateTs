import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import excel from "@excel/excel";

const router = Router();
router.post("/decomposePotentialItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    items: await player.troop.decomposePotentialItem(req.body),
    ...player.delta,
  });
});
router.post("/decomposeClassicPotentialItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    items: await player.troop.decomposeClassicPotentialItem(req.body),
    ...player.delta,
  });
});
router.post("/getGoodPurchaseState", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: {},
    ...player.delta,
  });
});
router.post("/getLowGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.lowGoodList,
    ...player.delta,
  });
});
router.post("/getHighGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.highGoodList,
    ...player.delta,
  });
});
router.post("/getClassicGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.classicGoodList,
    ...player.delta,
  });
});
router.post("/getEPGSGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.EPGSGoodList,
    ...player.delta,
  });
});
router.post("/getLMTGSGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.LMTGSGoodList,
    ...player.delta,
  });
});
router.post("/getExtraGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.extraGoodList,
    ...player.delta,
  });
});
router.post("/getREPGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.REPGoodList,
    ...player.delta,
  });
});
router.post("/getSkinGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.skinGoodList,
    ...player.delta,
  });
});
router.post("/getCashGoodList", (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.cashGoodList,
    ...player.delta,
  });
});
router.post("/getGPGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.GPGoodList,
    ...player.delta,
  });
});
router.post("/getSocialGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...player.shop.socialGoodList,
    ...player.delta,
  });
});

router.post("/buyLowGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyLowGood(req.body),
    ...player.delta,
  });
});
router.post("/buyHighGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyHighGood(req.body),
    ...player.delta,
  });
});
router.post("/buyExtraGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyExtraGood(req.body),
    ...player.delta,
  });
});
router.post("/buyCashGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.shop.buyCashGood(req.body);
  res.send({
    result: 0,
    ...player.delta,
  });
});
router.post("/buyEPGSGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyEPGSGood(req.body),
    ...player.delta,
  });
});
router.post("/buyEPGSGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyEPGSGood(req.body),
    ...player.delta,
  });
});
router.post("/buyREPGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyREPGood(req.body),
    ...player.delta,
  });
});
router.post("/buyClassicGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyClassicGood(req.body),
    ...player.delta,
  });
});
router.post("/buyLMTGSGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyLMTGSGood(req.body),
    ...player.delta,
  });
});
router.post("/buySkinGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.shop.buySkinGood(req.body);
  res.send({
    ...player.delta,
  });
});

export default router;
