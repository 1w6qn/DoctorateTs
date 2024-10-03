import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import excel from "@excel/excel";

const router = Router();
router.post("/decomposePotentialItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    items: player.troop.decomposePotentialItem(req.body!.charInstIdList),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/decomposeClassicPotentialItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    items: player.troop.decomposeClassicPotentialItem(req.body!.charInstIdList),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getGoodPurchaseState", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: {},
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getLowGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.lowGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getHighGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.highGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getClassicGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.classicGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getEPGSGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.EPGSGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getLMTGSGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.LMTGSGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getExtraGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.extraGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getREPGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.REPGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getSkinGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.skinGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getCashGoodList", (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.cashGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getGPGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...excel.ShopTable.GPGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getSocialGoodList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...player.shop.socialGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});

router.post("/buyLowGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyLowGood(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyHighGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyHighGood(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyExtraGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyExtraGood(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyCashGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyEPGSGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyEPGSGood(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyEPGSGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyEPGSGood(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyREPGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyREPGood(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyClassicGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyClassicGood(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyLMTGSGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: await player.shop.buyLMTGSGood(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buySkinGood", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.shop.buySkinGood(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});

export default router;
