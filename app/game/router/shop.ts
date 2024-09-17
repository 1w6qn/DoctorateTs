import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/decomposePotentialItem", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    items: player.troop.decomposePotentialItem(req.body!.charInstIdList),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/decomposeClassicPotentialItem", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    items: player.troop.decomposeClassicPotentialItem(req.body!.charInstIdList),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getGoodPurchaseState", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    result: {},
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getLowGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.lowGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getHighGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.highGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getClassicGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.classicGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getEPGSGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.EPGSGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getLMTGSGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.LMTGSGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getExtraGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.extraGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getREPGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.REPGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getSkinGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.skinGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getCashGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.cashGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getGPGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.GPGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getSocialGoodList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.shop.socialGoodList,
    ...player.delta,
  });
  player._trigger.emit("save");
});

router.post("/buyLowGood", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    result: 0,
    items: player.shop.buyLowGood(req.body!.goodId, req.body!.count),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buySkinGood", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.shop.buySkinGood(req.body!.goodId);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
export default router;
