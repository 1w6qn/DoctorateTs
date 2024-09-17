import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/syncNormalGacha", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;

  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/finishNormalGacha", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    charGet: await player.recruit.finish(req.body!.slotId),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/normalGacha", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    charGet: await player.recruit.normalGacha(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});

router.post("/boostNormalGacha", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.recruit.boost(req.body!.slotId, req.body!.buy);
  res.send({
    result: 0,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/cancleNormalGacha", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  await player.recruit.cancle(req.body!.slotId);

  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/buyRecruitSlot", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.recruit.buyRecruitSlot(req.body!.slotId);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/refreshTags", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  await player.recruit.refreshTags(req.body!.slotId);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getPoolDetail", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    detailInfo: player.gacha.getPoolDetail(req.body!.poolId),
    gachaObjGroupType: 0,
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/advancedGacha", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    result: 0,
    charGet: await player.gacha.advancedGacha(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/tenAdvancedGacha", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  const r = await player.gacha.tenAdvancedGacha(req.body);
  res.send({
    result: 0,
    gachaResultList: r,
    ...player.delta,
  });
  player._trigger.emit("save");
});
export default router;
