import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/batchSetCharVoiceLan", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.batchSetCharVoiceLan(req.body);

  res.send(player.delta);
});
router.post("/setDefaultSkill", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.setDefaultSkill(req.body);

  res.send(player.delta);
});
router.post("/changeCharSkin", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.changeCharSkin(req.body);

  res.send(player.delta);
});
router.post("/setEquipment", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.setEquipment(req.body);

  res.send(player.delta);
});
router.post("/unlockEquipment", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.unlockEquipment(req.body);

  res.send(player.delta);
});
router.post("/upgradeEquipment", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.upgradeEquipment(req.body);

  res.send(player.delta);
});
router.post("/changeCharTemplate", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.changeCharTemplate(req.body);

  res.send(player.delta);
});

router.post("/boostPotential", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.boostPotential(req.body);

  res.send({
    result: 1,
    ...player.delta,
  });
});
router.post("/upgradeChar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.upgradeChar(req.body);

  res.send(player.delta);
});
router.post("/upgradeSkill", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.upgradeSkill(req.body);

  res.send(player.delta);
});
router.post("/evolveChar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.evolveChar(req.body);

  res.send(player.delta);
});

export default router;
