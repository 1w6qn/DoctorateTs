import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/batchSetCharVoiceLan", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.batchSetCharVoiceLan(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/setDefaultSkill", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.setDefaultSkill(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/changeCharSkin", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.changeCharSkin(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/setEquipment", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.setEquipment(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/unlockEquipment", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.unlockEquipment(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/upgradeEquipment", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.upgradeEquipment(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/changeCharTemplate", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.changeCharTemplate(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});

router.post("/boostPotential", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.boostPotential(req.body);
  player._trigger.emit("save");
  res.send({
    result: 1,
    ...player.delta,
  });
});
router.post("/upgradeChar", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.upgradeChar(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/upgradeSkill", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.upgradeSkill(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/evolveChar", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.troop.evolveChar(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});

export default router;
