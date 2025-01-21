import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/setDefaultSkill", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.setDefaultSkill(req.body);
  res.send(player.delta);
});
router.post("/upgradeChar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.upgradeChar(req.body);
  res.send(player.delta);
});
router.post("/evolveChar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.evolveChar(req.body);
  res.send(player.delta);
});
router.post("/lockChar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.lockChar(req.body);
  res.send(player.delta);
});
router.post("/sellChar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.sellChar(req.body);
  res.send(player.delta);
});
router.post("/boostPotential", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.boostPotential(req.body);
  res.send({
    result: 1,
    ...player.delta,
  });
});

router.post("/upgradeSkill", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.upgradeSkill(req.body);
  res.send(player.delta);
});
router.post("/upgradeSpecialization", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.upgradeSpecialization(req.body);
  res.send(player.delta);
});
router.post("/completeUpgradeSpecialization", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.completeUpgradeSpecialization(req.body);
  res.send(player.delta);
});
router.post("/changeCharSkin", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.changeCharSkin(req.body);
  res.send(player.delta);
});
router.post("/changeCharTemplate", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.changeCharTemplate(req.body);
  res.send(player.delta);
});
router.post("/getSpCharMissionReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.getSpCharMissionReward(req.body);
  res.send(player.delta);
});
router.post("/evolveCharUseItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.evolveCharUseItem(req.body);
  res.send(player.delta);
});
router.post("/upgradeCharLevelMaxUseItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.upgradeCharLevelMaxUseItem(req.body);
  res.send(player.delta);
});
router.post("/upgradeSpecializedSkillUseItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.upgradeSpecializedSkillUseItem(req.body);
  res.send(player.delta);
});

router.post("/addonStory/unlock", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.addonStoryUnlock(req.body);
  res.send(player.delta);
});
router.post("/addonStage/battleStart", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.addonStageBattleStart(req.body);
  res.send(player.delta);
});
router.post("/addonStage/battleFinish", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.addonStageBattleFinish(req.body);
  res.send(player.delta);
});
router.post("/unlockEquipment", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.unlockEquipment(req.body);
  res.send(player.delta);
});
router.post("/upgradeEquipment", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.upgradeEquipment(req.body);
  res.send(player.delta);
});
router.post("/setEquipment", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.setEquipment(req.body);
  res.send(player.delta);
});

router.post("/batchSetCharVoiceLan", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.batchSetCharVoiceLan(req.body);
  res.send(player.delta);
});
router.post("/setCharVoiceLan", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.setCharVoiceLan(req.body);
  res.send(player.delta);
});
export default router;
