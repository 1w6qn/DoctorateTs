import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/setDefaultSkill", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.setDefaultSkill(req.body);
  res.send(player.delta);
});
router.post("/upgradeChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.upgradeChar(req.body);
  const delta = player.delta;
  console.log(delta);
  res.send(delta);
});
router.post("/evolveChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.evolveChar(req.body);
  res.send(player.delta);
});
router.post("/lockChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.lockChar(req.body);
  res.send(player.delta);
});
router.post("/sellChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.sellChar(req.body);
  res.send(player.delta);
});
router.post("/boostPotential", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.boostPotential(req.body);
  res.send({
    result: 1,
    ...player.delta,
  });
});

router.post("/upgradeSkill", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.upgradeSkill(req.body);
  res.send(player.delta);
});
router.post("/upgradeSpecialization", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.upgradeSpecialization(req.body);
  res.send(player.delta);
});
router.post("/completeUpgradeSpecialization", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.completeUpgradeSpecialization(req.body);
  res.send(player.delta);
});
router.post("/changeCharSkin", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.changeCharSkin(req.body);
  res.send(player.delta);
});
router.post("/changeCharTemplate", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.changeCharTemplate(req.body);
  res.send(player.delta);
});
router.post("/getSpCharMissionReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.getSpCharMissionReward(req.body);
  res.send(player.delta);
});
router.post("/evolveCharUseItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.evolveCharUseItem(req.body);
  res.send(player.delta);
});
router.post("/upgradeCharLevelMaxUseItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.upgradeCharLevelMaxUseItem(req.body);
  res.send(player.delta);
});
router.post("/upgradeSpecializedSkillUseItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.upgradeSpecializedSkillUseItem(req.body);
  res.send(player.delta);
});

router.post("/addonStory/unlock", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.troop.addonStoryUnlock(req.body);
  res.send(player.delta);
});
router.post("/addonStage/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.troop.addonStageBattleStart(req.body);
  res.send(player.delta);
});
router.post("/addonStage/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.troop.addonStageBattleFinish(req.body);
  res.send(player.delta);
});
router.post("/unlockEquipment", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.unlockEquipment(req.body);
  res.send(player.delta);
});
router.post("/upgradeEquipment", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.upgradeEquipment(req.body);
  res.send(player.delta);
});
router.post("/setEquipment", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.setEquipment(req.body);
  res.send(player.delta);
});

router.post("/batchSetCharVoiceLan", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.batchSetCharVoiceLan(req.body);
  res.send(player.delta);
});
router.post("/setCharVoiceLan", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.setCharVoiceLan(req.body);
  res.send(player.delta);
});
export default router;
