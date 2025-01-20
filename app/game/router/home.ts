import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/homeTheme/change", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setHomeTheme(req.body);
  res.send(player.delta);
});
router.post("/background/setBackground", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setBackground(req.body);
  res.send(player.delta);
});
router.post("/charRotation/setCurrent", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.charRotation.setCurrent(req.body);
  res.send(player.delta);
});
router.post("/charRotation/createPreset", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.charRotation.createPreset();
  res.send(player.delta);
});
router.post("/charRotation/updatePreset", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.charRotation.updatePreset(req.body);
  res.send(player.delta);
});
router.post("/charRotation/deletePreset", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.charRotation.deletePreset(req.body);
  res.send(player.delta);
});
router.post("/char/changeMarkStar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.changeMarkStar(req.body);
  res.send(player.delta);
});
router.post("/setting/perf/setLowPower", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setLowPower(req.body);
  res.send(player.delta);
});
router.post("/npcAudio/changeLan", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.npcAudioChangeLan(req.body);
  res.send(player.delta);
});
router.post("/story/finishStory", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.finishStory(req.body);
  res.send({
    items: [],
    ...player.delta,
  });
});
export default router;
