import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/homeTheme/change", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setHomeTheme(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/background/setBackground", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setBackground(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/char/changeMarkStar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  console.log(req.body);
  await player.troop.changeMarkStar(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/setting/perf/setLowPower", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setLowPower(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/npcAudio/changeLan", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.npcAudioChangeLan(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/story/finishStory", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.finishStory(req.body);
  player._trigger.emit("save");
  res.send({
    items: [],
    ...player.delta,
  });
});
export default router;
