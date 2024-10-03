import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/confirmMission", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  res.send({
    items: player.mission.confirmMission(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/confirmMissionGroup", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.mission.confirmMissionGroup(req.body);
  res.send(player.delta);
  player._trigger.emit("save");
});
router.post("/autoConfirmMissions", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  res.send({
    items: await player.mission.autoConfirmMissions(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/exchangeMissionRewards", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.mission.exchangeMissionRewards(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
export default router;
