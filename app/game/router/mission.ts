import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/confirmMission", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send({
    items: player.mission.confirmMission(req.body),
    ...player.delta,
  });
});
router.post("/confirmMissionGroup", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.mission.confirmMissionGroup(req.body);
  res.send(player.delta);
});
router.post("/autoConfirmMissions", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;

  res.send({
    items: await player.mission.autoConfirmMissions(req.body),
    ...player.delta,
  });
});
router.post("/exchangeMissionRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.mission.exchangeMissionRewards(req.body);
  res.send({
    ...player.delta,
  });
});
export default router;
