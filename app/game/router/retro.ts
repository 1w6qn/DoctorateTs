import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/retro/unlockRetroBlock", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.retro.unlockRetroBlock(req.body);
  res.send(player.delta);
});
router.post("/retro/getRetroTrailReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    items: await player.retro.getRetroTrailReward(req.body),
    ...player.delta,
  });
});
router.post("/retro/getRetroPassReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.retro.getRetroPassReward(req.body);
  res.send({
    items: await player.retro.getRetroPassReward(req.body),
    ...player.delta,
  });
});
export default router;
