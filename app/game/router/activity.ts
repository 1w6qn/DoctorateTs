import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/getChainLogInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    reward: await player.openServer.getChainLogInReward(req.body),
    ...player.delta,
  });
});
router.post("/getChainLogInFinalRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    reward: await player.openServer.getChainLogInFinalRewards(),
    ...player.delta,
  });
});
router.post("/getOpenServerCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    reward: await player.openServer.getCheckInReward(req.body),
    ...player.delta,
  });
});

export default router;
