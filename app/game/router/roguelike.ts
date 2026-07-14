import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

router.post("/roguelike/createGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
  });
});

router.post("/roguelike/finishGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
  });
});

router.post("/roguelike/giveUpGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
  });
});

router.post("/roguelike/milestoneReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    items: [],
    result: 0,
  });
});

router.post("/roguelike/milestoneRewardTryBest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    items: [],
    result: 0,
  });
});

router.post("/roguelike/upgradeOutBuff", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
  });
});

export default router;