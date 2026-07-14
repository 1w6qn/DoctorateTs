import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

router.post("/vecBreakV2/getSeasonRecord", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    seasonRecord: {},
  });
});

router.post("/vecBreakV2/changeBuffList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/vecBreakV2/defendBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  });
});

router.post("/vecBreakV2/defendBattleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/vecBreakV2/setDefend", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/vecBreakV2/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  });
});

router.post("/vecBreakV2/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

export default router;