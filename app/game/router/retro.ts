import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/retro/unlockRetroBlock", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.retro.unlockRetroBlock(req.body);
  res.send(player.delta);
});
router.post("/retro/getRetroTrailReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    items: await player.retro.getRetroTrailReward(req.body),
    ...player.delta,
  });
});
router.post("/retro/getRetroPassReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.retro.getRetroPassReward(req.body);
  res.send({
    items: await player.retro.getRetroPassReward(req.body),
    ...player.delta,
  });
});
router.post("/retro/typeAct20side/competitionStart", async (req, res) => {
  // 参考 OBS misc_bp.retro_typeAct20side_competitionStart：固定 stub
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    battleId: "00000000-0000-0000-0000-000000000000",
    ...player.delta,
  });
});
router.post("/retro/typeAct20side/competitionFinish", async (req, res) => {
  // 参考 OBS misc_bp.retro_typeAct20side_competitionFinish：固定评价结构
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    performance: 0,
    expression: 0,
    operation: 0,
    total: 0,
    level: "SS",
    isNew: false,
    ...player.delta,
  });
});
export default router;
