import { Router } from "express";
import httpContext from "express-http-context2";
import { randomUUID } from "node:crypto";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  RetroCarCompetitionFinishRequest,
  RetroCarCompetitionFinishResponse,
  RetroCarCompetitionStartRequest,
  RetroCarCompetitionStartResponse,
  RetroGetPassRewardRequest,
  RetroGetPassRewardResponse,
  RetroTrailRewardRequest,
  RetroTrailRewardResponse,
  RetroUnlockRetroBlockRequest,
  RetroUnlockRetroBlockResponse,
} from "../model/protocol/retro";

const router = Router();
router.post("/retro/unlockRetroBlock", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RetroUnlockRetroBlockRequest;
  await player.retro.unlockRetroBlock(body);
  res.send(player.delta satisfies RetroUnlockRetroBlockResponse);
});
router.post("/retro/getRetroTrailReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RetroTrailRewardRequest;
  res.send({
    items: await player.retro.getRetroTrailReward(body),
    ...player.delta,
  } satisfies RetroTrailRewardResponse);
});
router.post("/retro/getRetroPassReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RetroGetPassRewardRequest;
  await player.retro.getRetroPassReward(body);
  res.send({
    items: await player.retro.getRetroPassReward(body),
    ...player.delta,
  } satisfies RetroGetPassRewardResponse);
});
router.post("/retro/typeAct20side/competitionStart", async (req, res) => {
  // 参考 OBS misc_bp.retro_typeAct20side_competitionStart：战车竞速非标准战斗，
  // 不校验 body，返回 result 0 + 真实随机 battleId（客户端按 DefaultStartBattleResponse 解析）
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RetroCarCompetitionStartRequest;
  res.send({
    result: 0,
    battleId: randomUUID(),
    ...player.delta,
  } satisfies RetroCarCompetitionStartResponse);
});
router.post("/retro/typeAct20side/competitionFinish", async (req, res) => {
  // 参考 OBS misc_bp.retro_typeAct20side_competitionFinish：固定评价结构
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RetroCarCompetitionFinishRequest;
  res.send({
    performance: 0,
    expression: 0,
    operation: 0,
    total: 0,
    level: "SS",
    isNew: false,
    ...player.delta,
  } satisfies RetroCarCompetitionFinishResponse);
});
export default router;
