import { Router } from "express";
import { getPlayer, getPlayerOptional } from "../../request-context";
import { randomUUID } from "node:crypto";
import { PlayerDataManager } from "../PlayerDataManager";
import { validateBody } from "../../domain/contracts/validate-body";
import {
  unlockRetroBlockSchema,
  getRetroTrailRewardSchema,
  getRetroPassRewardSchema,
  competitionStartSchema,
  competitionFinishSchema,
} from "../../domain/retro/retro.schema";
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
} from "../../domain/retro/retro";

const router = Router();
router.post("/retro/unlockRetroBlock", validateBody(unlockRetroBlockSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as RetroUnlockRetroBlockRequest;
  if (body.retroId == null) {
    res.send({ result: 1, ...player.delta } satisfies RetroUnlockRetroBlockResponse);
    return;
  }
  await player.retro.unlockRetroBlock(body);
  res.send(player.delta satisfies RetroUnlockRetroBlockResponse);
});
router.post("/retro/getRetroTrailReward", validateBody(getRetroTrailRewardSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as RetroTrailRewardRequest;
  res.send({
    items: await player.retro.getRetroTrailReward(body),
    ...player.delta,
  } satisfies RetroTrailRewardResponse);
});
router.post("/retro/getRetroPassReward", validateBody(getRetroPassRewardSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as RetroGetPassRewardRequest;
  // 修复：原实现调用两次 getRetroPassReward → 每次请求双倍发放；改为单次调用
  const items = await player.retro.getRetroPassReward(body);
  res.send({ items, ...player.delta } satisfies RetroGetPassRewardResponse);
});
router.post("/retro/typeAct20side/competitionStart", validateBody(competitionStartSchema), async (req, res) => {
  // 参考 OBS misc_bp.retro_typeAct20side_competitionStart：战车竞速非标准战斗，
  // 不校验 body，返回 result 0 + 真实随机 battleId（客户端按 DefaultStartBattleResponse 解析）
  const player = getPlayer();
  req.body as RetroCarCompetitionStartRequest;
  res.send({
    result: 0,
    battleId: randomUUID(),
    ...player.delta,
  } satisfies RetroCarCompetitionStartResponse);
});
router.post("/retro/typeAct20side/competitionFinish", validateBody(competitionFinishSchema), async (req, res) => {
  // 参考 OBS misc_bp.retro_typeAct20side_competitionFinish：固定评价结构
  const player = getPlayer();
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
