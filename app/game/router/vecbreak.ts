import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  VecBreakV2ChangeBuffRequest,
  VecBreakV2ChangeBuffResponse,
  VecBreakV2DefenseStartBattleRequest,
  VecBreakV2FinishBattleRequest,
  VecBreakV2FinishBattleResponse,
  VecBreakV2OffenseStartBattleRequest,
  VecBreakV2SeasonRecordRequest,
  VecBreakV2SeasonRecordResponse,
  VecBreakV2SetDefendRequest,
  VecBreakV2SetDefendResponse,
  VecBreakV2StartBattleResponse,
} from "../model/protocol/vecbreak";

const router = Router();

router.post("/vecBreakV2/getSeasonRecord", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2SeasonRecordRequest;

  res.send({
    ...player.delta,
    seasonRecord: {},
  } satisfies VecBreakV2SeasonRecordResponse);
});

router.post("/vecBreakV2/changeBuffList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2ChangeBuffRequest;

  res.send(player.delta satisfies VecBreakV2ChangeBuffResponse);
});

router.post("/vecBreakV2/defendBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2DefenseStartBattleRequest;

  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  } satisfies VecBreakV2StartBattleResponse);
});

router.post("/vecBreakV2/defendBattleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2FinishBattleRequest;

  res.send(player.delta satisfies VecBreakV2FinishBattleResponse);
});

router.post("/vecBreakV2/setDefend", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2SetDefendRequest;

  res.send(player.delta satisfies VecBreakV2SetDefendResponse);
});

router.post("/vecBreakV2/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2OffenseStartBattleRequest;

  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  } satisfies VecBreakV2StartBattleResponse);
});

router.post("/vecBreakV2/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as VecBreakV2FinishBattleRequest;

  res.send(player.delta satisfies VecBreakV2FinishBattleResponse);
});

export default router;
