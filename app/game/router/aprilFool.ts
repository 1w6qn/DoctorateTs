import httpContext from "express-http-context2";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { Router } from "express";
import {
  Act3FunBattleFinishRequest,
  Act3FunBattleFinishResponse,
  Act3FunBattleStartRequest,
  Act3FunBattleStartResponse,
} from "@game/model/protocol/aprilFool";

const router = Router();

router.post("/act5fun/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act3FunBattleStartRequest;
  res.send({
    apFailReturn: 0,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    inApProtectPeriod: false,
    isApProtect: 0,
    notifyPowerScoreNotEnoughIfFailed: false,
    result: 0,
    ...player.delta,
  } satisfies Act3FunBattleStartResponse);
});
router.post("/act5fun/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act3FunBattleFinishRequest;
  res.send({
    ...(await player.aprilFool.act5funBattleFinish(body)),
    ...player.delta,
  } satisfies Act3FunBattleFinishResponse);
});
export default router;
