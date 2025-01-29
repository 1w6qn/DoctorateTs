import httpContext from "express-http-context2";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { Router } from "express";

const router = Router();

router.post("/act5fun/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    apFailReturn: 0,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    inApProtectPeriod: false,
    isApProtect: 0,
    notifyPowerScoreNotEnoughIfFailed: false,
    result: 0,
    ...player.delta,
  });
});
router.post("/act5fun/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...(await player.aprilFool.act5funBattleFinish(req.body)),
    ...player.delta,
  });
});
export default router;
