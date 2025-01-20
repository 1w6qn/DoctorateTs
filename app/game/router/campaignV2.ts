import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

/**
 *     CAMP_CONFIRM_BREAK_REWARD = "/campaignV2/getBreakReward";
 *     CAMP_GET_COMMON_MISSION_REWARD = "/campaignV2/getExMissionReward";
 *     CAMP_BATTLE_START = "/campaignV2/battleStart";
 *     CAMP_BATTLE_FINISH = "/campaignV2/battleFinish";
 *     CAMP_BATTLE_SWEEP = "/campaignV2/battleSweep";
 *    **/
const router = Router();
router.post("/getBreakReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.squadFormation(req.body);
  res.send(player.delta);
});
router.post("/getExMissionReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.troop.changeSquadName(req.body);
  res.send(player.delta);
});
router.post("/battleStart", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...(await player.battle.start(req.body)),
    ...player.delta,
  });
});
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...player.battle.finish(req.body),
    ...player.delta,
  });
});
router.post("/battleSweep", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    battleReplay: player.battle.loadReplay(req.body),
    ...player.delta,
  });
});
export default router;
