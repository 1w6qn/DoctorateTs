import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/squadFormation", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.squadFormation(req.body!.squadId, req.body!.slots);
  res.send(player.delta);
  player._trigger.emit("save");
});
router.post("/changeSquadName", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.troop.changeSquadName(req.body);
  res.send(player.delta);
  player._trigger.emit("save");
});
router.post("/battleStart", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...(await player.battle.start(req.body)),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...player.battle.finish(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getBattleReplay", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    battleReplay: player.battle.loadReplay(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/saveBattleReplay", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.battle.saveReplay(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
export default router;
