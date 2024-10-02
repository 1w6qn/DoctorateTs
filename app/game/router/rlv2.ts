import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/giveUpGame", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  player.rlv2.giveUpGame();
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/createGame", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  await player.rlv2.createGame(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/chooseInitialRelic", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  await player.rlv2.chooseInitialRelic(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/chooseInitialRecruitSet", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  await player.rlv2.chooseInitialRecruitSet(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/activeRecruitTicket", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  await player.rlv2.activeRecruitTicket(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/recruitChar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  res.send({
    chars: player.rlv2.recruitChar(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/finishEvent", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.finishEvent();
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/moveTo", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.rlv2.moveTo(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/moveAndBattleStart", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.rlv2.moveAndBattleStart(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.rlv2.battleFinish(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/chooseBattleReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.chooseBattleReward(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/finishBattleReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.finishBattleReward(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/setTroopCarry", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.setTroopCarry(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/loseFragment", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.loseFragment(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/useInspiration", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.useInspiration(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
export default router;
