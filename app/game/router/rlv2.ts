import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/giveUpGame", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  player.rlv2.giveUpGame();
  res.send(player.delta);
});
router.post("/createGame", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  await player.rlv2.createGame(req.body);
  res.send(player.delta);
});
router.post("/chooseInitialRelic", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  await player.rlv2.chooseInitialRelic(req.body);
  res.send(player.delta);
});
router.post("/chooseInitialRecruitSet", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  await player.rlv2.chooseInitialRecruitSet(req.body);
  res.send(player.delta);
});
router.post("/activeRecruitTicket", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  await player.rlv2.activeRecruitTicket(req.body);
  res.send(player.delta);
});
router.post("/recruitChar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;

  res.send({
    chars: player.rlv2.recruitChar(req.body),
    ...player.delta,
  });
});
router.post("/finishEvent", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.finishEvent();
  res.send(player.delta);
});
router.post("/moveTo", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.rlv2.moveTo(req.body);
  res.send(player.delta);
});
router.post("/moveAndBattleStart", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.rlv2.moveAndBattleStart(req.body);
  res.send(player.delta);
});
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.rlv2.battleFinish(req.body);
  res.send(player.delta);
});
router.post("/chooseBattleReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.chooseBattleReward(req.body);
  res.send(player.delta);
});
router.post("/finishBattleReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.finishBattleReward(req.body);
  res.send(player.delta);
});
router.post("/setTroopCarry", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.setTroopCarry(req.body);
  res.send(player.delta);
});
router.post("/loseFragment", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.loseFragment(req.body);
  res.send(player.delta);
});
router.post("/useInspiration", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.useInspiration(req.body);
  res.send(player.delta);
});
router.post("/setPinned", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  player.rlv2.setPinned(req.body);
  res.send(player.delta);
});
export default router;
