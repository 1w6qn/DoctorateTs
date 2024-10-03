import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { now } from "@utils/time";

const router = Router();
router.post("/markStoryAcceKnown", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.storyreview.markStoryAcceKnown();
  res.send(player.delta);
  player._trigger.emit("save");
});
router.post("/rewardGroup", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    items: await player.storyreview.rewardGroup(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/readStory", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.storyreview.readStory(req.body!.storyId);
  res.send(player.delta);
  player._trigger.emit("save");
});
router.post("/unlockStoryByCoin", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.storyreview.unlockStoryByCoin(req.body!.storyId);
  res.send({
    unlockTs: now(),
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/trailReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    items: await player.storyreview.trailReward(req.body),
    ...player.delta,
  });
  player._trigger.emit("save");
});

export default router;
