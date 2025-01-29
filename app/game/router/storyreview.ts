import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { now } from "@utils/time";

const router = Router();
router.post("/markStoryAcceKnown", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.storyreview.markStoryAcceKnown();
  res.send(player.delta);
});
router.post("/rewardGroup", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    items: await player.storyreview.rewardGroup(req.body),
    ...player.delta,
  });
});
router.post("/readStory", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.storyreview.readStory(req.body!.storyId);
  res.send(player.delta);
});
router.post("/unlockStoryByCoin", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.storyreview.unlockStoryByCoin(req.body!.storyId);
  res.send({
    unlockTs: now(),
    ...player.delta,
  });
});
router.post("/trailReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    items: await player.storyreview.trailReward(req.body),
    ...player.delta,
  });
});

export default router;
