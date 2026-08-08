import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { now } from "@utils/time";
import {
  MarkStoryAcceKnownRequest,
  MarkStoryAcceKnownResponse,
  ReadStoryRequest,
  ReadStoryResponse,
  StoryReviewGetTrialRewardRequest,
  StoryReviewGetTrialRewardResponse,
  StoryReviewRewardRequest,
  StoryReviewRewardResponse,
  UnlockStoryByCoinRequest,
  UnlockStoryByCoinResponse,
} from "../model/protocol/storyreview";

const router = Router();
router.post("/markStoryAcceKnown", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as MarkStoryAcceKnownRequest;
  await player.storyreview.markStoryAcceKnown();
  res.send(player.delta satisfies MarkStoryAcceKnownResponse);
});
router.post("/rewardGroup", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as StoryReviewRewardRequest;
  res.send({
    items: await player.storyreview.rewardGroup(body),
    ...player.delta,
  } satisfies StoryReviewRewardResponse);
});
router.post("/readStory", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ReadStoryRequest;
  await player.storyreview.readStory(body);
  res.send(player.delta satisfies ReadStoryResponse);
});
router.post("/unlockStoryByCoin", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UnlockStoryByCoinRequest;
  await player.storyreview.unlockStoryByCoin(body);
  res.send({
    unlockTs: now(),
    ...player.delta,
  } satisfies UnlockStoryByCoinResponse);
});
router.post("/trailReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as StoryReviewGetTrialRewardRequest;
  res.send({
    items: await player.storyreview.trailReward(body),
    ...player.delta,
  } satisfies StoryReviewGetTrialRewardResponse);
});

export default router;
