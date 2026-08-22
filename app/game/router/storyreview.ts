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
import { validateBody } from "../model/protocol/validate-body";
import {
  markStoryAcceKnownSchema,
  readStorySchema,
  rewardGroupSchema,
  trailRewardSchema,
  unlockStoryByCoinSchema,
} from "../model/protocol/storyreview.schema";

const router = Router();
router.post("/markStoryAcceKnown", validateBody(markStoryAcceKnownSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as MarkStoryAcceKnownRequest;
  await player.storyreview.markStoryAcceKnown();
  res.send(player.delta satisfies MarkStoryAcceKnownResponse);
});
router.post("/rewardGroup", validateBody(rewardGroupSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as StoryReviewRewardRequest;
  res.send({
    items: await player.storyreview.rewardGroup(body),
    ...player.delta,
  } satisfies StoryReviewRewardResponse);
});
router.post("/readStory", validateBody(readStorySchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ReadStoryRequest;
  // 修复：缺 storyId 必填参数时返回业务错误，而非 500
  if (typeof body?.storyId !== "string" || body.storyId === "") {
    return res.send({ result: 1, ...player.delta });
  }
  await player.storyreview.readStory(body);
  res.send(player.delta satisfies ReadStoryResponse);
});
router.post("/unlockStoryByCoin", validateBody(unlockStoryByCoinSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UnlockStoryByCoinRequest;
  // 修复：缺 storyId 必填参数时返回业务错误，而非 500
  if (typeof body?.storyId !== "string" || body.storyId === "") {
    return res.send({ result: 1, ...player.delta });
  }
  await player.storyreview.unlockStoryByCoin(body);
  res.send({
    unlockTs: now(),
    ...player.delta,
  } satisfies UnlockStoryByCoinResponse);
});
router.post("/trailReward", validateBody(trailRewardSchema), async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as StoryReviewGetTrialRewardRequest;
  res.send({
    items: await player.storyreview.trailReward(body),
    ...player.delta,
  } satisfies StoryReviewGetTrialRewardResponse);
});

export default router;
