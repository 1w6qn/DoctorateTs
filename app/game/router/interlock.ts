import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  Act1LockGetMilestoneBatchRequest,
  Act1LockGetMilestoneBatchResponse,
  Act1LockGetMilestoneRequest,
  Act1LockGetMilestoneResponse,
  Act1LockSetDefendRequest,
  Act1LockSetDefendResponse,
  Act1LockSetSquadRequest,
  Act1LockSetSquadResponse,
} from "../model/protocol/interlock";

const router = Router();

router.post("/interlock/milestone", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act1LockGetMilestoneRequest;

  res.send({
    ...player.delta,
    items: [],
  } satisfies Act1LockGetMilestoneResponse);
});

router.post("/interlock/milestoneBatch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act1LockGetMilestoneBatchRequest;

  res.send({
    ...player.delta,
    items: [],
  } satisfies Act1LockGetMilestoneBatchResponse);
});

router.post("/interlock/setDefend", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act1LockSetDefendRequest;

  res.send(player.delta satisfies Act1LockSetDefendResponse);
});

router.post("/interlock/setSquad", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act1LockSetSquadRequest;

  res.send(player.delta satisfies Act1LockSetSquadResponse);
});

export default router;
