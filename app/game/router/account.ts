import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { now } from "@utils/time";

const router = Router();
router.post("/login", async (req, res) => {
  res.send({
    result: 0,
    uid: "1",
    secret: "1",
    serviceLicenseVersion: 0,
  });
});
router.post("/syncData", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.update(async (draft) => {
    draft.pushFlags.status = now();
  });
  res.send({
    result: 0,
    ts: now(),
    user: player,
    ...player.delta,
  });
});
router.post("/syncStatus", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player._trigger.emit("status:refresh:time", []);
  res.send({
    ts: now(),
    result: {},
    ...player.delta,
  });
});
router.post("/syncPushMessage", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send(player.delta);
});

export default router;
