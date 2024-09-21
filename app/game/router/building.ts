import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { now } from "@utils/time";

const router = Router();
router.post("/sync", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  const ts = now();
  player._playerdata.event.building = ts + 5000;
  res.send({
    ts,
    ...player.delta,
  });
  player._trigger.emit("save");
});
export default router;
