import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/editNameCard", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.editNameCard(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
router.post("/getOtherPlayerNameCard", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.getOtherPlayerNameCard(req.body);
  res.send({
    ...player.delta,
  });
  player._trigger.emit("save");
});
export default router;
