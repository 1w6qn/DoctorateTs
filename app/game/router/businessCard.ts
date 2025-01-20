import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/editNameCard", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.editNameCard(req.body);
  res.send({
    ...player.delta,
  });
});
router.post("/getOtherPlayerNameCard", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.getOtherPlayerNameCard(req.body);
  res.send({
    ...player.delta,
  });
});
export default router;
