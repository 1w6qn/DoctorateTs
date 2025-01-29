import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/editNameCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.social.editNameCard(req.body);
  res.send({
    ...player.delta,
  });
});
router.post("/getOtherPlayerNameCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    nameCard: await player.social.getOtherPlayerNameCard(req.body),
    ...player.delta,
  });
});
export default router;
