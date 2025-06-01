import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/sync", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ts: await player.building.sync(),
    ...player.delta,
  });
});
router.post("/changeBGM", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.changeBGM(req.body);
  res.send({
    ...player.delta,
  });
});
router.post("/setPrivateDormOwner", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.setPrivateDormOwner(req.body);
  res.send({
    ...player.delta,
  });
});
router.post("/setBuildingAssist", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.setBuildingAssist(req.body);
  res.send({
    ...player.delta,
  });
});
export default router;
