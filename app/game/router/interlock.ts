import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

router.post("/interlock/milestone", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    items: [],
  });
});

router.post("/interlock/milestoneBatch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    items: [],
  });
});

router.post("/interlock/setDefend", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/interlock/setSquad", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

export default router;