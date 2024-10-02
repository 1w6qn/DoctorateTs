import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";

const router = Router();
router.post("/changeSecretary", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.changeSecretary(req.body);
  res.send(player.delta);
});
router.post("/changeAvatar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.changeAvatar(req.body);
  res.send(player.delta);
});
router.post("/changeResume", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  if ((req.body!.resume as string).slice(0) == "@") {
    player._trigger.emit(req.body!.resume.slice(1, req.body!.resume.length));
  } else {
    await player.status.changeResume(req.body);
  }
  res.send(player.delta);
});
router.post("/bindNickName", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.bindNickName(req.body);
  res.send(player.delta);
});
router.post("/useRenameCard", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.bindNickName(req.body);
  player._trigger.emit("useItems", [
    { id: req.body!.itemId, count: 1, instId: req.body!.instId } as ItemBundle,
  ]);
  res.send(player.delta);
});
router.post("/receiveTeamCollectionReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.receiveTeamCollectionReward(req.body);
  res.send(player.delta);
});
router.post("/buyAp", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.buyAp();
  res.send(player.delta);
});
router.post("/exchangeDiamondShard", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.exchangeDiamondShard(req.body);
  res.send(player.delta);
});
router.post("/useItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  const item = {
    id: req.body!.itemId,
    count: req.body!.count,
    instId: req.body!.instId,
  } as ItemBundle;
  player._trigger.emit("useItems", [item]);

  res.send(player.delta);
});
router.post("/useItems", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  const items: {
    itemId: string;
    count: number;
    instId: number;
  }[] = req.body!.items;
  player._trigger.emit(
    "useItems",
    items.map((item) => {
      return {
        id: item.itemId,
        count: item.count,
        instId: item.instId,
      };
    }),
  );
  res.send(player.delta);
});
router.post("/checkIn", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...(await player.checkIn.checkIn()),
    ...player.delta,
  });
});
export default router;
