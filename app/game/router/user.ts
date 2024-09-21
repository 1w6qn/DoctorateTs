import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";

const router = Router();
router.post("/changeSecretary", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.changeSecretary(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/changeAvatar", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.changeAvatar(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/changeResume", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  if ((req.body!.resume as string).slice(0) == "@") {
    player._trigger.emit(req.body!.resume.slice(1, req.body!.resume.length));
  } else {
    player.status.changeResume(req.body);
  }
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/bindNickName", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.bindNickName(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/useRenameCard", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.bindNickName(req.body);
  player._trigger.emit("useItems", [
    { id: req.body!.itemId, count: 1, instId: req.body!.instId } as ItemBundle,
  ]);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/receiveTeamCollectionReward", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.receiveTeamCollectionReward(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/buyAp", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.buyAp();
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/exchangeDiamondShard", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player.status.exchangeDiamondShard(req.body);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/useItem", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  const item = {
    id: req.body!.itemId,
    count: req.body!.count,
    instId: req.body!.instId,
  } as ItemBundle;
  player._trigger.emit("useItems", [item]);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/useItems", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  const items: ItemBundle[] = [];
  for (const item of req.body!.items) {
    items.push({
      id: item.itemId,
      count: item.count,
      instId: item.instId,
    } as ItemBundle);
  }
  player._trigger.emit("useItems", items);
  player._trigger.emit("save");
  res.send(player.delta);
});
router.post("/checkIn", async (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  player._trigger.emit("save");
  res.send({
    ...player.checkIn.checkIn(),
    ...player.delta,
  });
});
export default router;
