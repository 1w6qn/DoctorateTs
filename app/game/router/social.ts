import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";

const router = Router();
router.post("/deleteFriend", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.social.deleteFriend(req.body);
  res.send(player.delta);
});
router.post("/sendFriendRequest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.social.sendFriendRequest(req.body);
  res.send(player.delta);
});
router.post("/processFriendRequest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...(await player.social.processFriendRequest(req.body)),
    ...player.delta,
  });
});
router.post("/searchPlayer", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...(await player.social.searchPlayer(req.body)),
    ...player.delta,
  });
});
router.post("/getSortListInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.social.getSortListInfo(req.body);
  res.send({
    result,
    ...player.delta,
  });
});
router.post("/getFriendList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.social.getFriendList(req.body);
  res.send({
    ...result,
    ...player.delta,
  });
});
router.post("/getFriendRequestList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...(await player.social.getFriendRequestList(req.body)),
    ...player.delta,
  });
});
router.post("/setAssistCharList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.social.setAssistCharList(req.body);
  res.send(player.delta);
});
router.post("/setFriendAlias", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.social.setFriendAlias(req.body);
  res.send(player.delta);
});
router.post("/receiveSocialPoint", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.social.receiveSocialPoint();
  res.send(player.delta);
});
router.post("/setCardShowMedal", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.social.setCardShowMedal(req.body);
  res.send(player.delta);
});
export default router;
