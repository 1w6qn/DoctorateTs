import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import {
  DeleteFriendRequest,
  DeleteFriendResponse,
  GetFriendListRequest,
  GetFriendListResponse,
  GetFriendRequestListRequest,
  GetFriendRequestResponse,
  GetSortListInfoRequest,
  GetSortListInfoResponse,
  ProcessFriendRequest,
  ProcessFriendResponse,
  ReceiveSocialPointRequest,
  ReceiveSocialPointResponse,
  SearchPlayerRequest,
  SearchPlayerResponse,
  SendFriendRequest,
  SendFriendResponse,
  SetAssistCharListRequest,
  SetAssistCharListResponse,
  SetCardShowMedalRequest,
  SetCardShowMedalResponse,
  SetFriendAliasRequest,
  SetFriendAliasResponse,
  SetStarFriendListRequest,
  SetStarFriendListResponse,
} from "../model/protocol/social";

const router = Router();
router.post("/deleteFriend", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as DeleteFriendRequest;
  await player.social.deleteFriend(body);
  res.send(player.delta satisfies DeleteFriendResponse);
});
router.post("/sendFriendRequest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SendFriendRequest;
  await player.social.sendFriendRequest(body);
  res.send(player.delta satisfies SendFriendResponse);
});
router.post("/processFriendRequest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ProcessFriendRequest;
  res.send({
    ...(await player.social.processFriendRequest(body)),
    ...player.delta,
  } satisfies ProcessFriendResponse);
});
router.post("/searchPlayer", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SearchPlayerRequest;
  res.send({
    ...(await player.social.searchPlayer(body)),
    ...player.delta,
  } satisfies SearchPlayerResponse);
});
router.post("/getSortListInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetSortListInfoRequest;
  const result = await player.social.getSortListInfo(body);
  res.send({
    result,
    ...player.delta,
  } satisfies GetSortListInfoResponse);
});
router.post("/getFriendList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetFriendListRequest;
  const result = await player.social.getFriendList(body);
  res.send({
    ...result,
    ...player.delta,
  } satisfies GetFriendListResponse);
});
router.post("/getFriendRequestList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetFriendRequestListRequest;
  res.send({
    ...(await player.social.getFriendRequestList(body)),
    ...player.delta,
  } satisfies GetFriendRequestResponse);
});
router.post("/setAssistCharList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SetAssistCharListRequest;
  await player.social.setAssistCharList(body);
  res.send(player.delta satisfies SetAssistCharListResponse);
});
router.post("/setFriendAlias", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SetFriendAliasRequest;
  await player.social.setFriendAlias(body);
  res.send(player.delta satisfies SetFriendAliasResponse);
});
router.post("/receiveSocialPoint", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ReceiveSocialPointRequest;
  await player.social.receiveSocialPoint();
  res.send(player.delta satisfies ReceiveSocialPointResponse);
});
router.post("/setCardShowMedal", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SetCardShowMedalRequest;
  await player.social.setCardShowMedal(body);
  res.send(player.delta satisfies SetCardShowMedalResponse);
});
router.post("/setStarFriendList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as SetStarFriendListRequest;
  // 参考 OBS bp_social.setStarFriendList：空实现返回固定结构
  res.send({
    result: 0,
    newIdList: [],
    ...player.delta,
  } satisfies SetStarFriendListResponse);
});
export default router;
