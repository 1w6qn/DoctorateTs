import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  ChangeNameCardComponentRequest,
  ChangeNameCardComponentResponse,
  ChangeNameCardSkinRequest,
  ChangeNameCardSkinResponse,
  EditNameCardRequest,
  EditNameCardResponse,
  GetOtherPlayerNameCardRequest,
  GetOtherPlayerNameCardResponse,
} from "../model/protocol/businessCard";

const router = Router();
router.post("/changeNameCardSkin", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ChangeNameCardSkinRequest;
  await player.social.changeNameCardSkin(body);
  res.send(player.delta satisfies ChangeNameCardSkinResponse);
});
router.post("/changeNameCardComponent", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ChangeNameCardComponentRequest;
  await player.social.changeNameCardComponent(body);
  res.send(player.delta satisfies ChangeNameCardComponentResponse);
});
router.post("/editNameCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EditNameCardRequest;
  await player.social.editNameCard(body);
  res.send(player.delta satisfies EditNameCardResponse);
});
router.post("/getOtherPlayerNameCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetOtherPlayerNameCardRequest;
  res.send({
    nameCard: await player.social.getOtherPlayerNameCard(body),
    ...player.delta,
  } satisfies GetOtherPlayerNameCardResponse);
});
export default router;
