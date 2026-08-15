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
  // 修复：EditBusinessCard 任务事件从未 emit → 编辑名片类任务永不推进
  await player._trigger.emit("EditBusinessCard", []);
  res.send(player.delta satisfies EditNameCardResponse);
});
router.post("/getOtherPlayerNameCard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetOtherPlayerNameCardRequest;
  // 修复：缺必填 uid 参数时返回业务错误，而非 500
  if (typeof body?.uid !== "string" || body.uid === "") {
    return res.send({ result: 1, ...player.delta });
  }
  res.send({
    nameCard: await player.social.getOtherPlayerNameCard(body),
    ...player.delta,
  } satisfies GetOtherPlayerNameCardResponse);
});
export default router;
