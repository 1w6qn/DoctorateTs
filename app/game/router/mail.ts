import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { mailManager } from "../manager/mail";

const router = Router();
router.post("/removeAllReceivedMail", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.delta,
  });
});
router.post("/receiveAllMail", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    ...player.delta,
  });
});
router.post("/getMetaInfoList", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    result: mailManager.getMetaInfoList(player.status.uid, req.body),
    ...player.delta,
  });
});
router.post("/receiveMail", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    result: 0,
    items: mailManager.receiveMail(player.status.uid, req.body),
    ...player.delta,
  });
});
router.post("/listMailbox", (req, res) => {
  const player: PlayerDataManager = httpContext.get(
    "playerData",
  ) as PlayerDataManager;
  res.send({
    mailList: mailManager.listMailbox(player.status.uid, req.body),
    ...player.delta,
  });
});

export default router;
