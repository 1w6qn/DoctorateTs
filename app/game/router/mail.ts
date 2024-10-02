import { Router } from "express";
import httpContext from "express-http-context";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { mailManager } from "../manager/mail";

const router = Router();
router.post("/removeAllReceivedMail", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  mailManager.removeAllReceivedMail(player.uid, req.body);
  res.send({
    ...player.delta,
  });
});
router.post("/receiveAllMail", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    items: mailManager.receiveAllMail(player.uid, req.body),
    ...player.delta,
  });
});
router.post("/getMetaInfoList", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: mailManager.getMetaInfoList(player.status.uid, req.body),
    ...player.delta,
  });
});
router.post("/receiveMail", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    result: 0,
    items: mailManager.receiveMail(player.status.uid, req.body),
    ...player.delta,
  });
});
router.post("/listMailbox", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    mailList: mailManager.listMailbox(player.status.uid, req.body),
    ...player.delta,
  });
});

export default router;
