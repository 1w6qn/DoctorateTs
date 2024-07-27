import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';
import { mailManager } from '../manager/MailManager';

const router = Router();
router.post("/removeAllReceivedMail", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        ...player.delta
    })
})
router.post("/receiveAllMail", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        ...player.delta
    })
})
router.post("/getMetaInfoList", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        result:mailManager.getMetaInfoList(player.status.uid,req.body),
        ...player.delta
    })
})
router.post("/receiveMail", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        result:0,
        items:mailManager.receiveMail(player.status.uid, req.body),
        ...player.delta
    })
})
router.post("/listMailbox", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        mailList:mailManager.listMailbox(player.status.uid, req.body),
        ...player.delta
    })
})

export default router;