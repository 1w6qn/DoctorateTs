
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';

const router = Router();
router.post("/editNameCard", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.editNameCard(req.body!.flag,req.body!.content)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/getOtherPlayerNameCard", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.getOtherPlayerNameCard(req.body!.uid)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
export default router;