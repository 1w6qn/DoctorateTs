
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from './manager/PlayerDataManager';

const router = Router();
router.post("/sync", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player._trigger.emit("save")
    let ts=parseInt((new Date().getTime() / 1000).toString())
    player._playerdata.event.building=parseInt((new Date().getTime() / 1000).toString())+5000
    res.send({
        ts: ts,
        ...player.delta
    })
})
export default router;