
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';

const router = Router();
router.post("/squadFormation", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.squadFormation(req.body!.squadId, req.body!.slots)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/changeSquadName", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.changeSquadName(req.body!.squadId, req.body!.name)
    player._trigger.emit("save")
    res.send(player.delta)
})


export default router;