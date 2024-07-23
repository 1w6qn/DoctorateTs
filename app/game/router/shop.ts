
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';
const router = Router();
router.post("/decomposePotentialItem", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        items: player.troop.decomposePotentialItem(req.body!.charInstIdList),
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/decomposeClassicPotentialItem", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        items: player.troop.decomposeClassicPotentialItem(req.body!.charInstIdList),
        ...player.delta
    })
    player._trigger.emit("save")
})
export default router;