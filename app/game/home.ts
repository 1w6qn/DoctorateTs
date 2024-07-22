
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from './manager/PlayerDataManager';

const router = Router();
router.post("/homeTheme/change", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    player.home.setHomeTheme(req.body.themeId)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/background/setBackground", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.home.setBackground(req.body.bgID)
    player._trigger.emit("save")
    res.send(player.delta)
})


export default router;