
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';

const router = Router();
router.post("/giveUpGame", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    player.rlv2.giveUpGame();
    res.send({
        
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/createGame", async(req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    await player.rlv2.createGame(req.body);
    res.send({
        
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/chooseInitialRelic", async(req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    player.rlv2.chooseInitialRelic(req.body);
    res.send({
        
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/moveTo", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.rlv2.moveTo(req.body);
    res.send({
        
        ...player.delta
    })
    player._trigger.emit("save")
})
export default router;