import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from './manager/PlayerDataManager';

const router = Router();
router.post("/getChainLogInReward", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    player._trigger.emit("save")
    res.send({
        reward:[],
        ...player.delta
    })
})
router.post("/getChainLogInFinalRewards", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;

    player._trigger.emit("save")
    res.send({
        reward:[],
        ...player.delta
    })
})
router.post("/getOpenServerCheckInReward", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;

    player._trigger.emit("save")
    res.send({
        ...player.delta
    })
})
export default router;