
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from './manager/PlayerDataManager';

const router = Router();
router.post("/setDefaultSkill", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.setDefaultSkill(req.body.charInstId,req.body.defaultSkillIndex)
    player._trigger.emit("save")
})
router.post("/boostPotential", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.boostPotential(req.body.charInstId,req.body.itemId,req.body.targetRank)
    player._trigger.emit("save")
})
export default router;