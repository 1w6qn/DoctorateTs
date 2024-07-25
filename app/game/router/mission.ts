
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';

const router = Router();
router.post("/confirmMission", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    res.send({
        items:player.mission.confirmMission(req.body!.missionId),
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/confirmMissionGroup", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.mission.confirmMissionGroup(req.body!.missionGroupId)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/autoConfirmMissions", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    res.send({
        items:player.mission.autoConfirmMissions(req.body!.type),
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/exchangeMissionRewards", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.mission.exchangeMissionRewards(req.body!.targetRewardsId)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
export default router;