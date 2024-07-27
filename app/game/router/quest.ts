
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';

const router = Router();
router.post("/squadFormation", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.squadFormation(req.body!.squadId, req.body!.slots)
    res.send(player.delta)
    player._trigger.emit("save")
})
router.post("/changeSquadName", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.changeSquadName(req.body!.squadId, req.body!.name)
    res.send(player.delta)
    player._trigger.emit("save")
})
router.post("/battleStart", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        ...player.battle.start(req.body),
        ...player.delta,
    })
    player._trigger.emit("save")
})
router.post("/battleFinish", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        ...player.battle.finish(req.body),
        ...player.delta,
    })
    player._trigger.emit("save")
})
router.post("/getBattleReplay", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        battleReplay: player.battle.loadReplay(req.body!.stageId),
        ...player.delta,
    })
    player._trigger.emit("save")
})
router.post("/saveBattleReplay", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.battle.saveReplay(req.body!.battleId, req.body!.battleReplay)
    res.send({
        ...player.delta,
    })
    player._trigger.emit("save")
})
export default router;