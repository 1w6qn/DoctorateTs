
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
router.post("/battleStart", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    player._trigger.emit("save")
    res.send({
        "apFailReturn": 0,
        'battleId': 'abcdefgh-1234-5678-a1b2c3d4e5f6',
        "inApProtectPeriod": false,
        "isApProtect": 0,
        "notifyPowerScoreNotEnoughIfFailed": false,
        'playerDataDelta': {
            'modified': {},
            'deleted': {}
        },
        'result': 0
    })
})
router.post("/battleFinish", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    player._trigger.emit("save")
    res.send({
        "result":0,
        "apFailReturn": 0,
        "expScale": 1.2,
        "goldScale": 1.2,
        "rewards": [],
        "firstRewards": [],
        "unlockStages": [],
        "unusualRewards": [],
        "additionalRewards": [],
        "furnitureRewards": [],
        "alert": [],
        "suggestFriend": false,
        "pryResult": [],
        "playerDataDelta": {
            "modified": {},
            "deleted": {}
        }
    })
})
export default router;