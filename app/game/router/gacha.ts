
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';

const router = Router();
router.post("/syncNoramlGacha", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;

    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/finishNoramlGacha", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.recruit.finish(req.body!.slotId)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})


router.post("/boostNoramlGacha", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.recruit.boost(req.body!.slotId,req.body!.buy)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/cancleNoramlGacha", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.recruit.cancle(req.body!.slotId)

    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/buyRecruitSlot", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.recruit.buyRecruitSlot(req.body!.slotId)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/refreshTags", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.recruit.refreshTags(req.body!.slotId)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
export default router;