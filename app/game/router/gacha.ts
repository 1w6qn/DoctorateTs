
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
router.post("/finishNoramlGacha", async (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        charGet: await player.recruit.finish(req.body!.slotId),
        ...player.delta
    })
    player._trigger.emit("save")
})


router.post("/boostNoramlGacha", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.recruit.boost(req.body!.slotId,req.body!.buy)
    res.send({
        result:0,
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/cancleNoramlGacha", async (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    await player.recruit.cancle(req.body!.slotId)

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
router.post("/refreshTags", async (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    await player.recruit.refreshTags(req.body!.slotId)
    res.send({
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/getPoolDetail", async (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        detailInfo:player.gacha.getPoolDetail(req.body!.poolId),
        gachaObjGroupType:0,
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/advancedGacha", async (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        result:0,
        charGet:await player.gacha.advancedGacha(req.body),
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/tenAdvancedGacha", async (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    res.send({
        result:0,
        gachaResultList:await player.gacha.tenAdvancedGacha(req.body),
        ...player.delta
    })
    player._trigger.emit("save")
})
export default router;