
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';
import { now } from '@utils/time';

const router = Router();
router.post("/markStoryAcceKnown", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.storyreview.markStoryAcceKnown()
    res.send(player.delta)
    player._trigger.emit("save")
})
router.post("/rewardGroup", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({
        items:player.storyreview.rewardGroup(req.body),
        ...player.delta
    })
    player._trigger.emit("save")
    
})
router.post("/readStory", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.storyreview.readStory(req.body!.storyId)
    res.send(player.delta)
    player._trigger.emit("save")
})
router.post("/unlockStoryByCoin", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.storyreview.unlockStoryByCoin(req.body!.storyId)
    res.send({
        unlockTs:now(),
        ...player.delta
    })
    player._trigger.emit("save")
})
router.post("/trailReward", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    res.send({
        items:player.storyreview.trailReward(req.body),
        ...player.delta
    })
    player._trigger.emit("save")
})

export default router;