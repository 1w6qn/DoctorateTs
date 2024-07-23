
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from './manager/PlayerDataManager';

const router = Router();
router.post("/markStoryAcceKnown", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.storyreview.markStoryAcceKnown()
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/rewardGroup", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.storyreview.rewardGroup(req.body!.groupId)
    
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/readStory", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.storyreview.readStory(req.body!.storyId)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/unlockStoryByCoin", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.storyreview.unlockStoryByCoin(req.body!.storyId)
    
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/trailReward", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.storyreview.trailReward(req.body!.groupId,req.body!.rewardIdList)
    
    player._trigger.emit("save")
    res.send(player.delta)
})

export default router;