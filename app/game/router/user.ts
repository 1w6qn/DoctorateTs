
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';
import { ItemBundle } from '../../excel/character_table';

const router = Router();
router.post("/changeSecretary", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.changeSecretary(req.body)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/changeAvatar", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.changeAvatar(req.body!.avatar)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/changeResume", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    if((req.body!.resume as string).slice(0)=="@"){
        player._trigger.emit(req.body!.resume.slice(1,req.body!.resume.length))
    }else{
        player.status.changeResume(req.body!.resume)
    }
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/bindNickName", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.bindNickName(req.body!.nickname)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/useRenameCard", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.bindNickName(req.body!.nickname)
    player._trigger.emit("useItems",[{id:req.body!.itemId,count:1,instId:req.body!.instId}as ItemBundle])
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/receiveTeamCollectionReward", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.receiveTeamCollectionReward(req.body!.rewardId)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/buyAp", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.buyAp()
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/exchangeDiamondShard", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.status.exchangeDiamondShard(req.body!.count)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/useItem", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    let item={id:req.body!.itemId,count:req.body!.count,instId:req.body!.instId}as ItemBundle
    player._trigger.emit("useItems",[item])
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/useItems", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    let items:ItemBundle[]=[]
    for(let item of req.body!.items){
        items.push({id:item.itemId,count:item.count,instId:item.instId}as ItemBundle)
    }
    player._trigger.emit("useItems",items)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/checkIn", (req, res) => {
    let player: PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player._trigger.emit("save")
    res.send({
        ...player.checkIn.checkIn(),
        ...player.delta
    })
})
export default router;