
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from './manager/PlayerDataManager';

const router = Router();
router.post("Build/batchSetCharVoiceLan", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.batchSetCharVoiceLan(req.body!.voiceLan)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("Build/setDefaultSkill", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.setDefaultSkill(req.body!.charInstId,req.body!.defaultSkillIndex)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("Build/changeCharSkin", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.changeCharSkin(req.body!.charInstId,req.body!.skinId)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("Build/setEquipment", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.setEquipment(req.body!.charInstId,req.body!.equipId)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("Build/changeCharTemplate", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.changeCharTemplate(req.body!.charInstId,req.body!.templateId)
    player._trigger.emit("save")
    res.send(player.delta)
})

router.post("Build/boostPotential", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.boostPotential(req.body!.charInstId,req.body!.itemId,req.body!.targetRank)
    player._trigger.emit("save")
    res.send({
        result:1,
        ...player.delta
    })
})
router.post("Build/upgradeChar", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.upgradeChar(req.body!.charInstId,req.body!.expMats)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("Build/upgradeSkill", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.upgradeSkill(req.body!.charInstId,req.body!.targetLevel)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("Build/evolveChar", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.evolveChar(req.body!.charInstId,req.body!.destEvolvePhase)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/changeMarkStar", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.changeMarkStar(req.body!.chrIdDict)
    player._trigger.emit("save")
    res.send(player.delta)
})
export default router;