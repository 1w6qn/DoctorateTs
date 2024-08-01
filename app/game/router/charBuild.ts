
import { Router } from 'express';
import httpContext from 'express-http-context';
import { PlayerDataManager } from '../manager/PlayerDataManager';

const router = Router();
router.post("/batchSetCharVoiceLan", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.batchSetCharVoiceLan(req.body!.voiceLan)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/setDefaultSkill", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.setDefaultSkill(req.body!.charInstId,req.body!.defaultSkillIndex)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/changeCharSkin", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.changeCharSkin(req.body!.charInstId,req.body!.skinId)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/setEquipment", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.setEquipment(req.body)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/unlockEquipment", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.unlockEquipment(req.body)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/upgradeEquipment", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.upgradeEquipment(req.body)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/changeCharTemplate", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.changeCharTemplate(req.body!.charInstId,req.body!.templateId)
    player._trigger.emit("save")
    res.send(player.delta)
})

router.post("/boostPotential", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.boostPotential(req.body!.charInstId,req.body!.itemId,req.body!.targetRank)
    player._trigger.emit("save")
    res.send({
        result:1,
        ...player.delta
    })
})
router.post("/upgradeChar", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.upgradeChar(req.body!.charInstId,req.body!.expMats)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/upgradeSkill", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.upgradeSkill(req.body!.charInstId,req.body!.targetLevel)
    player._trigger.emit("save")
    res.send(player.delta)
})
router.post("/evolveChar", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player.troop.evolveChar(req.body!.charInstId,req.body!.destEvolvePhase)
    player._trigger.emit("save")
    res.send(player.delta)
})

export default router;