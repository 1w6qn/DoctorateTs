import { Router } from "express";
import httpContext from 'express-http-context';
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { now } from "@utils/time";
const router = Router();
router.post("/login", (req, res) => {
    
    res.send({
        "result": 0,
        "uid": "1",
        "secret": "1",
        "serviceLicenseVersion": 0
    });

});
router.post("/syncData", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player._playerdata.pushFlags.status=now()
    res.send({
        "result": 0,
        "ts": now(),
        "user": player,
        ...player.delta
    })
});
router.post("/syncStatus", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    player._trigger.emit("status:refresh:time");
    res.send({
        "ts": now(),
        "result": {},
        ...player.delta
    })
});
router.post("/syncPushMessage", (req, res) => {
    let player:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    res.send({})
});

export default router;