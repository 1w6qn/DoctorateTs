import { Router } from "express";
import { PlayerDataModel } from "./model/playerdata";
import httpContext from 'express-http-context';
import { PlayerDataManager } from "./manager/PlayerDataManager";
const router = Router();
router.post("/login", (req, res) => {
    res.send({
        "result": 0,
        "uid": "1",
        "secret": "1",
        "serviceLicenseVersion": 0
    });
});
router.post("/syncData", async (req, res) => {
    let data:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    
    res.send({
        "result": 0,
        "ts": parseInt((new Date().getTime()/1000).toString()),
        "user": data,
        "playerDataDelta": {
            "modified": {},
            "deleted": {}
        }
    })
});
router.post("/syncStatus", async (req, res) => {
    let data:PlayerDataManager = httpContext.get("playerdata") as PlayerDataManager;
    data._trigger.emit("syncStatus");
    res.send({
        "ts": parseInt((new Date().getTime()/1000).toString()),
        "result": {},
        "playerDataDelta": {
            "modified": {},
            "deleted": {}
        }
    })
});
export default router;