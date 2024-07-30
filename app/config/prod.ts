import { Router } from "express";
import config from "../config"
const router = Router();
router.get('/official/Android/version', (req, res) => {
    res.send(config.version)
})
router.get('/official/network_config', (req, res) => {
    let content = JSON.stringify(config.NetworkConfig);
    res.send({
        "sign": "sign",
        "content": content.replace(/{server}/g, `${config.Host}:${config.PORT}`)
    })
})
router.get('/official/refresh_config', (req, res) => {
    res.send({"resVersion":config.version.resVersion})
})
router.get('/official/remote_config', (req, res) => {
    res.send({
        "enableGameBI": false,
        "enableSDKNetSecure": true,
        "enableBestHttp": true
    })
})
router.get('/announce_meta/Android/preannouncement.meta.json', async(req, res) => {
    res.send(await import("../../data/announce/preannouncement.meta.json"))
})
router.get('/announce_meta/Android/announcement.meta.json', async(req, res) => {
    res.send(await import("../../data/announce/announcement.meta.json"))
})
export default router ;
