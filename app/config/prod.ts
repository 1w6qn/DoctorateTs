import { Router } from "express";
import config from "../config"
import prean from "../../data/announce/preannouncement.meta.json"
import an from "../../data/announce/announcement.meta.json"
import os from "os";

function getLocalIpAddress(): string {
    const interfaces = os.networkInterfaces();
    for (const interfaceName in interfaces) {
        const networkInterface = interfaces[interfaceName];
        if (networkInterface) {
            for (const iface of networkInterface) {
                // 检查是否是IPv4并且不是回环地址
                if (iface.family === 'IPv4' && !iface.internal) {
                    return iface.address;
                }
            }
        }
    }
    return "";
}

const router = Router();
router.get('/official/Android/version', (req, res) => {
    res.send(config.version)
})
router.get('/official/network_config', (req, res) => {
    let content = JSON.stringify(config.NetworkConfig);
    res.send({
        "sign": "sign",
        "content": content.replace(/{server}/g, `${getLocalIpAddress()}:${config.PORT}`)
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
router.get('/announce_meta/Android/preannouncement.meta.json', (req, res) => {
    res.send(prean)
})
router.get('/announce_meta/Android/announcement.meta.json', (req, res) => {
    res.send(an)
})
export default router ;
