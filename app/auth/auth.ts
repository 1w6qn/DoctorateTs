import { Router } from "express";
import config from "../config"
const router = Router();
router.get('/general/v1/server_time', (req, res) => {
    res.send({
        "status": 0,
        "type": "A",
        "msg": "OK",
        "data": {
            "serverTime": new Date().getTime(),
            "isHoliday": false
        }
    })
})
router.get('/app/v1/config', (req, res) => {
    res.send(config.AppConfig)
})
router.get('/user/auth/v1/token_by_phone_password', (req, res) => {
    res.send({
        "status": 0,
        "msg": "OK",
        "data": {
            "token": "doctorate"
        }
    })
})
router.get('/user/info/v1/basic', (req, res) => {
    res.send({
        "status": 0,
        "msg": "OK",
        "data": {
            "hgId": "1",
            "phone": "doctorate",
            "email": "doctorate",
            "identityNum": "doctorate",
            "identityName": "doctorate",
            "isMinor": false,
            "isLatestUserAgreement": true
        }
    })
})
router.get('/user/oauth2/v2/grant', (req, res) => {
    res.send({
        "status": 0,
        "msg": "OK",
        "data": {
            "code": "doctorate",
            "uid": "1"
        }
    })
})
router.get('/pay/getUnconfirmedOrderIdList', (req, res) => {
    res.send({
        "orderIdList": [],
        "playerDataDelta": {
            "modified": {},
            "deleted": {}
        }
    })
})
router.get('/app/v1/config', (req, res) => {
    res.send(config.AppConfig)
})

export default router;