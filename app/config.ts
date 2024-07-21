interface UserConfig {
    Host: string;
    PORT: number;
    version: {
        resVersion: string;
        clientVersion: string;
    };
    enableMods:boolean;
    NetworkConfig: any;
    AppConfig: any;
}


const config: UserConfig = {
    Host: 'http://192.168.1.10',
    PORT: 8443,
    version:{
        "resVersion": "24-07-15-10-57-16-e6a8d4",
        "clientVersion": "2.3.01"
      },
    enableMods:false,
    NetworkConfig: {
        "configVer": "5",
        "funcVer": "V052",
        "configs": {
            "V052": {
                "override": true,
                "network": {
                    "gs": "{server}",
                    "as": "{server}",
                    "u8": "{server}/u8",
                    "hu": "{server}/assetbundle/official",
                    "hv": "{server}/config/prod/official/{0}/version",
                    "rc": "{server}/config/prod/official/remote_config",
                    "an": "{server}/config/prod/announce_meta/{0}/announcement.meta.json",
                    "prean": "{server}/config/prod/announce_meta/{0}/preannouncement.meta.json",
                    "sl": "https://ak.hypergryph.com/protocol/service",
                    "of": "https://ak.hypergryph.com/index.html",
                    "pkgAd": null,
                    "pkgIOS": null,
                    "secure": false
                }
            }
        }
    },
    AppConfig: {
        "data": {
            "antiAddiction": {
                "minorPeriodEnd": 21,
                "minorPeriodStart": 20
            },
            "payment": [
                {
                    "key": "alipay",
                    "recommend": true
                },
                {
                    "key": "wechat",
                    "recommend": false
                },
                {
                    "key": "pcredit",
                    "recommend": false
                }
            ],
            "customerServiceUrl": "https://chat.hypergryph.com/chat/h5/v2/index.html?sysnum=889ee281e3564ddf883942fe85764d44\u0026channelid=2",
            "cancelDeactivateUrl": "https://user.hypergryph.com/cancellation",
            "agreementUrl": {
                "game": "https://user.hypergryph.com/protocol/plain/ak/index",
                "unbind": "https://user.hypergryph.com/protocol/plain/ak/cancellation",
                "gameService": "https://user.hypergryph.com/protocol/plain/ak/service",
                "account": "https://user.hypergryph.com/protocol/plain/index",
                "privacy": "https://user.hypergryph.com/protocol/plain/privacy",
                "register": "https://user.hypergryph.com/protocol/plain/registration",
                "updateOverview": "https://user.hypergryph.com/protocol/plain/overview_of_changes",
                "childrenPrivacy": "https://user.hypergryph.com/protocol/plain/children_privacy"
            },
            "app": {
                "enablePayment": true,
                "enableAutoLogin": false,
                "enableAuthenticate": true,
                "enableAntiAddiction": true,
                "wechatAppId": "wx0ae7fb63d830f7c1",
                "alipayAppId": "2018091261385264",
                "oneLoginAppId": "7af226e84f13f17bd256eca8e1e61b5a",
                "enablePaidApp": false,
                "appName": "明日方舟",
                "appAmount": 600,
                "needShowName": false,
                "customerServiceUrl": "https://customer-service.hypergryph.com/ak?hg_token={hg_token}\u0026source_from=sdk"
            },
            "scanUrl": {
                "login": "yj://scan_login"
            },
            "userCenterUrl": "https://user.hypergryph.com/pcSdk/userInfo"
        },
        "msg": "OK",
        "status": 0,
        "type": "A"
    }
        
};

export default config;