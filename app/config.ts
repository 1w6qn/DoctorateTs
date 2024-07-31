interface UserConfig {
    Host: string;
    PORT: number;
    version: {
        resVersion: string;
        clientVersion: string;
    };
    enableMods:boolean;
    NetworkConfig: any;
}


const config: UserConfig = {
    Host: 'http://192.168.1.11',
    PORT: 8443,
    version:{
        "resVersion": "24-07-23-15-16-02-a53606",
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
}

export default config;