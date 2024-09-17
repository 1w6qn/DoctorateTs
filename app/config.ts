interface UserConfig {
  Host: string;
  PORT: number;
  version: {
    resVersion: string;
    clientVersion: string;
  };
  assets: {
    enableMods: boolean;
    downloadLocally: boolean;
  };

  NetworkConfig: any;
}

const config: UserConfig = {
  Host: "http://192.168.0.6",
  PORT: 8000,
  version: {
    resVersion: "24-09-05-09-46-01-db17aa",
    clientVersion: "2.3.61",
  },
  assets: {
    enableMods: false,
    downloadLocally: false,
  },
  NetworkConfig: {
    configVer: "5",
    funcVer: "V054",
    configs: {
      V054: {
        override: true,
        network: {
          gs: "{server}",
          as: "{server}",
          u8: "{server}/u8",
          hu: "{server}/assetbundle/official",
          hv: "{server}/config/prod/official/{0}/version",
          rc: "{server}/config/prod/official/remote_config",
          an: "{server}/config/prod/announce_meta/{0}/announcement.meta.json",
          prean:
            "{server}/config/prod/announce_meta/{0}/preannouncement.meta.json",
          sl: "https://ak.hypergryph.com/protocol/service",
          of: "https://ak.hypergryph.com/index.html",
          pkgAd: null,
          pkgIOS: null,
          secure: false,
        },
      },
    },
  },
};

export default config;
