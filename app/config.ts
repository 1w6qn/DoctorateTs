import { readJsonSync } from "@utils/file";

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
    autoUpdate: boolean;
  };
  NetworkConfig: object;
}

const config = readJsonSync<UserConfig>("./data/config.json");

export default config;
