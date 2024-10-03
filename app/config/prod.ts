import { Router } from "express";
import config from "../config";
import { readJson } from "@utils/file";

const router = Router();
router.get("/official/Android/version", async (req, res) => {
  let modPatch = {};
  if (config.assets.enableMods) {
    modPatch = {
      resVersion: config.version.resVersion + Math.floor(Math.random() * 100),
    };
  }
  res.send(Object.assign({}, config.version, modPatch));
});
router.get("/official/network_config", async (req, res) => {
  const content = JSON.stringify(config.NetworkConfig).replace(
    /{server}/g,
    `${config.Host}:${config.PORT}`,
  );
  const sign = "sign";
  res.send({ sign, content });
});
router.get("/official/refresh_config", async (req, res) => {
  res.send(config.version);
});
router.get("/official/remote_config", async (req, res) => {
  res.send({
    enableGameBI: false,
    enableSDKNetSecure: true,
    enableBestHttp: true,
  });
});
router.get(
  "/announce_meta/Android/preannouncement.meta.json",
  async (req, res) => {
    res.send(readJson("./data/announce/preannouncement.meta.json"));
  },
);
router.get(
  "/announce_meta/Android/announcement.meta.json",
  async (req, res) => {
    res.send(readJson("./data/announce/announcement.meta.json"));
  },
);
export default router;
