import { Router } from "express";
import config from "../config";
import { readJson } from "@utils/file";
import { buildNetworkConfigContent } from "./remote-config";

const router = Router();
// Windows 平台独立版本（odpy 参考：config.version.windows；无则回退单版本）
router.get("/official/Windows/version", async (req, res) => {
  const win = (config.version as any).windows;
  res.send(win || config.version);
});
router.get("/official/Android/version", async (req, res) => {
  let modPatch = {};
  if (config.assets.enableMods) {
    modPatch = {
      resVersion: config.version.resVersion + Math.floor(Math.random() * 100),
    };
  }
  res.send(Object.assign({}, config.version, modPatch));
});
// hv 端点格式：/config/prod/official/{clientVersion}/version（客户端按版本号请求）
router.get("/official/:version/version", async (req, res) => {
  let modPatch = {};
  if (config.assets.enableMods) {
    modPatch = {
      resVersion: config.version.resVersion + Math.floor(Math.random() * 100),
    };
  }
  res.send(Object.assign({}, config.version, modPatch));
});
router.get("/official/network_config", async (req, res) => {
  const content = buildNetworkConfigContent();
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
// 公告元数据（平台参数化——Android/Windows/iOS）
router.get(
  "/announce_meta/:platform/preannouncement.meta.json",
  async (req, res) => {
    res.send(await readJson("./data/announce/preannouncement.meta.json"));
  },
);
router.get(
  "/announce_meta/:platform/announcement.meta.json",
  async (req, res) => {
    res.send(await readJson("./data/announce/announcement.meta.json"));
  },
);
// 容错：客户端 URL 拼接（announce_meta + /api/gate/meta 误拼成一条请求）——返回公告
router.get(
  "/announce_meta/:platform/preannouncement.meta.json/api/gate/meta/:gatePlatform",
  async (req, res) => {
    res.send(await readJson("./data/announce/preannouncement.meta.json"));
  },
);

/** 1x1 透明 PNG（静态图片占位） */
const PLACEHOLDER_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
  "base64",
);


export default router;
