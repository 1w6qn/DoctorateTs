import express from "express";
import axios, { AxiosError } from "axios";
import fs from "fs/promises";
import path from "path";
import morgan from "morgan";

/**
 *  已知bug:
 *  1.无法处理/game/activity/getActivityCheckInVideoReward
 *  2.无法处理/game/shop/getSkinGoodList
 *  */
const app = express();
app.use(express.json());
app.use(
  morgan(":method :url :status :res[content-length] - :response-time ms"),
);

const printJson = async (data: string, filepath: string): Promise<void> => {
  const now = new Date();
  const timestamp = now.toISOString().replace(/[:.]/g, "-");
  const dirPath = path.join(__dirname, "tmp", filepath);
  const filePath = path.join(dirPath, `${timestamp}.json`);

  await fs.mkdir(dirPath, { recursive: true });
  await fs.writeFile(
    filePath,
    JSON.stringify(typeof data === "string" ? JSON.parse(data) : data, null, 2),
  );
};

const createProxyHandler = (baseUrl: string) => {
  return async (req: express.Request, res: express.Response) => {
    const endpoint: string = (req.params.endpoint as unknown as string[]).join(
      "/",
    );

    // 保存请求数据的代码
    const requestData = {
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      body: req.body,
      query: req.query,
      timestamp: new Date().toISOString(),
    };

    try {
      const response = await axios({
        method: req.method,
        url: `${baseUrl}/${endpoint}`,
        data: req.method === "POST" ? req.body : undefined,
        headers: { ...req.headers, Host: undefined },
        params: req.query,
      });
      res.send(response.data);
      await printJson(response.data, endpoint); // 在这里调用 printJson

      // 保存请求数据到文件
      await printJson(JSON.stringify(requestData), `request_${endpoint}`);
    } catch (error) {
      const axiosError = error as AxiosError; // 类型断言
      const errorMessage = axiosError.response
        ? `Error ${axiosError.response.status}: ${axiosError.response.data}`
        : axiosError.message;
      // 输出简化的错误信息
      console.error(
        `Error during request forwarding to ${baseUrl}/${endpoint}: ${errorMessage}`,
      );
      res.status(500).send("Internal Server Error");
    }
  };
};

app.get("/config/prod/official/network_config", (req, res) => {
  const responseData = {
    sign: "sign",
    content: JSON.stringify({
      configVer: "5",
      funcVer: "V059",
      configs: {
        V059: {
          override: true,
          network: {
            gs: "http://127.0.0.1:8443/game/",
            as: "http://127.0.0.1:8443/auth/",
            u8: "http://127.0.0.1:8443/u8/",
            hu: "https://ak.hycdn.cn/assetbundle/official",
            hv: "https://ak-conf.hypergryph.com/config/prod/official/{0}/version",
            rc: "http://127.0.0.1:8443/config/prod/official/remote_config",
            an: "http://127.0.0.1:8443/config/prod/announce_meta/Android/announcement.meta.json",
            prean:
              "http://127.0.0.1:8443/config/prod/announce_meta/Android/preannouncement.meta.json",
            sl: "https://ak.hypergryph.com/protocol/service",
            of: "https://ak.hypergryph.com/index.html",
            pkgAd: "https://ak.hypergryph.com/download",
            pkgIOS: "https://apps.apple.com/cn/app/id1454663939",
            secure: false,
          },
        },
      },
    }),
  };
  res.json(responseData);
});
app.get("/launcher", (req, res) => {
  const responseData = {
  "action": 0,
  "version": "76.0.0",
  "request_version": "76.0.0",
  "pkg": {
    "packs": [],
    "total_size": "0",
    "file_path": "https://ak.hycdn.cn/GzD1CpaWgmSq1wew/76.0/update/1/1/Windows/76.0.0_jbAnLFy2dtzNQvii/files",
    "url": "",
    "md5": "",
    "package_size": "0",
    "file_id": "0",
    "sub_channel": "1",
    "game_files_md5": "86f10402f2abeb283624ae90f4a0063a"
  },
  "patch": null,
  "state": 0,
  "launcher_action": 0,
  "pre_patch": null,
  "client_version": "2.7.61"
}
  res.json(responseData);
});
app.get("/game-config", (req, res) => {
  const responseData = {
    "an": "https://ak-conf.hypergryph.com/config/prod/announce_meta/{0}/announcement.meta.json",
    "as": "http://127.0.0.1:8443/auth/",
    "gs": "http://127.0.0.1:8443/game/",
    "hu": "https://ak.hycdn.cn/assetbundle/official",
    "hv": "https://ak-conf.hypergryph.com/config/prod/official/{0}/version",
    "of": "https://ak.hypergryph.com/index.html",
    "sl": "https://ak.hypergryph.com/protocol/service",
    "u8": "http://127.0.0.1:8443/u8/",
    "pkgAd": "https://ak.hypergryph.com/download",
    "prean": "https://ak-webview.hypergryph.com",
    "devsdk": false,
    "pkgIOS": "https://apps.apple.com/cn/app/id1454663939",
    "configVer": 5
  }
  res.json(responseData);
});
app.get(
  "/config/*endpoint",
  createProxyHandler("https://ak-conf.hypergryph.com/config"),
);
app.post("/u8/*endpoint", createProxyHandler("https://as.hypergryph.com/u8"));
app.get("/auth/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.post("/auth/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.post(
  "/game/*endpoint",
  createProxyHandler("https://ak-gs-gf.hypergryph.com"),
);
app.get(
  "/*endpoint",
  createProxyHandler("https://launcher.hypergryph.com"),
);
const PORT = 8443;
app.listen(PORT, () => {
  console.log(`Server is running on http://0.0.0.0:${PORT}`);
});
