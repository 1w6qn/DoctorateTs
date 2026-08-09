import express from "express";
import axios, { AxiosError } from "axios";
import fs from "fs/promises";
import path from "path";
import morgan from "morgan";

/**
 * 官服抓包代理：客户端（network_config 指向本代理）→ 本代理 → 按官服路由规则分发到官方主机。
 *
 * 路由分发规则（路径前缀 → 官方主机，注册顺序即匹配优先级）：
 *   /config/*                      → ak-conf.hypergryph.com/config
 *   /u8/*                          → as.hypergryph.com/u8
 *   /auth/*                        → as.hypergryph.com（as 域带 /auth 前缀的私服形式）
 *   /app/*                         → as.hypergryph.com/app
 *   /user/auth|info|online|oauth2*、/general/* → as.hypergryph.com（as 域根路径形式）
 *   /game/*                        → ak-gs-gf.hypergryph.com（ak-gs 域带 /game 基址前缀形式）
 *   /api/gate/*                    → ak-webview.hypergryph.com/api/meta
 *   /api/*                         → game-config.hypergryph.com/api
 *   其余 POST（根路径游戏域）       → ak-gs-gf.hypergryph.com
 *     （/account、/shop、/activity、/user/checkIn、/batch_event 等）
 *
 * 修复说明：客户端在 gs/as 带尾斜杠配置下会发 /game//shop/getSkinGoodList 这类双斜杠路径，
 * 官服对 // 返回 404——createProxyHandler 已归一化 endpoint 去除前导斜杠；
 * 且当 gs 配置为裸地址（http://127.0.0.1:8444）时游戏路由以根路径到达（如 /shop/getSkinGoodList），
 * 由末尾的根路径游戏域兜底规则转发，解决 /game/activity/getActivityCheckInVideoReward、
 * /game/shop/getSkinGoodList 无法处理的问题。
 */
const PORT = 8444;
const BASE = `http://127.0.0.1:${PORT}`;

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
    // 官服对双斜杠路径返回 404（已验证 //shop/getSkinGoodList → 404，/shop/getSkinGoodList → 401），
    // 归一化去掉前导斜杠，保证拼出的转发 URL 无 //。
    const endpoint: string = (req.params.endpoint as unknown as string[])
      .join("/")
      .replace(/^\/+/, "");

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
        // 官服返回 401/400 等状态属正常（未带有效 secret/参数），不抛异常，原样透传
        validateStatus: () => true,
      });
      res.status(response.status).send(response.data);
      await printJson(response.data, endpoint).catch(() => undefined); // 在这里调用 printJson

      // 保存请求数据到文件
      await printJson(JSON.stringify(requestData), `request_${endpoint}`).catch(
        () => undefined,
      );
    } catch (error) {
      const axiosError = error as AxiosError; // 类型断言
      // 仅网络层错误（官方主机不可达）返回 502；有响应则已由 validateStatus 透传
      console.error(
        `Error during request forwarding to ${baseUrl}/${endpoint}: ${axiosError.message}`,
      );
      res.status(502).send("Bad Gateway");
    }
  };
};

app.get("/config/prod/official/network_config", (req, res) => {
  const responseData = {
    sign: "sign",
    content: JSON.stringify({
      configVer: "5",
      funcVer: "V070",
      configs: {
        V070: {
          override: true,
          network: {
            gs: BASE,
            as: BASE,
            u8: `${BASE}/u8`,
            hu: "https://ak.hycdn.cn/assetbundle/official",
            hv: "https://ak-conf.hypergryph.com/config/prod/official/{0}/version",
            rc: `${BASE}/config/prod/official/remote_config`,
            an: `${BASE}/config/prod/announce_meta/Android/announcement.meta.json`,
            prean: `${BASE}/config/prod/announce_meta/Android/preannouncement.meta.json`,
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
app.get("/api/game/get_latest", (req, res) => {
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
app.get("/api/remote_config/1/prod/default/Windows/network_config", (req, res) => {
  const responseData = {
    "an": "https://ak-conf.hypergryph.com/config/prod/announce_meta/{0}/announcement.meta.json",
    "as": BASE,
    "gs": BASE,
    "hu": "https://ak.hycdn.cn/assetbundle/official",
    "hv": "https://ak-conf.hypergryph.com/config/prod/official/{0}/version",
    "of": "https://ak.hypergryph.com/index.html",
    "sl": "https://ak.hypergryph.com/protocol/service",
    "u8": `${BASE}/u8`,
    "pkgAd": "https://ak.hypergryph.com/download",
    "prean": "https://ak-webview.hypergryph.com",
    "devsdk": false,
    "pkgIOS": "https://apps.apple.com/cn/app/id1454663939",
    "configVer": 5
  }
  res.json(responseData);
});
app.get("/config/*endpoint", createProxyHandler("https://ak-conf.hypergryph.com/config"));
app.post("/u8/*endpoint", createProxyHandler("https://as.hypergryph.com/u8"));
app.get("/auth/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.get("/app/*endpoint", createProxyHandler("https://as.hypergryph.com/app"));
app.post("/auth/*endpoint", createProxyHandler("https://as.hypergryph.com"));
// as 域根路径形式（gs/as 为裸地址时客户端不再带 /auth 前缀）
app.get("/user/auth/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.post("/user/auth/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.get("/user/info/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.post("/user/info/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.get("/user/online/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.post("/user/online/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.get("/user/oauth2/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.post("/user/oauth2/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.get("/general/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.post("/general/*endpoint", createProxyHandler("https://as.hypergryph.com"));
app.post(
  "/game/*endpoint",
  createProxyHandler("https://ak-gs-gf.hypergryph.com"),
);
app.get(
  "/api/gate/*endpoint",
  createProxyHandler("https://ak-webview.hypergryph.com/api/meta"),
);
app.get(
  "/api/*endpoint",
  createProxyHandler("https://game-config.hypergryph.com/api"),
);
// 游戏域根路径兜底（gs 为裸地址或官服域名时，游戏路由以根路径到达：
// /shop/getSkinGoodList、/activity/getActivityCheckInVideoReward、/account/login、
// /user/checkIn、/batch_event 等）。放在最后，as 域根路径规则优先匹配。
app.post("/*endpoint", createProxyHandler("https://ak-gs-gf.hypergryph.com"));

app.listen(PORT, () => {
  console.log(`Server is running on http://0.0.0.0:${PORT}`);
});
