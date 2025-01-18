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
      funcVer: "V057",
      configs: {
        V057: {
          override: true,
          network: {
            gs: "http://192.168.0.100:8443/game/",
            as: "http://192.168.0.100:8443/auth/",
            u8: "http://192.168.0.100:8443/u8/",
            hu: "https://ak.hycdn.cn/assetbundle/official",
            hv: "https://ak-conf.hypergryph.com/config/prod/official/{0}/version",
            rc: "http://192.168.0.100:8443/config/prod/official/remote_config",
            an: "http://192.168.0.100:8443/config/prod/announce_meta/Android/announcement.meta.json",
            prean:
              "http://192.168.0.100:8443/config/prod/announce_meta/Android/preannouncement.meta.json",
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

const PORT = 8443;
app.listen(PORT, () => {
  console.log(`Server is running on http://0.0.0.0:${PORT}`);
});
