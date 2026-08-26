import http from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import bodyParser from "body-parser";
import httpContext from "express-http-context2";
import { openDatabase, closeDatabase } from "../../app/db/database";
import excel from "../../app/excel/excel";
import { accountManager } from "../../app/game/service/player/AccountManager";
import { authMiddleware, gameErrorHandler } from "../../app/game/app";
import authRouter from "../../app/auth/auth";
import userRouter from "../../app/game/service/router/user";
import gachaRouter from "../../app/game/service/gacha/handler";
import shopRouter from "../../app/game/service/shop/handler";
import mailRouter from "../../app/game/service/router/mail";
import socialRouter from "../../app/game/service/router/social";
import rlv2Router from "../../app/game/service/rlv2/handler";

/**
 * 一个 HTTP 请求的响应封装
 * @property status - HTTP 状态码
 * @property body - 解析后的 JSON（非 JSON 响应时为空对象）
 */
export interface ApiResponse {
  status: number;
  body: any;
}

/**
 * 真实集成测试夹具
 *
 * 附带了真实业务运行所需的环境（内存 SQLite + 真实 excel + 真实 accountManager），
 * 并通过真实 HTTP server 暴露游戏路由。测试可据此验证「输入请求体 → 输出 playerDataDelta」。
 * @property baseUrl - 随机端口 HTTP 基础地址
 * @property register - 新建账号（复用官方 /user/auth/v1/register 链路），返回 uid 与 secret
 * @property post - 发送 JSON POST 请求（可带 secret 头），返回状态码与解析后的 body
 * @property getPlayerData - 按 uid 获取内存中的真实玩家数据管理器
 * @property close - 关闭服务器与数据库
 */
export interface ApiFixture {
  baseUrl: string;
  register: (account: string, password: string) => Promise<{ uid: string; secret: string }>;
  post: (path: string, body?: unknown, secret?: string) => Promise<ApiResponse>;
  getPlayerData: (uid: string) => any;
  close: () => Promise<void>;
}

/**
 * 启动一套真实游戏 API 集成测试环境
 *
 * 初始化顺序（有依赖，必须保持）：
 * 1. openDatabase(":memory:")——建立全局内存 SQLite 连接（绝不读写真实 social.db/存档文件）
 * 2. excel.init()——真实加载 data/excel/*.json 数据表（含 gacha 抽卡配置）
 * 3. accountManager.init()——复用内存库加载/迁移用户配置（只读真实 users.json 种子）
 * 4. 组装 Express 应用并挂载 auth + 各游戏路由（认证→路由→统一错误处理）
 * 5. 监听随机端口
 * @returns 可直接用于发请求的集成夹具
 */
export async function startApiFixture(): Promise<ApiFixture> {
  openDatabase(":memory:");
  await excel.init();
  await accountManager.init();

  const app = express();
  app.use(httpContext.middleware);
  app.use(bodyParser.json());
  app.use(authMiddleware);
  // 认证路由挂根（含 /user/auth/v1/register、/user/auth/v1/login）
  app.use("/", authRouter);
  app.use("/user", userRouter);
  app.use("/gacha", gachaRouter);
  app.use("/shop", shopRouter);
  app.use("/mail", mailRouter);
  app.use("/social", socialRouter);
  app.use("/rlv2", rlv2Router);
  app.use(gameErrorHandler);

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  return {
    baseUrl,
    register: async (account, password) => {
      const res = await fetch(`${baseUrl}/user/auth/v1/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ account, password }),
      });
      const body = await res.json();
      if (res.status !== 200 || body.result !== 0) {
        throw new Error(`注册失败 account=${account}：${JSON.stringify(body)}`);
      }
      return { uid: String(body.uid), secret: String(body.token) };
    },
    post: async (path, body = {}, secret) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (secret) headers["secret"] = secret;
      const res = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      const text = await res.text();
      let parsed: any = {};
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text };
      }
      return { status: res.status, body: parsed };
    },
    getPlayerData: (uid) => accountManager.data[uid],
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      closeDatabase();
    },
  };
}