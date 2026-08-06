/**
 * 游戏应用主模块
 * 
 * 创建 Express 应用实例，配置中间件，注册所有游戏路由。
 */

import httpContext from "express-http-context2";
import express from "express";
import bodyParser from "body-parser";
import { accountManager } from "./manager/AccountManger";
import config from "../config";

/** Express 应用实例 */
const app = express();

/** 注册 httpContext 中间件，用于请求上下文管理 */
app.use(httpContext.middleware);

/** 注册 JSON 解析中间件 */
app.use(bodyParser.json());

/**
 * 认证中间件：根据认证模式解析 secret 并注入玩家数据上下文
 * - single（单例）：强制 secret=1（单账号私服，任意 secret 都映射到 uid=1）
 * - real（真实）：保留客户端 secret（多账号），无效返回 401
 */
export const authMiddleware: express.RequestHandler = async (req, res, next) => {
  if (config.authMode === "real") {
    // 真实模式：secret 是 uid 或账号 token（参考 DoctoratePy query_account_by_secret），无效返回 401
    if (req.headers?.secret) {
      const uid = await accountManager.getUidByToken(req.headers.secret as string);
      if (!uid) {
        return res.status(401).send({ status: 401, msg: "无效的 secret" });
      }
      httpContext.set("playerData", await accountManager.getPlayerData(uid));
    }
  } else {
    // 单例模式：无论是否有 secret 都强制 uid=1（单账号私服——客户端全流程正常）
    req.headers.secret = "1";
    httpContext.set("playerData", await accountManager.getPlayerData("1"));
  }
  next();
};

app.use(authMiddleware);

/**
 * 设置游戏应用路由
 * 
 * 初始化账户管理器并注册所有游戏模块的路由。
 * @param app - Express 应用实例
 */
export async function setup(app: express.Application) {
  await accountManager.init();
  app.use("/businessCard", (await import("./router/businessCard")).default);
  app.use("/account", (await import("./router/account")).default);
  app.use("/charBuild", (await import("./router/charBuild")).default);
  app.use("/building", (await import("./router/building")).default);
  app.use("/quest", (await import("./router/quest")).default);
  app.use("/user", (await import("./router/user")).default);
  app.use("/activity", (await import("./router/activity")).default);
  app.use("/storyreview", (await import("./router/storyreview")).default);
  app.use("/mission", (await import("./router/mission")).default);
  app.use("/shop", (await import("./router/shop")).default);
  app.use("/rlv2", (await import("./router/rlv2")).default);
  app.use("/gacha", (await import("./router/gacha")).default);
  app.use("/mail", (await import("./router/mail")).default);
  app.use("/social", (await import("./router/social")).default);
  app.use("/retro", (await import("./router/retro")).default);
  app.use("/aprilFool", (await import("./router/aprilFool")).default);
  app.use("/crisis", (await import("./router/crisis")).default);
  app.use("/deepsea", (await import("./router/deepsea")).default);
  app.use("/tower", (await import("./router/tower")).default);
  app.use("/charm", (await import("./router/charm")).default);
  app.use("/charRotation", (await import("./router/charRotation")).default);
  app.use("/depot", (await import("./router/depot")).default);
  app.use("/sandbox", (await import("./router/sandbox")).default);
  app.use("/templateShop", (await import("./router/templateShop")).default);
  app.use("/multiplayer", (await import("./router/multiplayer")).default);
  app.use("/roguelike", (await import("./router/roguelike")).default);
  app.use("/campaignV2", (await import("./router/campaignV2")).default);
  app.use("/vecbreak", (await import("./router/vecbreak")).default);
  app.use("/interlock", (await import("./router/interlock")).default);
  app.use("/autochess", (await import("./router/autochess")).default);
  app.use("/pay", (await import("./router/pay")).default);
  app.use("/", (await import("./router/home")).default);
  // 挂载 user 模块的根级路由（gallery/cg/medal/mainlineClue/server_time 等非 /user 前缀接口）
  app.use("/", (await import("./router/user")).rootRouter);
}

export default app;