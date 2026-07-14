/**
 * 游戏应用主模块
 * 
 * 创建 Express 应用实例，配置中间件，注册所有游戏路由。
 */

import httpContext from "express-http-context2";
import express from "express";
import bodyParser from "body-parser";
import { accountManager } from "./manager/AccountManger";

/** Express 应用实例 */
const app = express();

/** 注册 httpContext 中间件，用于请求上下文管理 */
app.use(httpContext.middleware);

/** 注册 JSON 解析中间件 */
app.use(bodyParser.json());

/**
 * 全局中间件：验证用户身份并设置玩家数据上下文
 * 
 * 通过请求头中的 secret 字段验证用户身份，将玩家数据注入到请求上下文中。
 */
app.use(async (req, res, next) => {
  if (req.headers?.secret) {
    if (req.headers.secret != "1") {
      req.headers.secret = "1";
    }
    const data = await accountManager.getPlayerData(
      req.headers.secret as string,
    );
    httpContext.set("playerData", data);
  }
  next();
});

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
  app.use("/", (await import("./router/home")).default);
}

export default app;