/**
 * 游戏应用主模块
 * 
 * 创建 Express 应用实例，配置中间件，注册所有游戏路由。
 */

import httpContext from "express-http-context2";
import express from "express";
import bodyParser from "body-parser";
import { accountManager } from "./manager/AccountManger";
import { PlayerDataManager } from "./manager/PlayerDataManager";
import { acquireLock } from "@utils/mutex";
import { logger } from "@utils/logger";
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
    // 单例模式：无论是否有 secret 都强制固定账号（单账号私服——客户端全流程正常）
    const singleUid = config.singleUid || "1";
    req.headers.secret = singleUid;
    httpContext.set("playerData", await accountManager.getPlayerData(singleUid));
  }
  next();
};

app.use(authMiddleware);

/** 每账号请求互斥：同一 uid 的请求串行执行（防止并发 update() 丢变更） */
app.use(async (req, res, next) => {
  const player = httpContext.get<PlayerDataManager>("playerData");
  // /admin 管理接口属控制平面（含 game-proxy 自代理）：不占游戏锁，
  // 否则 single 模式下外层的 admin 请求持有 singleUid 锁、内层代理等待同一把锁会死锁
  if (!player || req.path.startsWith("/admin")) {
    next();
    return;
  }
  const release = await acquireLock(player.uid);
  res.on("finish", release);
  res.on("close", release);
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
  app.use("/mailCollection", (await import("./router/mailCollection")).default);
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
  // 挂载 activity 模块的根级路由（act25side/act29side/act36side 等客户端无 /activity 前缀的接口）
  app.use("/", (await import("./router/activity")).rootRouter);
  // 客户端将 roguelike/interlock/vecBreakV2 挂在 /activity 前缀下（/activity/roguelike/* 等），
  // 复用既有 router（其自带 /roguelike/*、/interlock/*、/vecBreakV2/* 路径），补 /activity 挂载别名
  app.use("/activity", (await import("./router/roguelike")).default);
  app.use("/activity", (await import("./router/interlock")).default);
  app.use("/activity", (await import("./router/vecbreak")).default);
  // 统一错误处理：异步 handler 抛错（Express 5 自动捕获）→ JSON 而非 HTML 500。
  // 例：single 模式社交自请求（不能加自己为好友）等业务校验错误，客户端收到可解析 JSON
  app.use(gameErrorHandler);
}

/**
 * 游戏路由统一错误处理中间件
 *
 * 无此中间件时 Express 默认返回 HTML 500，客户端 JSON 解析失败。
 * @param err - 抛出的错误
 */
export function gameErrorHandler(
  err: unknown,
  _req: express.Request,
  res: express.Response,
  _next: express.NextFunction,
): void {
  logger.error("game", (err as Error)?.message || String(err));
  res.status(500).json({
    status: 1,
    msg: "服务器内部错误",
    code: "INTERNAL_ERROR",
  });
}

export default app;