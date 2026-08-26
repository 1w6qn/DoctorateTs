/**
 * 集中路由注册表
 *
 * 收敛 app/game/app.ts 中所有（含内联 URL 重写）的挂载逻辑为一张声明式路由表，
 * setup() 迭代该表完成注册。数组有序：顺序即挂载顺序（多根挂载与别名别名的匹配优先级
 * 依赖先后次序，错误处理中间件 gameErrorHandler 由调用方始终保留在最后）。
 */

import express from "express";

/**
 * URL 重写函数签名
 *
 * 在对应 router 挂载前对 req.url 进行改写，用于客户端别名与服务端既有路径不一致时的对齐
 * （如 /crisisV2/* → /v2/*，/sandboxPerm/sandboxV2|V3/* → /v2|/v3/*）。
 * @param req - 待重写的请求对象
 */
export type RouteRewrite = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => void;

/**
 * 单个路由注册记录
 *
 * - prefix：挂载前缀（"" 或 "/" 表示根级挂载）
 * - module：懒加载的 router 模块路径（相对本文件）
 * - exportName：取模块的哪种导出，默认 "default"，根级可用 "rootRouter"
 * - rewrite：可选 URL 重写函数，在挂载前执行
 */
export interface RouteRegistration {
  /** 挂载前缀（如 "/account"；根级为 "/"） */
  prefix: string;
  /** 待懒加载的 router 模块路径（相对本文件） */
  module: string;
  /** 取模块的导出名：普通 router 用 "default"，根级路由用 "rootRouter" */
  exportName?: "default" | "rootRouter";
  /** 可选 URL 重写函数，在挂载前对 req.url 改写 */
  rewrite?: RouteRewrite;
}

/**
 * 危机合约 V2 客户端别名重写
 *
 * 客户端调用 /crisisV2/*，服务端既有路由为 /crisis/v2/*，故在 /crisisV2 前缀下
 * 将去前缀后的 url 前补 /v2（/crisisV2/battleStart → /v2/battleStart）。
 * @param req - 待重写的请求对象
 */
export function crisisV2Rewrite(
  req: express.Request,
  _res: express.Response,
  next: express.NextFunction,
): void {
  req.url = `/v2${req.url}`;
  next();
}

/**
 * 沙盒权限客户端别名重写
 *
 * 客户端路由为 /sandboxPerm/sandboxV2|V3/* 与 /sandboxPerm/changeTopic|pinTopic，
 * 服务端 sandbox router 路径为 /v2|/v3|/changeTopic|/pinTopic，故将 /sandboxV2|V3 段
 * 映射为 /v2|/v3，其余路径（changeTopic/pinTopic 等）保持不变。
 * @param req - 待重写的请求对象
 */
export function sandboxPermRewrite(
  req: express.Request,
  _res: express.Response,
  next: express.NextFunction,
): void {
  if (req.url.startsWith("/sandboxV2/")) {
    req.url = `/v2${req.url.slice("/sandboxV2".length)}`;
  } else if (req.url.startsWith("/sandboxV3/")) {
    req.url = `/v3${req.url.slice("/sandboxV3".length)}`;
  }
  next();
}

/**
 * 声明式路由表（顺序敏感）
 *
 * 顺序与重构前 setup() 的挂载顺序完全一致：普通前缀挂载 → 根级挂载（user/activity
 * rootRouter、模块自有前缀对齐）→ /activity 别名 → /crisisV2、/sandboxPerm 重写别名，
 * 最后是 misc-alignment 根级对齐。gameErrorHandler 不在表中，由 setup() 收尾注册。
 */
export const routes: RouteRegistration[] = [
  // —— 普通前缀挂载 ——
  { prefix: "/businessCard", module: "./service/router/businessCard" },
  { prefix: "/account", module: "./service/router/account" },
  { prefix: "/charBuild", module: "./service/router/charBuild" },
  { prefix: "/building", module: "./service/building/handler" },
  { prefix: "/quest", module: "./service/router/quest" },
  { prefix: "/user", module: "./service/router/user" },
  { prefix: "/activity", module: "./service/activity" },
  { prefix: "/storyreview", module: "./service/router/storyreview" },
  { prefix: "/mission", module: "./service/mission/handler" },
  { prefix: "/shop", module: "./service/shop/handler" },
  { prefix: "/rlv2", module: "./service/rlv2/handler" },
  { prefix: "/gacha", module: "./service/gacha/handler" },
  { prefix: "/mail", module: "./service/router/mail" },
  { prefix: "/social", module: "./service/router/social" },
  { prefix: "/retro", module: "./service/router/retro" },
  { prefix: "/aprilFool", module: "./service/router/aprilFool" },
  { prefix: "/crisis", module: "./service/router/crisis" },
  { prefix: "/deepsea", module: "./service/router/deepsea" },
  { prefix: "/siracusaMap", module: "./service/router/siracusaMap" },
  { prefix: "/explore", module: "./service/router/explore" },
  { prefix: "/tower", module: "./service/router/tower" },
  { prefix: "/charm", module: "./service/router/charm" },
  { prefix: "/charRotation", module: "./service/router/charRotation" },
  { prefix: "/depot", module: "./service/router/depot" },
  { prefix: "/sandbox", module: "./service/router/sandbox" },
  { prefix: "/templateShop", module: "./service/router/templateShop" },
  { prefix: "/mailCollection", module: "./service/router/mailCollection" },
  { prefix: "/multiplayer", module: "./service/router/multiplayer" },
  { prefix: "/roguelike", module: "./service/router/roguelike" },
  { prefix: "/campaignV2", module: "./service/router/campaignV2" },
  { prefix: "/vecbreak", module: "./service/router/vecbreak" },
  { prefix: "/interlock", module: "./service/router/interlock" },
  { prefix: "/autochess", module: "./service/router/autochess" },
  { prefix: "/pay", module: "./service/router/pay" },
  // 客户端 Lua 插件系统生效确认（PluginHeartbeat 心跳，见 lua/plugin/PluginHeartbeat.lua）
  { prefix: "/plugin", module: "./service/router/plugin-heartbeat" },
  // —— 根级挂载：home 兜底 + user/activity rootRouter + 模块自带前缀对齐 ——
  { prefix: "/", module: "./service/router/home" },
  // user 模块根级路由（gallery/cg/medal/mainlineClue/server_time 等非 /user 前缀接口）
  { prefix: "/", module: "./service/router/user", exportName: "rootRouter" },
  // activity 模块根级路由（act25side/act29side/act36side 等客户端无 /activity 前缀的接口）
  { prefix: "/", module: "./service/activity", exportName: "rootRouter" },
  // —— /activity 前缀别名：客户端将 roguelike/interlock/vecBreakV2/multiplayerV3 挂在此下 ——
  { prefix: "/activity", module: "./service/router/roguelike" },
  { prefix: "/activity", module: "./service/router/interlock" },
  { prefix: "/activity", module: "./service/router/vecbreak" },
  { prefix: "/activity", module: "./service/router/multiplayer" },
  // 客户端在根路径调用 /invite/*，multiplayer router 自带 /invite/* 路径，补根挂载
  { prefix: "/", module: "./service/router/multiplayer" },
  // campaignV2/retro 的 router 自带模块前缀，客户端调用单前缀，补根挂载对齐
  { prefix: "/", module: "./service/router/campaignV2" },
  { prefix: "/", module: "./service/router/retro" },
  // —— URL 重写别名挂载 ——
  // 客户端调用 /crisisV2/*（服务端既有路由为 /crisis/v2/*），URL 重写挂载别名
  { prefix: "/crisisV2", module: "./service/router/crisis", rewrite: crisisV2Rewrite },
  // 符文学徒试炼（/rune/battleStart|battleFinish，复用标准战斗）
  { prefix: "/rune", module: "./service/router/rune" },
  // 沙盒：客户端 /sandboxPerm/sandboxV2|V3/* 与 /sandboxPerm/changeTopic|pinTopic，URL 重写挂载别名
  {
    prefix: "/sandboxPerm",
    module: "./service/router/sandbox",
    rewrite: sandboxPermRewrite,
  },
  // 客户端在根路径调用 /vecBreakV2/getSeasonRecord（router 自带 /vecBreakV2/* 路径），补根挂载
  { prefix: "/", module: "./service/router/vecbreak" },
  // 资源版本审计（客户端 /audit/official/*，stub）
  { prefix: "/audit", module: "./service/router/audit" },
  // arkodc ODC 小游戏（act53side「直到大地变成一颗酸橙」安洁莉娜的旅行小记，客户端 /arkodc/*，根路径）
  { prefix: "/arkodc", module: "./service/router/arkodc" },
  // 全量对齐杂项（telemetry/odpy-only/api 端点等 stub），见 router/misc-alignment
  { prefix: "/", module: "./service/router/misc-alignment" },
];