/**
 * DoctorateTs 应用入口文件
 * 
 * 启动 Express 服务器，初始化所有模块，注册路由和中间件。
 */

import express from "express";
import config from "./app/config";
import excel from "@excel/excel";
import { enablePatches } from "immer";
import morgan from "morgan";
import prod from "./app/config/prod";
import auth from "./app/auth/auth";
import asset from "./app/asset";
import game, { setup } from "./app/game/app";
import bodyParser from "body-parser";

/**
 * 应用启动入口函数
 * 
 * 执行以下步骤：
 * 1. 启用 Immer 补丁功能
 * 2. 初始化 Excel 数据表
 * 3. 创建 Express 应用
 * 4. 注册中间件（JSON解析、日志记录）
 * 5. 注册路由（配置、认证、游戏、资源）
 * 6. 启动服务器监听
 */
(async () => {
  console.time();
  enablePatches();
  await excel.init();
  const app = express();
  app.use(bodyParser.json());
  app.use(morgan("short"));
  app.use("/config/prod", prod);
  app.use("/auth", auth);
  await setup(game);
  app.use("/", game);
  app.use("/assetbundle", asset);
  app.listen(config.PORT, async () => {
    console.timeEnd();
    console.log(`--------------DoctorateTs--------------`);
    console.log(`running at http://localhost:${config.PORT}`);
  });
})();