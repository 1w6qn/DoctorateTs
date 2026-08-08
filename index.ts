/**
 * DoctorateTs 应用入口文件
 * 
 * 启动 Express 服务器，初始化所有模块，注册路由和中间件。
 */

import express from "express";
import config from "./app/config";
import { logger } from "./app/utils/logger";
import { createTrafficRecorder } from "./app/utils/traffic-recorder";
import excel from "@excel/excel";
import { enablePatches } from "immer";
import morgan from "morgan";
import prod from "./app/config/prod";
import { remoteConfigRouter } from "./app/config/remote-config";
import { createHostRouter } from "./app/config/host-router";
import auth from "./app/auth/auth";
import asset from "./app/asset";
import game, { setup } from "./app/game/app";
import bodyParser from "body-parser";
import { accountManager } from "./app/game/manager/AccountManger";

/**
 * 应用启动入口函数
 * 
 * 执行以下步骤：
 * 1. 更新游戏数据和生成类型（可选）
 * 2. 启用 Immer 补丁功能
 * 3. 初始化 Excel 数据表
 * 4. 创建 Express 应用
 * 5. 注册中间件（JSON解析、日志记录）
 * 6. 注册路由（配置、认证、游戏、资源）
 * 7. 启动服务器监听
 */
(async () => {
  const args = process.argv.slice(2);
  const skipUpdate = args.includes("--skip-update") || args.includes("-s");
  // 完全离线模式：命令行参数 --offline/-o 或 data/config.json 中 offline: true
  const offline = args.includes("--offline") || args.includes("-o") || config.offline === true;
  
  if (offline) {
    logger.info("index", "完全离线模式：跳过所有网络操作，使用本地缓存数据");
    const updateModule = await import("./scripts/update-data");
    const code = await updateModule.main(false, true);
    if (code !== 0) {
      logger.error("index", "本地数据不完整，无法离线启动。请先联网执行 `npm run update` 初始化数据，");
      logger.error("index", "或去掉 --offline 参数以在线模式启动（会自动回退到本地缓存）。");
      process.exit(1);
    }
    logger.info("index", "本地数据校验通过，继续启动...");
  } else if (!skipUpdate) {
    logger.info("index", "开始更新游戏数据...");
    try {
      const updateModule = await import("./scripts/update-data");
      await updateModule.main(false);
      logger.info("index", "游戏数据更新完成");
    } catch (error) {
      logger.error("index", "游戏数据更新失败，使用本地缓存数据:", (error as Error).message);
    }
  } else {
    logger.info("index", "跳过游戏数据更新，使用本地缓存数据");
  }
  
  enablePatches();
  await excel.init();
  const app = express();
  app.use(bodyParser.json());
  app.use(morgan("short"));
  // 调试记录：debug.recordTraffic=true 时保存 request/response 到 tmp/（对齐 test.ts 抓包目录）
  app.use(createTrafficRecorder(config));
  // 子域名分发：*.hypergryph.com 请求按官服子域名映射到私服路由
  app.use(createHostRouter());
  app.use("/config/prod", prod);
  app.use("/api/remote_config", remoteConfigRouter);
  app.use("/api/gate", (await import("./app/config/gate")).default);
  // 启动器版本检查（/api/game/get_latest——action:0 空包，客户端无需更新直接启动）
  app.use("/api/game", (await import("./app/config/launcher")).default);
  // auth 挂根路径：as 域接口（/user/*、/u8/*、/app/* 等）直接命中（用户最终决定，勿改回 /auth）
  app.use("/", auth);
  await setup(game);
  app.use("/", game);
  app.use("/assetbundle", asset);

  // 单例模式：确保固定账号存在（如配置的 singleUid 不存在则自动创建）
  if (config.authMode === "single") {
    const singleUid = config.singleUid || "1";
    try {
      await accountManager.ensureSingleUser(singleUid);
    } catch (error) {
      logger.error("index", "单例账号创建失败:", (error as Error).message);
    }
  }

  // 单例模式：自动生成满配账号（全干员/全物品——随版本刷新，版本变化重新生成）
  if (config.authMode === "single" && config.singleAutoMaxAccount !== false) {
    const singleUid = config.singleUid || "1";
    try {
      const player = await accountManager.getPlayerData(singleUid);
      const marker = (player as any)?._playerdata?.status?.maxAccountResVersion;
      if (player && marker !== config.version.resVersion) {
        const { generateMaxedAccount } = await import("./scripts/generate-max-account");
        await generateMaxedAccount(player);
        await accountManager.flushSave(singleUid);
        logger.info("index", `单例满配账号已生成（${singleUid}，版本 ${config.version.resVersion}）`);
      }
    } catch (error) {
      logger.error("index", "满配账号生成失败:", (error as Error).message);
    }
  }

  app.use("/admin", (await import("./app/admin/admin-router")).default);
  app.listen(config.PORT, () => {
    logger.info("index", `--------------DoctorateTs--------------`);
    logger.info("index", `running at http://localhost:${config.PORT}`);
  });
})();