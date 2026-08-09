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
  // 抓包专用官服转发模式：命令行 --capture 或 data/config.json 中 capture.enabled: true
  const capture = args.includes("--capture") || config.capture?.enabled === true;
  // capture 模式的核心用途就是抓包：强制开启流量落盘 tmp/（目录格式与 test.ts 抓包一致）
  if (capture) {
    config.debug = { ...config.debug, recordTraffic: true };
  }
  
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
  // capture 模式：捕获非 JSON 原始请求体（multipart 等），转发时原样透传字节——
  // bodyParser.json 不解析 multipart，透传 req.body 会变成 {} 导致官服 400 "Invalid multipart payload format"
  // （实测 POST /activity/arkhub/savePixelArt multipart 2106B → 转发 {} → 400）。JSON 已由 json() 消费，跳过。
  if (capture) {
    app.use((req, _res, next) => {
      if (req.is("application/json")) return next();
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        (req as unknown as { rawBody: Buffer }).rawBody = Buffer.concat(chunks);
        next();
      });
    });
  }
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
  // 全量对齐（参考 ODPY 旧版路径）：/user/register 等别名到既有 /user/auth/v1/* 实现
  app.use("/", (req, _res, next) => {
    const OLD_AUTH_ALIASES: Record<string, string> = {
      "/user/register": "/user/auth/v1/register",
      "/user/login": "/user/auth/v1/login",
      "/user/sendSmsCode": "/user/auth/v1/send_sms_code",
      "/user/loginBySmsCode": "/user/auth/v1/login_by_smscode",
      "/user/v1/guestLogin": "/user/auth/v1/guest_login",
      "/user/changePassword": "/user/auth/v1/change_password",
      "/user/changePhone": "/user/auth/v1/change_phone",
      "/user/changePhoneCheck": "/user/auth/v1/change_phone_check",
      "/user/checkIdCard": "/user/auth/v1/check_id_card",
      "/user/authenticateUserIdentity": "/user/auth/v1/authenticate_user_identity",
      "/user/updateAgreement": "/user/auth/v1/update_agreement",
    };
    const path = req.path;
    if (OLD_AUTH_ALIASES[path]) {
      req.url = OLD_AUTH_ALIASES[path];
    }
    next();
  });
  // 抓包专用官服转发模式：as/gs 流量转发官服（config/launcher 保持本地——客户端才能被引导连到本代理）
  if (capture) {
    const { createOfficialForwarder } = await import("./app/proxy/official-forward");
    // arkhub 网关特殊适配：enterHall 返回官服网关地址，客户端随后 WebSocket 连网关——本代理
    // 监听 gatewayPort（缺省 30000）透传官服网关并记录流量，enterHall 响应 endpoint 改写为本代理
    const { startArkhubGatewayProxy } = await import("./app/proxy/arkhub-gateway");
    const gatewayPort = config.capture?.gatewayPort ?? 30000;
    const gateway = await startArkhubGatewayProxy({ port: gatewayPort });
    app.use(
      createOfficialForwarder({
        arkhubGateway: gateway
          ? { endpoint: String(config.Host).replace(/^https?:\/\//, ""), port: gatewayPort }
          : null,
      }),
    );
    logger.info("index", "抓包官服转发模式已开启：as/gs 流量将转发到官服并记录 tmp/");
  }
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