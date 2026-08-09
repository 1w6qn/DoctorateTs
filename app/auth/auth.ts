/**
 * 认证模块路由
 * 
 * 提供用户登录、Token 管理、OAuth2 授权等认证相关的 API 接口。
 * 所有接口路径前缀为 `/auth`。
 */

import { Router } from "express";
import { now } from "@utils/time";
import { readJson } from "@utils/file";
import { logger } from "@utils/logger";
import { verifyPassword } from "@utils/crypt";
import { accountManager } from "@game/manager/AccountManger";
import config from "../config";

const router = Router();

/** 动态服务器地址（去硬编码——协议/客服链接跟随 config.Host:PORT，与 remote-config resolveServer 一致） */
function serverUrl(): string {
  return `${config.Host}:${config.PORT}`;
}

/**
 * 获取服务器时间
 * 
 * 返回当前服务器时间戳和是否为节假日。
 * 
 * @route GET /auth/general/v1/server_time
 * @returns 服务器时间信息
 */
router.get("/general/v1/server_time", async (req, res) => {
  res.send({
    status: 0,
    type: "A",
    msg: "OK",
    data: {
      serverTime: now(),
      isHoliday: false,
    },
  });
});

/**
 * 获取应用配置
 * 
 * 返回游戏客户端所需的配置信息。
 * 
 * @route GET /auth/app/v1/config
 * @returns 应用配置 JSON
 */
router.get("/app/v1/config", async (req, res) => {
  const cfg = (await readJson("./data/appConfig.json")) as any;
  // 用户中心指向本地 /pcSdk/userInfo（官服 userCenterUrl 跳官方页面——私服化去硬编码）
  if (cfg?.data) {
    cfg.data.userCenterUrl = `${serverUrl()}/pcSdk/userInfo`;
  }
  res.send(cfg);
});

/**
 * 通过手机号和密码获取 Token
 * 
 * 用户登录接口，验证手机号和密码后返回登录 Token。
 * 
 * @route POST /auth/user/auth/v1/token_by_phone_password
 * @param phone - 用户手机号
 * @param password - 用户密码
 * @returns 包含 Token 的登录结果
 */
router.post("/user/auth/v1/token_by_phone_password", async (req, res) => {
  const code = await accountManager.tokenByPhonePassword(
    req.body!.phone,
    req.body!.password,
  );
  res.send({
    status: 0,
    msg: "OK",
    data: {
      token: code,
    },
  });
});

/**
 * 获取用户基本信息
 * 
 * 根据 Token 获取用户的认证信息，包括手机号、邮箱等。
 * 
 * @route GET /auth/user/info/v1/basic
 * @param token - 用户登录 Token（URL 参数）
 * @returns 用户认证信息
 */
router.get("/user/info/v1/basic", async (req, res) => {
  const uid = await accountManager.getUidByToken(req.query!.token as string);
  const data = await accountManager.getUserConfig(uid);
  if (config.authMode === "real" && !uid) {
    // 真实模式：无效 token 严格报错（单例模式宽松）
    return res.status(404).send({ status: 1, msg: "用户不存在", code: "USER_NOT_FOUND" });
  }
  // 对齐官服抓包结构：identityNum/identityName/isMinor/isLatestUserAgreement（2026-08-08 user/info/v1/basic）
  res.send({
    status: 0,
    msg: "OK",
    // token 无效时宽松返回空 auth（参考 DoctoratePy：按 token 查用户，私服单机不卡流程）
    data: {
      ...(data?.auth || {}),
      identityNum: uid,
      identityName: uid,
      isMinor: false,
      isLatestUserAgreement: true,
    },
  });
});

/** 是否需要云授权（参考 DoctoratePy userV1NeedCloudAuth） */
router.post("/user/info/v1/need_cloud_auth", async (req, res) => {
  res.send({ status: 0, msg: "OK" });
});

/** 用户协议版本（客户端检查——私服固定最新版本；POST 为 U8 SDK 备选调用方式，响应同 GET；协议 URL 动态跟随服务器地址） */
function agreementVersionBody(): Record<string, unknown> {
  const server = serverUrl();
  return {
    data: {
      agreementUrl: {
        childrenPrivacy: `${server}/protocol/plain/ak/children_privacy`,
        privacy: `${server}/protocol/plain/ak/privacy`,
        service: `${server}/protocol/plain/ak/service`,
        updateOverview: `${server}/protocol/plain/ak/overview_of_changes`,
      },
      authorized: true,
      isLatestUserAgreement: true,
    },
    msg: "OK",
    status: 0,
    type: "",
  };
}
router.get("/u8/user/auth/v1/agreement_version", async (req, res) => {
  res.send(agreementVersionBody());
});
router.post("/u8/user/auth/v1/agreement_version", async (req, res) => {
  res.send(agreementVersionBody());
});

/** PC SDK 用户中心（客户端 userCenterUrl 跳转；官服抓包响应为 null） */
router.get("/pcSdk/userInfo", async (_req, res) => {
  res.send(null);
});

/** OAuth2 授权 v1（兼容旧客户端——同 v2 逻辑） */
router.post("/user/oauth2/v1/grant", async (req, res) => {
  const code: string = req.body!.token;
  const uid = await accountManager.getUidByToken(code);
  res.send({
    status: 0,
    msg: "OK",
    data: { code, uid },
  });
});

/**
 * OAuth2 授权
 * 
 * 处理 OAuth2 授权流程，根据 Token 返回授权码和用户 ID。
 * 
 * @route POST /auth/user/oauth2/v2/grant
 * @param token - 用户登录 Token
 * @returns 授权码和用户 ID
 */
router.post("/user/oauth2/v2/grant", async (req, res) => {
  const code: string = req.body!.token;
  const uid = await accountManager.getUidByToken(code);
  res.send({
    status: 0,
    msg: "OK",
    data: { code, uid },
  });
});

/**
 * U8 渠道获取 Token
 * 
 * 处理 U8 游戏渠道的登录请求，解析渠道参数并返回 Token。
 * 
 * @route POST /auth/u8/user/v1/getToken
 * @param extension - 渠道扩展参数，包含 code
 * @returns U8 渠道登录结果
 */
router.post("/u8/user/v1/getToken", async (req, res) => {
  const code: string = JSON.parse(req.body!.extension).code;
  const uid = await accountManager.getUidByToken(code);
  // 对齐官服抓包结构：captcha/error/isNew 字段（2026-08-07 auth/u8/user/v1/getToken）
  res.send({
    result: 0,
    captcha: {},
    error: "",
    uid,
    channelUid: uid,
    token: code,
    isGuest: 0,
    extension: JSON.stringify({
      isMinor: false,
      isAuthenticate: true,
    }),
    isNew: false,
  });
});

/** U8 渠道账号验证（参考 DoctoratePy userVerifyAccount——access_token 换 uid） */
router.post("/u8/user/verifyAccount", async (req, res) => {
  const token: string = JSON.parse(req.body!.extension).access_token;
  const uid = await accountManager.getUidByToken(token);
  res.send({
    result: 0,
    uid,
    error: "",
    extension: JSON.stringify({ isGuest: false }),
    channelUid: uid,
    token,
    isGuest: 0,
  });
});

/**
 * 用户登出（参考 DoctoratePy onlineV1LoginOut）
 *
 * @route POST /auth/user/online/v1/loginout
 * @returns 登出成功结果
 */
router.post("/user/online/v1/loginout", async (req, res) => {
  res.send({ result: 0 });
});

/** 在线心跳（参考 DoctoratePy onlineV1Ping——客户端定期请求，返回正常 result 避免断线） */
router.post("/user/online/v1/ping", async (req, res) => {
  res.send({
    alertTime: 600,
    interval: 120,
    message: "OK",
    result: 0,
    timeLeft: -1,
  });
});

/** 在线心跳（客户端根路径别名 /online/v1/ping，无 /user 前缀） */
router.post("/online/v1/ping", async (req, res) => {
  res.send({
    alertTime: 600,
    interval: 120,
    message: "OK",
    result: 0,
    timeLeft: -1,
  });
});

/** 用户登出（客户端根路径别名 /online/v1/loginout，无 /user 前缀） */
router.post("/online/v1/loginout", async (req, res) => {
  res.send({ result: 0 });
});

/**
 * 手机号密码登录（参考 DoctoratePy userLogin）
 * result: 0 成功 / 1 用户名或密码错误 / 4 该用户尚不存在
 */
router.post("/user/auth/v1/login", async (req, res) => {
  const { account, password } = req.body ?? {};
  const found = Object.entries(accountManager.configs).find(
    ([, c]) => c.auth?.phone == account,
  );
  if (!found) {
    return res.send({ result: 4 });
  }
  const [uid, conf] = found;
  // 密码校验（支持 sha256 哈希存储 + 旧明文兼容）
  if (!verifyPassword(conf.password, password)) {
    return res.send({ result: 1 });
  }
  res.send({
    result: 0,
    uid,
    token: conf.secret || uid,
    isAuthenticate: true,
    isMinor: false,
    needAuthenticate: false,
    isLatestUserAgreement: true,
  });
});

/**
 * 手机号注册（参考 DoctoratePy userRegister）
 * result: 0 成功 / 5 <errMsg> 密码格式错误或账号已存在
 */
router.post("/user/auth/v1/register", async (req, res) => {
  const { account, password } = req.body ?? {};
  if (
    !/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*]{8,16}$/.test(password || "")
  ) {
    return res.send({
      result: 5,
      errMsg:
        "<color=red>密码格式错误</color>\n密码应为8-16位大小写字母和数字的组合\n其中可以选择包含一些常用字符",
    });
  }
  const exists = Object.values(accountManager.configs).some(
    (c) => c.auth?.phone == account,
  );
  if (exists) {
    return res.send({ result: 5, errMsg: "该账户已存在，请检查注册信息" });
  }
  const uid = await accountManager.registerUser(account, password);
  const token = accountManager.configs[uid]?.secret || uid;
  res.send({
    result: 0,
    uid,
    token,
    isAuthenticate: false,
    isMinor: false,
    needAuthenticate: true,
    isLatestUserAgreement: true,
  });
});

/** 短信验证码登录（参考 DoctoratePy userLoginBySmsCode——私服简化：账号存在即成功） */
router.post("/user/auth/v1/login_by_smscode", async (req, res) => {
  const { account } = req.body ?? {};
  const found = Object.entries(accountManager.configs).find(
    ([, c]) => c.auth?.phone == account,
  );
  if (!found) {
    return res.send({ result: 1 });
  }
  const [uid, conf] = found;
  res.send({
    result: 0,
    uid,
    token: conf.secret || uid,
    isAuthenticate: true,
    isMinor: false,
    needAuthenticate: false,
    isLatestUserAgreement: true,
  });
});

/** 发送短信验证码（参考 DoctoratePy userSendSmsCode——私服直接成功） */
router.post("/user/auth/v1/send_sms_code", async (req, res) => {
  res.send({ result: 0, msg: "OK" });
});

/** 发送手机验证码（参考 DoctoratePy userInfoV1SendPhoneCode） */
router.post("/user/info/v1/send_phone_code", async (req, res) => {
  res.send({ status: 0, msg: "OK" });
});

/** 实名认证（参考 DoctoratePy userAuthenticateUserIdentity——私服直接通过） */
router.post("/user/auth/v1/authenticate_user_identity", async (req, res) => {
  res.send({ result: 0, message: "OK", isMinor: false });
});

/** 同意用户协议（参考 DoctoratePy userUpdateAgreement） */
router.post("/user/auth/v1/update_agreement", async (req, res) => {
  res.send({ result: 0, message: "OK", isMinor: false });
});

/** 身份证校验（参考 DoctoratePy userCheckIdCard——私服直接通过） */
router.post("/user/auth/v1/check_id_card", async (req, res) => {
  res.send({ result: 0, message: "OK", isMinor: false });
});

/** 修改密码（参考 DoctoratePy userChangePassword——私服简化成功） */
router.post("/user/auth/v1/change_password", async (req, res) => {
  res.send({ result: 0 });
});

/** 换绑手机检查（参考 DoctoratePy userChangePhoneCheck） */
router.post("/user/auth/v1/change_phone_check", async (req, res) => {
  res.send({ result: 0 });
});

/** 换绑手机（参考 DoctoratePy userChangePhone——私服简化成功） */
router.post("/user/auth/v1/change_phone", async (req, res) => {
  res.send({ result: 0 });
});

/** 游客登录（参考 DoctoratePy userV1GuestLogin——私服返回未激活） */
router.post("/user/auth/v1/guest_login", async (req, res) => {
  res.send({ result: 3 });
});

/** 注销授权（参考 DoctoratePy userOauth2V1UnbindGrant——私服直接成功） */
router.post("/user/oauth2/v1/unbind_grant", async (req, res) => {
  res.send({ status: 0, msg: "OK" });
});

/** 支付订单状态（参考 DoctoratePy payConfirmOrderState——私服无支付返回未完成） */
router.post("/u8/pay/confirmOrderState", async (req, res) => {
  res.send({ payState: 0 });
});

/** Token 换取用户状态（参考 DoctoratePy userAuth——客户端登录后校验） */
router.post("/user/auth", async (req, res) => {
  const token = String(req.body?.token ?? "");
  const uid = await accountManager.getUidByToken(token);
  if (!uid) {
    return res.status(404).send({ status: 1, msg: "用户不存在" });
  }
  res.send({
    uid,
    isMinor: false,
    isAuthenticate: true,
    isGuest: false,
    needAuthenticate: false,
    isLatestUserAgreement: true,
  });
});

/**
 * 获取 U8 渠道商品列表
 * 
 * 返回 U8 渠道的付费商品列表（从本地 AllProductList.json 读取）。
 * 
 * @route POST /auth/u8/pay/getAllProductList
 * @returns 商品列表
 */
router.post("/u8/pay/getAllProductList", async (req, res) => {
  res.send(await readJson("./data/shop/AllProductList.json"));
});

/**
 * 统一异常处理（API 兜底）
 * 异步 handler 抛错（Express 5 自动捕获）→ 返回 JSON 错误而非裸 500
 */
router.use((err: any, _req: any, res: any, _next: any) => {
  logger.error("auth", (err as Error)?.message || String(err));
  res.status(500).send({
    status: 1,
    msg: "服务器内部错误",
    code: "INTERNAL_ERROR",
  });
});

export default router;