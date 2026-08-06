/**
 * 认证模块路由
 * 
 * 提供用户登录、Token 管理、OAuth2 授权等认证相关的 API 接口。
 * 所有接口路径前缀为 `/auth`。
 */

import { Router } from "express";
import { now } from "@utils/time";
import { readJson } from "@utils/file";
import { accountManager } from "@game/manager/AccountManger";

const router = Router();

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
  res.send(await readJson("./data/appConfig.json"));
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
  res.send({
    status: 0,
    msg: "OK",
    // token 无效时宽松返回空 auth（参考 DoctoratePy：按 token 查用户，私服单机不卡流程）
    data: data?.auth || {},
  });
});

/** 是否需要云授权（参考 DoctoratePy userV1NeedCloudAuth） */
router.post("/user/info/v1/need_cloud_auth", async (req, res) => {
  res.send({ status: 0, msg: "OK" });
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
  res.send({
    channelUid: "1",
    extension: JSON.stringify({
      isMinor: false,
      isAuthenticate: true,
    }),
    isGuest: 0,
    result: 0,
    token: code,
    uid,
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
 * 用户登出
 * 
 * 处理用户登出请求。
 * 
 * @route POST /auth/user/online/v1/loginout
 * @returns 空对象
 */
router.post("/user/online/v1/loginout", async (req, res) => {
  res.send({});
});

/**
 * 获取 U8 渠道商品列表
 * 
 * 返回 U8 渠道的付费商品列表（当前为空）。
 * 
 * @route POST /auth/u8/pay/getAllProductList
 * @returns 商品列表
 */
router.post("/u8/pay/getAllProductList", async (req, res) => {
  res.send({ productList: [] });
});

export default router;