/**
 * 全量对齐杂项路由（参考 ODPY，用户确认「参考项目全量对齐」）
 *
 * 覆盖 ODPY 清单中此前标注「设计跳过」的端点：遥测/埋点、支付变体、
 * ODPY 独有 api 端点、admin 别名、recalRune 根路径、yostar 等。
 * 多为 stub（返回空/固定响应），保证参考项目路径全部可达。
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/** 遥测/埋点/外部服务端点（客户端不依赖响应，返回空） */
for (const telemetryPath of [
  "/analytics/collect",
  "/beat",
  "/event",
  "/gameBulletin",
  "/loggw/logUpload.do",
  "/mgw.htm",
  "/deviceprofile/v4",
  "/iedsafe/Client/android/19791/config2.xml",
  "/survey/startSurvey",
  "/general/v1/send_phone_code",
]) {
  router.all(telemetryPath, async (_req, res) => {
    res.send({});
  });
}

/** yostar 登录链路（P4 原本跳过，全量对齐补 stub） */
router.post("/account/yostar_auth_request", async (_req, res) => {
  res.send({ result: 0, uid: "", token: "" });
});
router.post("/account/yostar_auth_submit", async (_req, res) => {
  res.send({ result: 0, uid: "", token: "" });
});
router.post("/user/yostar_createlogin", async (_req, res) => {
  res.send({ result: 0, uid: "", token: "" });
});

/** ODPY 独有 app/api 端点（stub） */
router.get("/app/getCode", async (_req, res) => {
  res.send({ code: "0" });
});
router.get("/app/getSettings", async (_req, res) => {
  res.send({});
});
router.get("/api/gacha/cate", async (_req, res) => {
  res.send({ cateList: [] });
});
router.get("/api/gacha/history", async (_req, res) => {
  res.send({ history: [] });
});
router.get("/api/autoChess/act1autochess/playerSummary", async (_req, res) => {
  res.send({});
});
router.get("/api/autoChess/act2autochess/playerSummary", async (_req, res) => {
  res.send({});
});
router.get("/api/is/rogue_1/bulletinVersion", async (_req, res) => {
  res.send({ version: 0 });
});
router.post("/api/is/rogue_1/bulletinVersion", async (_req, res) => {
  res.send({ version: 0 });
});

/** 用户协议（ODPY 独有，stub） */
router.post("/user/agreement", async (_req, res) => {
  res.send({ result: 0 });
});
router.post("/user/auth/v2/token_by_phone_code", async (_req, res) => {
  res.send({ result: 3, msg: "token_by_phone_code 已由 /user/auth/v1 替代" });
});

/** 支付变体（Appstore/支付宝/微信/订单查询——CN 2.7.61 客户端不调用，全量对齐补 stub） */
for (const payVariantPath of [
  "/pay/confirmOrderAppstore",
  "/pay/confirmOrderAppstoreNew",
  "/pay/createOrderAppstore",
  "/pay/order/v1/check",
  "/pay/order/v1/state",
  "/pay/v1/query_show_app_product",
  "/user/pay/order/v1/create/app_product/alipay",
  "/user/pay/order/v1/create/app_product/wechat",
  "/user/pay/order/v2/create/app_product",
  "/user/pay/v1/query_payment_config",
]) {
  router.post(payVariantPath, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData");
    res.send({
      result: 0,
      ...(player ? player.delta : { playerDataDelta: { modified: {}, deleted: {} } }),
    });
  });
}

/** recalRune 根路径别名（服务端既有 /crisis/recalRune/*） */
router.post("/recalRune/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    apFailReturn: 0,
    isApProtect: 0,
    inApProtectPeriod: false,
    notifyPowerScoreNotEnoughIfFailed: false,
    ...player.delta,
  });
});
router.post("/recalRune/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    ...player.delta,
  });
});

/** admin 别名（ODPY 管理端路径；本项目管理端为自有实现，此处仅保证路径可达） */
for (const adminAliasPath of [
  "/admin/cheat",
  "/admin/getVersion",
  "/admin/login/by_phone_password",
  "/admin/saveUserData",
  "/admin/verify",
]) {
  router.all(adminAliasPath, async (_req, res) => {
    res.send({ status: 0, result: 0 });
  });
}


/** 官方资源文件（/official/Android/assets/<hash>/<file>；私服无资源返回空） */
router.get("/official/Android/assets/:assetsHash/:fileName", async (_req, res) => {
  res.send({});
});


/** 根路径（ODPY 管理索引对应；返回空 JSON） */
router.all("/", async (_req, res) => {
  res.send({ result: 0 });
});


/** DoctoratePy 支付变体（支付宝/微信/成功回调——CN 2.7.61 客户端不调用，全量对齐补 stub） */
router.post("/pay/createOrderAlipay", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData");
  res.send({ result: 0, ...(player ? player.delta : { playerDataDelta: { modified: {}, deleted: {} } }) });
});
router.post("/pay/createOrderWechat", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData");
  res.send({ result: 0, ...(player ? player.delta : { playerDataDelta: { modified: {}, deleted: {} } }) });
});
router.post("/pay/confirmOrderAlipay", async (_req, res) => {
  res.send({ status: 0 });
});
router.post("/pay/confirmOrderWechat", async (_req, res) => {
  res.send({ status: 0 });
});
router.post("/pay/success", async (_req, res) => {
  res.send({ result: 0 });
});

/** DoctoratePy 管理登录（stub） */
router.post("/login", async (_req, res) => {
  res.send({ result: 0, msg: "OK" });
});


/** 协议确认（EN 客户端路径变体） */
router.post("/user/agreement/confirm", async (_req, res) => {
  res.send({ result: 0 });
});

/** EN/YoStar 客户端端点（CN 2.7.61 不调用，全量对齐补 stub） */
for (const enPath of [
  "/common/client-code",
  "/common/client-info",
  "/common/client-log",
  "/common/config",
  "/common/version",
  "/yostar/get-auth",
  "/user/detail",
  "/user/quick-login",
]) {
  router.all(enPath, async (_req, res) => {
    res.send({});
  });
}

export default router;
