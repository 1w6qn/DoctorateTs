import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { accountManager } from "../manager/AccountManger";
import { now } from "@utils/time";

const router = Router();

/**
 * 用户登录（参考 DoctoratePy accountLogin）
 * 客户端流程：token_by_phone_password / oauth2 grant 拿到 token → /account/login 换游戏凭证 secret
 * token 语义：real 模式为账号 secret（或 uid 兼容），single 模式任意 token 收敛到 singleUid
 * 版本校验 YAGNI：clientVersion/networkVersion 读取但不拦截（私服客户端版本可能滞后，避免卡登录）
 */
router.post("/login", async (req, res) => {
  const token = String(req.body?.token ?? "");
  const uid = await accountManager.getUidByToken(token);
  if (!uid) {
    // 参考 DoctoratePy：result 3 = 记忆已经模糊，请重新输入登录信息
    return res.send({ result: 3 });
  }
  const conf = await accountManager.getUserConfig(uid);
  res.send({
    result: 0,
    uid,
    secret: conf?.secret || uid,
    serviceLicenseVersion: 0,
    majorVersion: "446",
  });
});

router.post("/syncData", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData");
  if (!player) {
    return res.status(401).send({ status: 401, msg: "未登录（缺少 secret）" });
  }

  await player.update(async (draft) => {
    draft.pushFlags.status = now();
  });
  res.send({
    result: 0,
    ts: now(),
    user: player,
    ...player.delta,
  });
});

router.post("/syncStatus", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData");
  if (!player) {
    return res.status(401).send({ status: 401, msg: "未登录（缺少 secret）" });
  }
  await player._trigger.emit("status:refresh:time", []);
  res.send({
    ts: now(),
    result: {},
    ...player.delta,
  });
});

router.post("/syncPushMessage", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData");
  if (!player) {
    return res.status(401).send({ status: 401, msg: "未登录（缺少 secret）" });
  }
  res.send(player.delta);
});

export default router;
