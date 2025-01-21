import { Router } from "express";
import { now } from "@utils/time";
import { readJson } from "@utils/file";
import { accountManager } from "@game/manager/AccountManger";

const router = Router();

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
router.get("/app/v1/config", async (req, res) => {
  res.send(await readJson("./data/appConfig.json"));
});
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
router.get("/user/info/v1/basic", async (req, res) => {
  const uid = await accountManager.getUidByToken(req.query!.token as string);
  const data = await accountManager.getUserConfig(uid);
  res.send({
    status: 0,
    msg: "OK",
    data: data.auth,
  });
});
router.post("/user/oauth2/v2/grant", async (req, res) => {
  const code: string = req.body!.token;
  const uid = await accountManager.getUidByToken(code);
  res.send({
    status: 0,
    msg: "OK",
    data: { code, uid },
  });
});
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
router.post("/user/online/v1/loginout", async (req, res) => {
  res.send({});
});
router.post("/u8/pay/getAllProductList", async (req, res) => {
  res.send({ productList: [] });
});
export default router;
