import { Router } from "express";
import { now } from "@utils/time";
import { readJson } from "@utils/file";

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
router.get("/user/auth/v1/token_by_phone_password", (req, res) => {
  res.send({
    status: 0,
    msg: "OK",
    data: {
      token: "doctorate",
    },
  });
});
router.get("/user/info/v1/basic", async (req, res) => {
  res.send({
    status: 0,
    msg: "OK",
    data: {
      hgId: "1",
      phone: "doctorate",
      email: "doctorate",
      identityNum: "doctorate",
      identityName: "doctorate",
      isMinor: false,
      isLatestUserAgreement: true,
    },
  });
});
router.post("/user/oauth2/v2/grant", async (req, res) => {
  res.send({
    status: 0,
    msg: "OK",
    data: {
      code: "doctorate",
      uid: "1",
    },
  });
});
router.post("/u8/user/v1/getToken", async (req, res) => {
  res.send({
    channelUid: "1",
    extension: JSON.stringify({
      isMinor: false,
      isAuthenticate: true,
    }),
    isGuest: 0,
    result: 0,
    token: "1",
    uid: "1",
  });
});
router.post("/user/online/v1/loginout", async (req, res) => {
  res.send({});
});
router.post("/u8/pay/getAllProductList", async (req, res) => {
  res.send({ productList: [] });
});
export default router;
