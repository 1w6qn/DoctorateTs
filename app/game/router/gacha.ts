import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/syncNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.sync();
  res.send(player.delta);
});
router.post("/finishNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    charGet: await player.recruit.finish(req.body),
    ...player.delta,
  });
});
router.post("/normalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    charGet: await player.recruit.normalGacha(req.body),
    ...player.delta,
  });
});

router.post("/boostNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.boost(req.body);
  res.send({
    result: 0,
    ...player.delta,
  });
});
router.post("/cancleNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.cancel(req.body);
  res.send(player.delta);
});
router.post("/buyRecruitSlot", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.buyRecruitSlot(req.body);
  res.send(player.delta);
});
router.post("/refreshTags", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.refreshTags(req.body);
  res.send(player.delta);
});
router.post("/getPoolDetail", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    detailInfo: player.gacha.getPoolDetail(req.body),
    gachaObjGroupType: 0,
    ...player.delta,
  });
});
router.post("/advancedGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    charGet: await player.gacha.advancedGacha(req.body),
    ...player.delta,
  });
});
router.post("/tenAdvancedGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    gachaResultList: await player.gacha.tenAdvancedGacha(req.body),
    ...player.delta,
  });
});
export default router;
