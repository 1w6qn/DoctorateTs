import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

router.post("/roguelike/createGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
  });
});

router.post("/roguelike/finishGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
  });
});

router.post("/roguelike/giveUpGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
  });
});

router.post("/roguelike/milestoneReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    items: [],
    result: 0,
  });
});

router.post("/roguelike/milestoneRewardTryBest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    items: [],
    result: 0,
  });
});

/**
 * 升级局外增益（解锁增益树/科技树节点）
 * 
 * 请求体：{ theme: "rogue_1", id: "outbuff_1" }（兼容 buffId 字段名）
 * 校验与扣点逻辑见 RoguelikeV2Controller.unlockBuff
 * 
 * @route POST /roguelike/upgradeOutBuff
 */
router.post("/roguelike/upgradeOutBuff", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { theme, id, buffId } = req.body ?? {};
  const buffId2 = id || buffId;
  const ret = await player.rlv2.unlockBuff(theme, buffId2);
  res.send({
    ...player.delta,
    result: ret.success ? 0 : 1,
    errorMsg: ret.reason,
  });
});

export default router;