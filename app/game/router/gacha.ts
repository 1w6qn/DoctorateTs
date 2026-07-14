/**
 * 抽卡路由模块
 * 
 * 处理抽卡和招募相关的 HTTP 请求，包括普通招募、高级抽卡、十连抽等功能。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/**
 * 同步普通招募状态
 * @route POST /gacha/syncNormalGacha
 * @returns 玩家增量数据
 */
router.post("/syncNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.sync();
  res.send(player.delta);
});

/**
 * 完成普通招募
 * @route POST /gacha/finishNormalGacha
 * @param req.body - 招募参数
 * @returns 招募结果和玩家增量数据
 */
router.post("/finishNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    charGet: await player.recruit.finish(req.body),
    ...player.delta,
  });
});

/**
 * 执行普通招募
 * @route POST /gacha/normalGacha
 * @param req.body - 招募参数
 * @returns 招募结果和玩家增量数据
 */
router.post("/normalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    charGet: await player.recruit.normalGacha(req.body),
    ...player.delta,
  });
});

/**
 * 加速普通招募
 * @route POST /gacha/boostNormalGacha
 * @param req.body - 加速参数
 * @returns 加速结果和玩家增量数据
 */
router.post("/boostNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.boost(req.body);
  res.send({
    result: 0,
    ...player.delta,
  });
});

/**
 * 取消普通招募
 * @route POST /gacha/cancleNormalGacha
 * @param req.body - 取消参数
 * @returns 玩家增量数据
 */
router.post("/cancleNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.cancel(req.body);
  res.send(player.delta);
});

/**
 * 购买招募槽位
 * @route POST /gacha/buyRecruitSlot
 * @param req.body - 购买参数
 * @returns 玩家增量数据
 */
router.post("/buyRecruitSlot", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.buyRecruitSlot(req.body);
  res.send(player.delta);
});

/**
 * 刷新招募标签
 * @route POST /gacha/refreshTags
 * @param req.body - 刷新参数
 * @returns 玩家增量数据
 */
router.post("/refreshTags", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.recruit.refreshTags(req.body);
  res.send(player.delta);
});

/**
 * 获取抽卡池详情
 * @route POST /gacha/getPoolDetail
 * @param req.body - 抽卡池参数
 * @returns 抽卡池详情和玩家增量数据
 */
router.post("/getPoolDetail", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    detailInfo: player.gacha.getPoolDetail(req.body),
    gachaObjGroupType: 0,
    ...player.delta,
  });
});

/**
 * 执行高级抽卡（单抽）
 * @route POST /gacha/advancedGacha
 * @param req.body - 抽卡参数
 * @returns 抽卡结果和玩家增量数据
 */
router.post("/advancedGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    charGet: await player.gacha.advancedGacha(req.body),
    ...player.delta,
  });
});

/**
 * 执行高级抽卡（十连）
 * @route POST /gacha/tenAdvancedGacha
 * @param req.body - 抽卡参数
 * @returns 十连抽卡结果列表和玩家增量数据
 */
router.post("/tenAdvancedGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 0,
    gachaResultList: await player.gacha.tenAdvancedGacha(req.body),
    ...player.delta,
  });
});

export default router;