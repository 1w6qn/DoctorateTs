/**
 * 抽卡路由模块
 * 
 * 处理抽卡和招募相关的 HTTP 请求，包括普通招募、高级抽卡、十连抽等功能。
 * 请求/响应类型见 @game/model/protocol/gacha（参考 CS 2.7.61 协议类）。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { GACHA_RULE_TYPE } from "../model/gacha";
import excel from "@excel/excel";
import {
  AdvancedGachaRequest,
  AdvancedGachaResponse,
  BoostNormalGachaRequest,
  BoostNormalGachaResponse,
  BuyRecruitSlotRequest,
  BuyRecruitSlotResponse,
  CancelNormalGachaRequest,
  CancelNormalGachaResponse,
  ChoosePoolUpRequest,
  ChoosePoolUpResponse,
  FinishNormalGachaRequest,
  FinishNormalGachaResponse,
  GetDetailGachaRequest,
  GetDetailGachaResponse,
  GetFreeCharRequest,
  GetFreeCharResponse,
  NormalGachaRequest,
  NormalGachaResponse,
  RefreshTagsGachaRequest,
  RefreshTagsGachaResponse,
  SyncNormalGachaRequest,
  SyncNormalGachaResponse,
  TenAdvancedGachaRequest,
  TenAdvancedGachaResponse,
} from "../model/protocol/gacha";

const router = Router();

/**
 * 同步普通招募状态
 * @route POST /gacha/syncNormalGacha
 * @returns 玩家增量数据
 */
router.post("/syncNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as SyncNormalGachaRequest;
  await player.recruit.sync();
  res.send(player.delta satisfies SyncNormalGachaResponse);
});

/**
 * 完成普通招募
 * @route POST /gacha/finishNormalGacha
 * @param req.body - 招募参数
 * @returns 招募结果和玩家增量数据
 */
router.post("/finishNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as FinishNormalGachaRequest;
  res.send({
    charGet: await player.recruit.finish(body),
    ...player.delta,
  } satisfies FinishNormalGachaResponse);
});

/**
 * 执行普通招募
 * @route POST /gacha/normalGacha
 * @param req.body - 招募参数
 * @returns 招募结果和玩家增量数据
 */
router.post("/normalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as NormalGachaRequest;
  await player.recruit.normalGacha(body);
  // 参考 CS NormalGachaResponse（无 charGet 字段）与官方抓包：仅返回增量数据
  res.send(player.delta satisfies NormalGachaResponse);
});

/**
 * 加速普通招募
 * @route POST /gacha/boostNormalGacha
 * @param req.body - 加速参数
 * @returns 加速结果和玩家增量数据
 */
router.post("/boostNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BoostNormalGachaRequest;
  await player.recruit.boost(body);
  res.send({
    result: 0,
    ...player.delta,
  } satisfies BoostNormalGachaResponse);
});

/**
 * 取消普通招募
 * @route POST /gacha/cancelNormalGacha
 * @param req.body - 取消参数
 * @returns 玩家增量数据
 */
router.post("/cancelNormalGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as CancelNormalGachaRequest;
  await player.recruit.cancel(body);
  res.send(player.delta satisfies CancelNormalGachaResponse);
});

/**
 * 购买招募槽位
 * @route POST /gacha/buyRecruitSlot
 * @param req.body - 购买参数
 * @returns 玩家增量数据
 */
router.post("/buyRecruitSlot", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BuyRecruitSlotRequest;
  await player.recruit.buyRecruitSlot(body);
  res.send(player.delta satisfies BuyRecruitSlotResponse);
});

/**
 * 刷新招募标签
 * @route POST /gacha/refreshTags
 * @param req.body - 刷新参数
 * @returns 玩家增量数据
 */
router.post("/refreshTags", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RefreshTagsGachaRequest;
  await player.recruit.refreshTags(body);
  res.send(player.delta satisfies RefreshTagsGachaResponse);
});

/**
 * 获取抽卡池详情
 * @route POST /gacha/getPoolDetail
 * @param req.body - 抽卡池参数
 * @returns 抽卡池详情和玩家增量数据
 */
router.post("/getPoolDetail", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetDetailGachaRequest;
  res.send({
    detailInfo: await player.gacha.getPoolDetail(body),
    gachaObjGroupType: 0,
    ...player.delta,
  } satisfies GetDetailGachaResponse);
});

/**
 * 执行高级抽卡（单抽）
 * @route POST /gacha/advancedGacha
 * @param req.body - 抽卡参数
 * @returns 抽卡结果和玩家增量数据
 */
router.post("/advancedGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as AdvancedGachaRequest;
  res.send({
    result: 0,
    charGet: await player.gacha.advancedGacha(body),
    ...player.delta,
  } satisfies AdvancedGachaResponse);
});

/**
 * 执行高级抽卡（十连）
 * @route POST /gacha/tenAdvancedGacha
 * @param req.body - 抽卡参数
 * @returns 十连抽卡结果列表和玩家增量数据
 */
router.post("/tenAdvancedGacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as TenAdvancedGachaRequest;
  res.send({
    result: 0,
    gachaResultList: await player.gacha.tenAdvancedGacha(body),
    ...player.delta,
  } satisfies TenAdvancedGachaResponse);
});

/**
 * 选择高级抽卡 UP 角色
 * @route POST /gacha/choosePoolUp
 * @param req.body - { poolId, chooseChar }
 * @returns result 和玩家增量数据
 */
router.post("/choosePoolUp", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { poolId, chooseChar } = req.body as ChoosePoolUpRequest;
  await player.update(async (draft) => {
    // 参考 OBS bp_gacha.gacha_choosePoolUp：gacha[gachaType][poolId].upChar = chooseChar
    const pool = excel.GachaTable.gachaPoolClient.find((p) => p.gachaPoolId === poolId);
    const gachaType = pool ? GACHA_RULE_TYPE[pool.gachaRuleType] ?? "single" : "single";
    (draft as any).gacha[gachaType][poolId].upChar = chooseChar;
  });
  res.send({ result: 0, ...player.delta } satisfies ChoosePoolUpResponse);
});

/**
 * 获取免费干员
 * @route POST /gacha/getFreeChar
 * @param req.body - 抽卡参数
 * @returns result 和玩家增量数据
 */
router.post("/getFreeChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetFreeCharRequest;
  // 参考 OBS bp_gacha.gacha_getFreeChar（空操作），仅返回 result
  res.send({ result: 0, ...player.delta } satisfies GetFreeCharResponse);
});

export default router;
