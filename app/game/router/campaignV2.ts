/**
 * 主线战役V2路由模块
 *
 * 处理主线战役V2（campaignV2）相关的 HTTP 请求，包括战斗开始、战斗结束、扫荡、
 * 突破奖励和额外任务奖励等接口。
 *
 * 业务逻辑委托给 Manager 层（BattleManager 等）处理，路由层仅负责协议适配与响应封装。
 *
 * 参考实现：reference/opendoctoratepy-ex-public/server/campaignV2.py
 */

import { Router } from "express";
import { getPlayer, getPlayerOptional } from "../request-context";
import { ItemBundle } from "@excel/character_table";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  CampaignConfirmBreakRewardRequest,
  CampaignConfirmBreakRewardResponse,
  CampaignFinishBattleRequest,
  CampaignFinishBattleResponse,
  CampaignGetCommonMissionRewardRequest,
  CampaignGetCommonMissionRewardResponse,
  CampaignStartBattleRequest,
  CampaignStartBattleResponse,
  CampaignSweepRequest,
  CampaignSweepResponse,
} from "../model/protocol/campaignV2";
import { validateBody } from "../model/protocol/validate-body";
import {
  campaignV2BattleFinishSchema,
  campaignV2BattleStartSchema,
  campaignV2BattleSweepSchema,
  campaignV2GetBreakRewardSchema,
  campaignV2GetExMissionRewardSchema,
} from "../model/protocol/campaignV2.schema";

const router = Router();

/**
 * 主线战役V2战斗开始
 *
 * 委托 BattleManager.start 处理战斗初始化逻辑（关卡状态、体力消耗、AP保护等），
 * 并合并 playerDataDelta 返回给客户端。
 *
 * @route POST /campaignV2/battleStart
 * @param req.body - CommonStartBattleRequest 结构，包含 stageId、squad 等字段
 * @returns battleId、战斗结果及玩家增量数据
 */
router.post("/campaignV2/battleStart", validateBody(campaignV2BattleStartSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as CampaignStartBattleRequest;
  const battleResult = await player.battle.start(body);

  res.send({
    ...battleResult,
    ...player.delta,
  } satisfies CampaignStartBattleResponse);
});

/**
 * 主线战役V2战斗结束
 *
 * 委托 BattleManager.finish 处理战斗结算逻辑（关卡解锁、奖励掉落、经验/金币结算等），
 * 并合并 playerDataDelta 返回给客户端。
 *
 * @route POST /campaignV2/battleFinish
 * @param req.body - 包含 data（加密战斗数据）和 battleData 字段
 * @returns 战斗结算结果及玩家增量数据
 */
router.post("/campaignV2/battleFinish", validateBody(campaignV2BattleFinishSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as CampaignFinishBattleRequest;
  // 缺参校验：data/battleData 缺失时返回业务错误，避免 undefined 传入 battle.finish 抛 500
  if (body.data == null || body.battleData == null) {
    res.send({ result: 1, ...player.delta } satisfies CampaignFinishBattleResponse);
    return;
  }
  const finishResult = await player.battle.finish(body);

  res.send({
    ...finishResult,
    ...player.delta,
  } satisfies CampaignFinishBattleResponse);
});

/**
 * 主线战役V2扫荡
 *
 * 简化实现：返回固定的扫荡奖励结构。
 * 由于 Manager 层未提供 sweep 方法（且参考实现亦为静态返回），
 * 此处在路由层直接构造符合协议的响应，diamondMaterialRewards 返回固定钻石碎屑。
 *
 * @route POST /campaignV2/battleSweep
 * @returns 扫荡结果（奖励列表、解锁关卡、玩家增量数据等）
 */
router.post("/campaignV2/battleSweep", validateBody(campaignV2BattleSweepSchema), async (req, res) => {
  const player = getPlayer();
  req.body as CampaignSweepRequest;

  // 修复：展示的奖励入账（原实现只在响应里给 1 合成玉，从不 items:get → 不到账）
  const diamondRewards: ItemBundle[] = [
    { type: "DIAMOND_SHD", id: "4003", count: 1 },
  ];
  await player._trigger.emit("items:get", [diamondRewards]);

  res.send({
    ...player.delta,
    result: 0,
    apFailReturn: 1,
    rewards: [],
    unlockStages: [],
    unusualRewards: [],
    additionalRewards: [],
    furnitureRewards: [],
    diamondMaterialRewards: diamondRewards,
    currentFeeBefore: 0,
    currentFeeAfter: 1,
  } satisfies CampaignSweepResponse);
});

/**
 * 获取主线战役V2突破奖励
 *
 * 简化实现：参考 Python 实现返回 202 状态码（已接受但未处理）。
 * 突破奖励的完整逻辑涉及 mission 系统的 CompleteBreakReward 事件，
 * 当前版本暂不实现，等待后续迭代补全。
 *
 * @route POST /campaignV2/getBreakReward
 * @returns HTTP 202 状态码
 */
router.post("/campaignV2/getBreakReward", validateBody(campaignV2GetBreakRewardSchema), async (req, res) => {
  const player = getPlayer();
  req.body as CampaignConfirmBreakRewardRequest;
  // 修复：sendStatus(202) 返回文本 "Accepted"，客户端按 JSON 解析失败（同 gallery
  // 修复模式）→ 返回 JSON 增量
  res.send(player.delta satisfies CampaignConfirmBreakRewardResponse);
});

/**
 * 获取主线战役V2额外任务奖励
 *
 * 简化实现：参考 Python 实现返回 202 状态码（已接受但未处理）。
 * 额外任务奖励的完整逻辑涉及 mission 系统的事件触发与奖励发放，
 * 当前版本暂不实现，等待后续迭代补全。
 *
 * @route POST /campaignV2/getExMissionReward
 * @returns HTTP 202 状态码
 */
router.post("/campaignV2/getExMissionReward", validateBody(campaignV2GetExMissionRewardSchema), async (req, res) => {
  const player = getPlayer();
  req.body as CampaignGetCommonMissionRewardRequest;
  // 修复：同上——JSON 响应避免客户端解析失败
  res.send(player.delta satisfies CampaignGetCommonMissionRewardResponse);
});

export default router;
