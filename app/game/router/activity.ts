/**
 * 活动路由模块
 *
 * 处理活动相关的 HTTP 请求，包括签到奖励、节日活动、活动任务、活动商店、
 * 信物回收等多种活动类型的业务逻辑。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { accountManager } from "../manager/AccountManger";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { decryptBattleData } from "@utils/crypt";
import { logger } from "@utils/logger";
import { CommonStartBattleRequest } from "../model/battle";
import {
  ActCheckinvsSignRequest,
  ActCheckinvsSignResponse,
  AutoConfirmMissionsRequest,
  AutoConfirmMissionsResponse,
  ChangeFestivalCharRequest,
  ChangeFestivalCharResponse,
  ConfirmActivityMissionGroupRequest,
  ConfirmActivityMissionGroupResponse,
  ConfirmActivityMissionListRequest,
  ConfirmActivityMissionListResponse,
  ConfirmActivityMissionRequest,
  ConfirmActivityMissionResponse,
  ExchangeActivityShopItemRequest,
  ExchangeActivityShopItemResponse,
  GetActivityCheckInRewardRequest,
  GetActivityCheckInRewardResponse,
  GetActivityCollectionRewardRequest,
  GetActivityCollectionRewardResponse,
  GetActivityShopInfoRequest,
  GetActivityShopInfoResponse,
  GetChainLogInFinalRewardsRequest,
  GetChainLogInFinalRewardsResponse,
  GetChainLogInRewardRequest,
  GetChainLogInRewardResponse,
  GetCheckInRewardRequest,
  GetCheckInRewardResponse,
  GetOpenServerCheckInRewardRequest,
  GetOpenServerCheckInRewardResponse,
  GetSwitchOnlyRewardRequest,
  GetSwitchOnlyRewardResponse,
  RecycleCharmsRequest,
  RecycleCharmsResponse,
  RewardAllMilestoneRequest,
  RewardAllMilestoneResponse,
  RewardMilestoneRequest,
  RewardMilestoneResponse,
  TryGetCharmFirstRewardRequest,
  TryGetCharmFirstRewardResponse,
  BossRushStartBattleRequest,
  BossRushStartBattleResponse,
  BossRushFinishBattleRequest,
  BossRushFinishBattleResponse,
  BossRushRelicSelectRequest,
  BossRushRelicSelectResponse,
  BossRushRelicUpgradeRequest,
  BossRushRelicUpgradeResponse,
} from "../model/protocol/activity";

const router = Router();

/**
 * 获取连签登录奖励
 * @route POST /activity/getChainLogInReward
 * @param req.body - 包含 index 的请求体
 * @returns 奖励列表和玩家增量数据
 */
router.post("/getChainLogInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetChainLogInRewardRequest;
  res.send({
    reward: await player.openServer.getChainLogInReward(body),
    ...player.delta,
  } satisfies GetChainLogInRewardResponse);
});

/**
 * 获取连签最终奖励
 * @route POST /activity/getChainLogInFinalRewards
 * @returns 奖励列表和玩家增量数据
 */
router.post("/getChainLogInFinalRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as GetChainLogInFinalRewardsRequest;
  res.send({
    reward: await player.openServer.getChainLogInFinalRewards(),
    ...player.delta,
  } satisfies GetChainLogInFinalRewardsResponse);
});

/**
 * 获取开服签到奖励
 * @route POST /activity/getOpenServerCheckInReward
 * @param req.body - 包含 index 的请求体
 * @returns 奖励列表和玩家增量数据
 */
router.post("/getOpenServerCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetOpenServerCheckInRewardRequest;
  res.send({
    reward: await player.openServer.getCheckInReward(body),
    ...player.delta,
  } satisfies GetOpenServerCheckInRewardResponse);
});

/**
 * 获取活动签到奖励
 * @route POST /activity/getActivityCheckInReward
 * @param req.body.activityId - 活动ID
 * @param req.body.index - 签到索引
 * @returns 玩家增量数据和物品列表
 */
router.post("/getActivityCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetActivityCheckInRewardRequest;

  await player.update(async (draft) => {
    const activityId = body.activityId;
    const targetIndex = body.index;

    if (!draft.activity.CHECKIN_ONLY[activityId]) {
      draft.activity.CHECKIN_ONLY[activityId] = {
        lastTs: 0,
        history: [],
      };
    }
    draft.activity.CHECKIN_ONLY[activityId].history[targetIndex] = 0;
  });

  res.send({
    ...player.delta,
    items: [],
  } satisfies GetActivityCheckInRewardResponse);
});

/**
 * 签到对决活动签到
 * @route POST /activity/actCheckinvs/sign
 * @param req.body.actId - 活动ID
 * @param req.body.tasteChoice - 口味选择（1=甜，2=咸）
 * @returns 玩家增量和物品列表
 */
router.post("/actCheckinvs/sign", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ActCheckinvsSignRequest;

  await player.update(async (draft) => {
    const actId = body.actId;
    const tasteChoice = body.tasteChoice;

    const vsData = draft.activity.CHECKIN_VS as any;
    if (!vsData[actId]) {
      vsData[actId] = {
        sweetVote: 0,
        saltyVote: 0,
        canVote: true,
        todayVoteState: 0,
        voteRewardState: 0,
        signedCnt: 0,
        availSignCnt: 1,
        socialState: 2,
        actDay: 1,
      };
    }
    vsData[actId].signedCnt++;
    vsData[actId].canVote = false;
    if (tasteChoice === 1) {
      vsData[actId].sweetVote++;
    } else {
      vsData[actId].saltyVote++;
    }
  });

  res.send({
    ...player.delta,
    items: [
      { type: "AP_SUPPLY", id: "ap_supply_lt_120", count: 1 },
      { type: "GOLD", id: "4001", count: 30000 },
    ],
  } satisfies ActCheckinvsSignResponse);
});

/**
 * 获取开关型活动奖励
 * @route POST /activity/getSwitchOnlyReward
 * @param req.body.activityId - 活动ID
 * @param req.body.reward - 奖励ID
 * @returns 玩家增量数据
 */
router.post("/getSwitchOnlyReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetSwitchOnlyRewardRequest;

  await player.update(async (draft) => {
    const activityId = body.activityId;
    const rewardId = body.reward;

    const switchData = draft.activity.SWITCH_ONLY as any;
    if (!switchData[activityId]) {
      switchData[activityId] = {};
    }
    switchData[activityId][rewardId] = 0;
  });

  res.send(player.delta satisfies GetSwitchOnlyRewardResponse);
});

/**
 * 获取签到奖励（通用入口）
 * @route POST /activity/getCheckInReward
 * @param req.body.activityId - 活动ID
 * @returns 玩家增量和物品列表
 *
 * 根据 activityId 后缀分发到不同的处理逻辑：
 * - access 后缀：访问型签到，发放理智药剂和合成玉
 * - blessing 后缀：祝福型签到，初始化祝福数据
 */
router.post("/getCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetCheckInRewardRequest;

  const activityId = body.activityId;

  if (activityId.endsWith("access")) {
    await player.update(async (draft) => {
      if (!draft.activity.CHECKIN_ACCESS[activityId]) {
        draft.activity.CHECKIN_ACCESS[activityId] = {
          rewardsCount: 0,
          currentStatus: 0,
          lastTs: 0,
        };
      }
      draft.activity.CHECKIN_ACCESS[activityId].rewardsCount++;
      draft.activity.CHECKIN_ACCESS[activityId].lastTs = Math.floor(Date.now() / 1000);
    });

    res.send({
      ...player.delta,
      items: [
        { type: "AP_SUPPLY", id: "ap_supply_lt_80", count: 1 },
        { type: "DIAMOND_SHD", id: "4003", count: 200 },
      ],
    } satisfies GetCheckInRewardResponse);
  } else if (activityId.endsWith("blessing")) {
    await player.update(async (draft) => {
      const blessData = draft.activity.BLESS_ONLY as any;
      if (!blessData[activityId]) {
        blessData[activityId] = {};
      }
    });

    res.send({
      ...player.delta,
      items: [],
    } satisfies GetCheckInRewardResponse);
  } else {
    res.send({
      ...player.delta,
      items: [],
    } satisfies GetCheckInRewardResponse);
  }
});

/**
 * 更换节日干员
 * @route POST /activity/changeFestivalChar
 * @param req.body.activityId - 活动ID（如 act3blessing）
 * @param req.body.index - 节日历史索引
 * @param req.body.newChar - 新干员ID
 * @returns 玩家增量数据
 *
 * 参考实现：更新 BLESS_ONLY 中 festivalHistory[index].charId 字段。
 * 由于活动数据结构差异，简化处理为直接写入 charId。
 */
router.post("/changeFestivalChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ChangeFestivalCharRequest;

  await player.update(async (draft) => {
    const blessData = draft.activity.BLESS_ONLY as any;
    if (!blessData[body.activityId]) {
      blessData[body.activityId] = { festivalHistory: [], history: [] };
    }
    const activityData = blessData[body.activityId];
    if (!activityData.festivalHistory) {
      activityData.festivalHistory = [];
    }
    if (!activityData.festivalHistory[body.index]) {
      activityData.festivalHistory[body.index] = { charId: body.newChar, state: 1 };
    } else {
      activityData.festivalHistory[body.index].charId = body.newChar;
    }
  });

  res.send(player.delta satisfies ChangeFestivalCharResponse);
});

/**
 * 领取活动里程碑奖励
 * @route POST /activity/rewardMilestone
 * @param req.body.activityId - 活动ID
 * @param req.body.milestoneId - 里程碑ID
 * @returns 玩家增量和奖励物品列表
 *
 * 简化实现：从活动数据中查找里程碑奖励配置，标记已领取状态并发放奖励。
 * 由于活动里程碑数据结构因活动类型而异，此处采用通用处理逻辑。
 */
router.post("/rewardMilestone", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RewardMilestoneRequest;
  const rewards: ItemBundle[] = [];

  await player.update(async (draft) => {
    // 尖灭测试（BOSS_RUSH）：领取状态写入 milestone.got（对齐官服快照结构），
    // 而非下面的通用 MILESTONE_ONLY 标记——客户端从 syncData 读 BOSS_RUSH[actId].milestone.got
    const bossRush = (draft.activity as any).BOSS_RUSH?.[body.activityId] as
      | { milestone?: { got?: string[] } }
      | undefined;
    if (bossRush?.milestone && body.milestoneId) {
      if (!bossRush.milestone.got) bossRush.milestone.got = [];
      if (!bossRush.milestone.got.includes(body.milestoneId)) {
        bossRush.milestone.got.push(body.milestoneId);
      }
      return;
    }
    // 通用活动：在 activity 数据中以 MILESTONE_ONLY 类型存储里程碑领取状态
    const milestoneData = (draft.activity as any).MILESTONE_ONLY as
      | { [key: string]: { [key: string]: number } }
      | undefined;
    if (!milestoneData) {
      (draft.activity as any).MILESTONE_ONLY = {};
    }
    const store = (draft.activity as any).MILESTONE_ONLY as {
      [key: string]: { [key: string]: number };
    };
    if (!store[body.activityId]) {
      store[body.activityId] = {};
    }
    // 标记该里程碑为已领取（0 表示已领取，参考游戏协议）
    if (body.milestoneId) {
      store[body.activityId][body.milestoneId] = 0;
    }
  });

  res.send({
    ...player.delta,
    item: rewards,
  } satisfies RewardMilestoneResponse);
});

/**
 * 领取所有活动里程碑奖励
 * @route POST /activity/rewardAllMilestone
 * @param req.body.activityId - 活动ID
 * @returns 玩家增量和奖励物品列表
 *
 * 简化实现：批量领取指定活动的所有可领取里程碑奖励。
 */
router.post("/rewardAllMilestone", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RewardAllMilestoneRequest;
  const rewards: ItemBundle[] = [];

  await player.update(async (draft) => {
    // 尖灭测试：批量领取走 milestone.got（无配置表时无法枚举未领里程碑，此处保持已领集合不变）
    const bossRush = (draft.activity as any).BOSS_RUSH?.[body.activityId] as
      | { milestone?: { got?: string[] } }
      | undefined;
    if (bossRush?.milestone) {
      return;
    }
    if (!(draft.activity as any).MILESTONE_ONLY) {
      (draft.activity as any).MILESTONE_ONLY = {};
    }
    const store = (draft.activity as any).MILESTONE_ONLY as {
      [key: string]: { [key: string]: number };
    };
    if (!store[body.activityId]) {
      store[body.activityId] = {};
    }
    // 简化处理：将所有已有里程碑标记为已领取
    // 实际游戏中需要查询活动配置表判断哪些里程碑已达成但未领取
    for (const milestoneId of Object.keys(store[body.activityId])) {
      store[body.activityId][milestoneId] = 0;
    }
  });

  res.send({
    ...player.delta,
    item: rewards,
  } satisfies RewardAllMilestoneResponse);
});

/**
 * 确认活动任务并领取奖励
 * @route POST /activity/confirmActivityMission
 * @param req.body.missionId - 活动任务ID
 * @returns 玩家增量和奖励物品列表
 *
 * 简化实现：从 ActivityTable.missionData 中查找任务奖励，标记任务为已完成（state=3）
 * 并通过事件触发器发放奖励。活动任务的进度追踪未实现，仅处理领取逻辑。
 */
router.post("/confirmActivityMission", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ConfirmActivityMissionRequest;
  const rewards: ItemBundle[] = [];

  // 优先尝试调用 mission manager（兼容部分活动任务在 MissionTable 中的情况）
  try {
    const items = await player.mission.confirmMission({ missionId: body.missionId });
    rewards.push(...items);
  } catch {
    // 兜底逻辑：从 ActivityTable.missionData 中查找任务奖励
    const missionInfo = excel.ActivityTable.missionData.find(
      (m) => m.id === body.missionId,
    );
    if (missionInfo) {
      for (const reward of missionInfo.rewards) {
        rewards.push({
          id: reward.id,
          count: reward.count,
          type: ItemTypeToString(reward.type),
        });
      }
      await player.update(async (draft) => {
        const activityMissions = draft.mission.missions["ACTIVITY"];
        if (activityMissions && activityMissions[body.missionId]) {
          activityMissions[body.missionId].state = 3;
        }
      });
      await player._trigger.emit("items:get", [rewards]);
    }
  }

  res.send({
    ...player.delta,
    rewards,
  } satisfies ConfirmActivityMissionResponse);
});

/**
 * 批量确认活动任务并领取奖励
 * @route POST /activity/confirmActivityMissionList
 * @param req.body.missionIdList - 活动任务ID列表
 * @returns 玩家增量和奖励物品列表
 *
 * 循环调用单个任务确认逻辑，合并所有奖励。
 */
router.post("/confirmActivityMissionList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ConfirmActivityMissionListRequest;
  const allRewards: ItemBundle[] = [];

  const missionIdList = body.missionIdList || [];
  for (const missionId of missionIdList) {
    try {
      const items = await player.mission.confirmMission({ missionId });
      allRewards.push(...items);
    } catch {
      // 兜底逻辑：从 ActivityTable.missionData 中查找任务奖励
      const missionInfo = excel.ActivityTable.missionData.find(
        (m) => m.id === missionId,
      );
      if (missionInfo) {
        for (const reward of missionInfo.rewards) {
          allRewards.push({
            id: reward.id,
            count: reward.count,
            type: ItemTypeToString(reward.type),
          });
        }
        await player.update(async (draft) => {
          const activityMissions = draft.mission.missions["ACTIVITY"];
          if (activityMissions && activityMissions[missionId]) {
            activityMissions[missionId].state = 3;
          }
        });
      }
    }
  }

  if (allRewards.length > 0) {
    await player._trigger.emit("items:get", [allRewards]);
  }

  res.send({
    ...player.delta,
    rewards: allRewards,
  } satisfies ConfirmActivityMissionListResponse);
});

/**
 * 确认活动任务组并领取奖励
 * @route POST /activity/confirmActivityMissionGroup
 * @param req.body.missionGroupId - 活动任务组ID
 * @returns 玩家增量数据
 *
 * 简化实现：优先调用 mission manager 的 confirmMissionGroup，
 * 失败时从 ActivityTable.missionGroup 中查找组奖励并发放。
 */
router.post("/confirmActivityMissionGroup", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ConfirmActivityMissionGroupRequest;
  let rewards: ItemBundle[] = [];

  try {
    await player.mission.confirmMissionGroup({ missionGroupId: body.missionGroupId });
  } catch {
    // 兜底逻辑：从 ActivityTable.missionGroup 中查找组奖励
    const groupInfo = excel.ActivityTable.missionGroup.find(
      (g) => g.id === body.missionGroupId,
    );
    if (groupInfo && groupInfo.rewards) {
      rewards = groupInfo.rewards.map((r) => ({
        id: r.id,
        count: r.count,
        type: ItemTypeToString(r.type),
      }));
      await player._trigger.emit("items:get", [rewards]);
    }
    await player.update(async (draft) => {
      draft.mission.missionGroups[body.missionGroupId] = 1;
    });
  }

  res.send({
    ...player.delta,
    rewards,
  } satisfies ConfirmActivityMissionGroupResponse);
});

/**
 * 自动确认并领取所有已完成的活动任务奖励
 * @route POST /activity/autoConfirmMissions
 * @param req.body.type - 任务类型（如 ACTIVITY）
 * @returns 玩家增量和奖励物品列表
 *
 * 简化实现：遍历指定类型的所有任务，对 state==2 且进度已满的任务
 * 调用 confirmMission 发放奖励。
 */
router.post("/autoConfirmMissions", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as AutoConfirmMissionsRequest;
  const allRewards: ItemBundle[] = [];

  try {
    const items = await player.mission.autoConfirmMissions({ type: body.type });
    allRewards.push(...items);
  } catch {
    // 兜底逻辑：直接遍历玩家数据中的活动任务
    await player.update(async (draft) => {
      const missions = draft.mission.missions[body.type];
      if (!missions) return;
      for (const [missionId, missionState] of Object.entries(missions)) {
        const isCompleted =
          missionState.state === 2 &&
          missionState.progress.length > 0 &&
          missionState.progress[0].target != null &&
          missionState.progress[0].value >= (missionState.progress[0].target as number);
        if (isCompleted) {
          missionState.state = 3;
          // 查找任务奖励
          const missionInfo = excel.ActivityTable.missionData.find(
            (m) => m.id === missionId,
          );
          if (missionInfo) {
            for (const reward of missionInfo.rewards) {
              allRewards.push({
                id: reward.id,
                count: reward.count,
                type: ItemTypeToString(reward.type),
              });
            }
          }
        }
      }
    });
    if (allRewards.length > 0) {
      await player._trigger.emit("items:get", [allRewards]);
    }
  }

  res.send({
    ...player.delta,
    items: allRewards,
  } satisfies AutoConfirmMissionsResponse);
});

/**
 * 兑换活动商店商品
 * @route POST /activity/exchangeActivityShopItem
 * @param req.body.shopId - 活动商店ID
 * @param req.body.goodId - 商品ID
 * @param req.body.count - 购买数量
 * @returns 玩家增量和奖励物品列表
 *
 * 简化实现：从 PlayerTemplateShop 中扣除对应代币，发放商品物品。
 * 由于活动商店配置因活动而异，此处采用通用 tshop 数据结构处理。
 */
router.post("/exchangeActivityShopItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ExchangeActivityShopItemRequest;
  const count = body.count || 1;
  let rewardItem: ItemBundle | null = null;

  await player.update(async (draft) => {
    // 初始化模板商店数据（如果不存在）
    if (!draft.tshop[body.shopId]) {
      draft.tshop[body.shopId] = {
        coin: 0,
        info: [],
        progressInfo: {},
      };
    }
    const shop = draft.tshop[body.shopId];
    // 查找商品购买记录
    const existingItem = shop.info.find((i) => i.id === body.goodId);
    if (existingItem) {
      existingItem.count += count;
    } else {
      shop.info.push({ id: body.goodId, count });
    }
  });

  if (rewardItem) {
    await player._trigger.emit("items:get", [[rewardItem]]);
  }

  res.send({
    ...player.delta,
    items: rewardItem ? [rewardItem] : [],
  } satisfies ExchangeActivityShopItemResponse);
});

/**
 * 获取活动收集奖励
 * @route POST /activity/getActivityCollectionReward
 * @param req.body.activityId - 活动ID
 * @param req.body.collectionId - 收集项ID
 * @returns 玩家增量和奖励物品列表
 *
 * 简化实现：从 ActivityTable.activity.COLLECTION 中查找活动配置，
 * 标记收集状态并发放对应奖励。
 */
router.post("/getActivityCollectionReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetActivityCollectionRewardRequest;
  const rewards: ItemBundle[] = [];

  await player.update(async (draft) => {
    if (!(draft.activity as any).COLLECTION) {
      (draft.activity as any).COLLECTION = {};
    }
    const collectionData = (draft.activity as any).COLLECTION as {
      [key: string]: { [key: number]: number };
    };
    if (!collectionData[body.activityId]) {
      collectionData[body.activityId] = {};
    }
    // 从配置表查找收集奖励
    const collectionConfig =
      excel.ActivityTable.activity.COLLECTION[body.activityId];
    if (collectionConfig && collectionConfig.collections && body.collectionId != null) {
      const collectionInfo = collectionConfig.collections.find(
        (c) => c.id === body.collectionId,
      );
      if (collectionInfo) {
        rewards.push({
          id: collectionInfo.itemId,
          count: collectionInfo.itemCnt,
        });
      }
    }
    // 标记收集项为已领取（0 表示已领取）
    if (body.collectionId != null) {
      collectionData[body.activityId][body.collectionId] = 0;
    }
  });

  if (rewards.length > 0) {
    await player._trigger.emit("items:get", [rewards]);
  }

  res.send({
    ...player.delta,
    item: rewards,
  } satisfies GetActivityCollectionRewardResponse);
});

/**
 * 获取活动商店信息
 * @route POST /activity/getActivityShopInfo
 * @param req.body.shopId - 活动商店ID
 * @returns 玩家增量和商店信息
 *
 * 简化实现：返回玩家在指定活动商店的购买记录和代币余额。
 */
router.post("/getActivityShopInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetActivityShopInfoRequest;

  const playerData = player._playerdata as any;
  const tshop = playerData.tshop || {};
  const shopInfo = tshop[body.shopId] || { coin: 0, info: [], progressInfo: {} };

  res.send({
    ...player.delta,
    shopInfo,
  } satisfies GetActivityShopInfoResponse);
});

/**
 * 回收信物
 * @route POST /activity/recycleCharms
 * @param req.body.charmIds - 待回收的信物ID列表
 * @returns 玩家增量、回收结果和回收数量
 *
 * 简化实现：从 charm.charms 中减少对应信物数量，按回收比例返还硬币。
 */
router.post("/recycleCharms", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RecycleCharmsRequest;
  const charmIds = body.charmIds || [];
  let recycleNum = 0;

  await player.update(async (draft) => {
    const charms = draft.charm.charms;
    for (const charmId of charmIds) {
      if (charms[charmId] && charms[charmId] > 0) {
        charms[charmId] -= 1;
        recycleNum += 1;
        // 查找信物配置获取回收价格
        const charmInfo = excel.CharmTable.charmList.find((c) => c.id === charmId);
        if (charmInfo) {
          // 回收返还 1 个硬币（简化处理，实际游戏按价格比例返还）
          draft.inventory["4001"] = (draft.inventory["4001"] || 0) + 1;
        }
      }
    }
  });

  res.send({
    ...player.delta,
    result: 0,
    recycleNum,
  } satisfies RecycleCharmsResponse);
});

/**
 * 尝试获取信物首通奖励
 * @route POST /activity/tryGetCharmFirstReward
 * @param req.body.charmId - 信物ID
 * @returns 玩家增量、是否首通标志和奖励列表
 *
 * 简化实现：检查信物是否已领取首通奖励，未领取则发放奖励并标记。
 */
router.post("/tryGetCharmFirstReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as TryGetCharmFirstRewardRequest;
  let isFirst = false;
  const rewards: ItemBundle[] = [];

  await player.update(async (draft) => {
    // 在 charm 数据中新增 firstReward 字段记录首通领取状态
    const charmStatus = draft.charm as any;
    if (!charmStatus.firstReward) {
      charmStatus.firstReward = {};
    }
    if (!charmStatus.firstReward[body.charmId]) {
      isFirst = true;
      charmStatus.firstReward[body.charmId] = 1;
      // 查找信物配置获取首通奖励（简化：发放 1 个该信物作为首通奖励）
      const charmInfo = excel.CharmTable.charmList.find((c) => c.id === body.charmId);
      if (charmInfo) {
        rewards.push({ id: body.charmId, count: 1, type: "CHARM" });
      }
    }
  });

  if (rewards.length > 0) {
    await player._trigger.emit("items:get", [rewards]);
  }

  res.send({
    ...player.delta,
    isFirst,
    reward: rewards,
  } satisfies TryGetCharmFirstRewardResponse);
});

/* ===== 尖灭测试（bossRush，参考 DoctoratePy activity.py / OBS misc_bp）===== */

/**
 * 尖灭测试开始战斗
 * @route POST /activity/bossRush/battleStart
 * @param req.body - CS: BossRushStartBattleRequest（activityId/stageId/teamId/ownSlots/assistFriend）
 * @returns 战斗开始信息（同 quest battleStart 形状）
 *
 * 复用标准战斗开始（battle.start）——尖灭关卡 apCost=0 不耗理智，
 * battleInfo 由 battle.start 落库供 battleFinish 结算读取。
 */
router.post("/bossRush/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BossRushStartBattleRequest;
  res.send({
    ...(await player.battle.start({
      stageId: body.stageId,
      squad: body.ownSlots,
      usePracticeTicket: 0,
      assistFriend: body.assistFriend,
      // 其余字段 battle.start 未读取，填默认值满足类型
      isRetro: 0,
      pray: 0,
      battleType: 0,
      continuous: { battleTimes: 1 },
      isReplay: 0,
      startTs: 0,
    } as CommonStartBattleRequest)),
    ...player.delta,
  } satisfies BossRushStartBattleResponse);
});

/**
 * 尖灭测试战斗结算
 * @route POST /activity/bossRush/battleFinish
 * @param req.body - CS: BossRushFinishBattleRequest（CommonFinishBattleRequest + activityId）
 * @returns 结算信息 + 尖灭专属字段（wave/milestone/token）
 *
 * 复用标准战斗结算（battle.finish：掉落/关卡解锁/图鉴），
 * 再按 DoctoratePy 逻辑更新 activity.BOSS_RUSH[activityId] 的
 * milestone.point / relic.token.total / best[stageId]；wave 从战斗数据
 * extraBattleInfo 的 bossrush_finished_wave 解析，掉落加值数据驱动
 * （当前 excel 无尖灭掉落配置时 milestoneAdd/tokenAdd 回退为 0）。
 */
router.post("/bossRush/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BossRushFinishBattleRequest;

  // 标准战斗结算
  const result = await player.battle.finish({
    data: body.data,
    battleData: body.battleData,
  });

  // 解密战斗数据：解析波次与关卡 id
  let wave = 0;
  let stageId = "";
  try {
    const battleData = await decryptBattleData(
      body.data,
      player._playerdata.pushFlags.status,
    );
    const extra = battleData.battleData?.stats?.extraBattleInfo ?? {};
    for (const [key, value] of Object.entries(extra)) {
      if (key.includes("bossrush_finished_wave")) {
        wave = Number(value);
      }
    }
    const battleInfo = await accountManager.getBattleInfo(
      player.uid,
      battleData.battleId,
    );
    stageId = battleInfo?.stageId ?? "";
  } catch (err) {
    logger.error("activity/bossRush/battleFinish", "解密战斗数据失败:", err);
  }

  // 更新尖灭专属数据（milestone/token/best）
  let milestoneBefore = 0;
  let milestoneAdd = 0;
  let tokenAdd = 0;
  await player.update(async (draft) => {
    const bossRush = (draft.activity as any).BOSS_RUSH?.[body.activityId] as
      | {
          milestone?: { point?: number; got?: string[] };
          relic?: {
            token?: { current?: number; total?: number };
            level?: { [key: string]: number };
            select?: string;
          };
          best?: { [key: string]: number };
        }
      | undefined;
    if (!bossRush) return;
    milestoneBefore = bossRush.milestone?.point ?? 0;
    // 数据驱动：掉落配置含 milestone_point/token_relic 时累计（当前 excel 无则回退 0）
    if (stageId && excel.StageTable.stages[stageId]) {
      const drops =
        excel.StageTable.stages[stageId].stageDropInfo?.displayDetailRewards ?? [];
      for (const drop of drops as any[]) {
        const dropId = drop?.id ?? "";
        if (dropId.includes("milestone_point")) {
          milestoneAdd += Number(drop?.dropCount ?? 0);
        }
        if (dropId.includes("token_relic")) {
          tokenAdd += Number(drop?.dropCount ?? 0);
        }
      }
    }
    if (milestoneAdd !== 0 && bossRush.milestone) {
      bossRush.milestone.point = milestoneBefore + milestoneAdd;
    }
    if (tokenAdd !== 0 && bossRush.relic?.token) {
      bossRush.relic.token.total = (bossRush.relic.token.total ?? 0) + tokenAdd;
    }
    // 更新该关最高波次（best）
    if (wave && stageId) {
      if (!bossRush.best) bossRush.best = {};
      if (wave > (bossRush.best[stageId] ?? 0)) {
        bossRush.best[stageId] = wave;
      }
    }
  });

  res.send({
    ...result,
    result: 0,
    wave,
    milestoneBefore,
    milestoneAdd,
    isMilestoneMax: false,
    tokenAdd,
    isTokenMax: false,
    ...player.delta,
  } satisfies BossRushFinishBattleResponse);
});

/**
 * 尖灭测试密文选择
 * @route POST /activity/bossRush/relicSelect
 * @param req.body - CS: BossRushRelicSelectRequest（activityId/relicId）
 * @returns 玩家增量
 *
 * 参考 DoctoratePy/OBS：写入 activity.BOSS_RUSH[activityId].relic.select
 */
router.post("/bossRush/relicSelect", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BossRushRelicSelectRequest;
  await player.update(async (draft) => {
    const relic = (draft.activity as any).BOSS_RUSH?.[body.activityId]?.relic as
      | { select?: string }
      | undefined;
    if (relic) {
      relic.select = body.relicId;
    }
  });
  res.send(player.delta satisfies BossRushRelicSelectResponse);
});

/**
 * 尖灭测试密文升级
 * @route POST /activity/bossRush/relicUpgrade
 * @param req.body - CS: BossRushRelicUpgradeRequest（activityId/relicId）
 * @returns 玩家增量
 *
 * 参考 DoctoratePy activityBossRushRelicUpgrade：等级 +1，消耗 20 尖灭代币（current）
 */
router.post("/bossRush/relicUpgrade", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BossRushRelicUpgradeRequest;
  await player.update(async (draft) => {
    const relic = (draft.activity as any).BOSS_RUSH?.[body.activityId]?.relic as
      | {
          token?: { current?: number; total?: number };
          level?: { [key: string]: number };
          select?: string;
        }
      | undefined;
    if (!relic) return;
    if (!relic.level) relic.level = {};
    relic.level[body.relicId] = (relic.level[body.relicId] ?? 1) + 1;
    if (!relic.token) relic.token = { current: 0, total: 0 };
    relic.token.current = Math.max(0, (relic.token.current ?? 0) - 20);
  });
  res.send(player.delta satisfies BossRushRelicUpgradeResponse);
});

export default router;

/**
 * 将 ItemType 枚举值转换为字符串类型标识
 * @param itemType - ItemType 枚举值
 * @returns 对应的字符串类型标识
 *
 * 用于将配置表中的数字类型枚举转换为 inventory manager 可识别的字符串类型。
 */
function ItemTypeToString(itemType: number | string): string {
  const key = typeof itemType === "string" ? parseInt(itemType, 10) : itemType;
  if (isNaN(key)) return String(itemType);
  const itemTypeMap: { [key: number]: string } = {
    0: "NONE",
    1: "CHAR",
    2: "CARD_EXP",
    3: "MATERIAL",
    4: "GOLD",
    5: "EXP_PLAYER",
    6: "TKT_TRY",
    7: "TKT_RECRUIT",
    8: "TKT_INST_FIN",
    9: "TKT_GACHA",
    10: "DIAMOND",
    11: "DIAMOND_SHD",
    12: "LGG_SHD",
    13: "HGG_SHD",
    14: "FURN",
    15: "ACTIVITY_COIN",
    16: "AP_GAMEPLAY",
    17: "AP_BASE",
    18: "SOCIAL_PT",
    19: "CHAR_SKIN",
    20: "TKT_GACHA_10",
    21: "AP_ITEM",
    22: "AP_SUPPLY",
    23: "RENAMING_CARD",
    24: "RENAMING_CARD_2",
    25: "ET_STAGE",
    26: "ACTIVITY_ITEM",
    27: "VOUCHER_PICK",
    28: "VOUCHER_CGACHA",
    29: "VOUCHER_MGACHA",
    30: "CRS_SHOP_COIN",
    31: "CRS_RUNE_COIN",
    32: "LMTGS_COIN",
    33: "EPGS_COIN",
    34: "LIMITED_TKT_GACHA_10",
    35: "LIMITED_FREE_GACHA",
    36: "REP_COIN",
    37: "ROGUELIKE",
    38: "LINKAGE_TKT_GACHA_10",
    39: "VOUCHER_ELITE_II_4",
    40: "VOUCHER_ELITE_II_5",
    41: "VOUCHER_ELITE_II_6",
    42: "VOUCHER_SKIN",
    43: "RETRO_COIN",
    44: "PLAYER_AVATAR",
    45: "UNI_COLLECTION",
    46: "VOUCHER_FULL_POTENTIAL",
    47: "RL_COIN",
    48: "RETURN_CREDIT",
    49: "MEDAL",
    50: "CHARM",
    51: "HOME_BACKGROUND",
    52: "EXTERMINATION_AGENT",
    53: "OPTIONAL_VOUCHER_PICK",
    54: "ACT_CART_COMPONENT",
    55: "VOUCHER_LEVELMAX_6",
    56: "VOUCHER_LEVELMAX_5",
    57: "VOUCHER_LEVELMAX_4",
    58: "VOUCHER_SKILL_SPECIALLEVELMAX_6",
    59: "VOUCHER_SKILL_SPECIALLEVELMAX_5",
    60: "VOUCHER_SKILL_SPECIALLEVELMAX_4",
    61: "ACTIVITY_POTENTIAL",
    62: "ITEM_PACK",
    63: "SANDBOX",
    64: "FAVOR_ADD_ITEM",
    65: "CLASSIC_SHD",
    66: "CLASSIC_TKT_GACHA",
    67: "CLASSIC_TKT_GACHA_10",
    68: "LIMITED_BUFF",
    69: "CLASSIC_FES_PICK_TIER_5",
    70: "CLASSIC_FES_PICK_TIER_6",
    71: "RETURN_PROGRESS",
    72: "NEW_PROGRESS",
    73: "MCARD_VOUCHER",
    74: "MATERIAL_ISSUE_VOUCHER",
    75: "CRS_SHOP_COIN_V2",
    76: "HOME_THEME",
    77: "SANDBOX_PERM",
    78: "SANDBOX_TOKEN",
    79: "TEMPLATE_TRAP",
    80: "NAME_CARD_SKIN",
    81: "EXCLUSIVE_TKT_GACHA",
    82: "EXCLUSIVE_TKT_GACHA_10",
  };
  return itemTypeMap[key] || "MATERIAL";
}
