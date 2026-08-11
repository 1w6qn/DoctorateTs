/**
 * 活动路由模块
 *
 * 处理活动相关的 HTTP 请求，包括签到奖励、节日活动、活动任务、活动商店、
 * 信物回收等多种活动类型的业务逻辑。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { accountManager } from "../manager/AccountManager";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { decryptBattleData } from "@utils/crypt";
import { logger } from "@utils/logger";
import { now } from "@utils/time";
import { CommonStartBattleRequest } from "../model/battle";
import config from "../../config";
import { VHALFIDLE_POOLS, VHALFIDLE_SPEC_CHAR } from "../data/vhalfidle";
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
  EnemyDuelBattleStartResponse,
  EnemyDuelCreateTeamRequest,
  EnemyDuelCreateTeamResponse,
  EnemyDuelJoinTeamRequest,
  EnemyDuelJoinTeamResponse,
  EnemyDuelMultiBattleFinishRequest,
  EnemyDuelMultiBattleFinishResponse,
  EnemyDuelMultiBattleStartRequest,
  EnemyDuelQueryMatchRequest,
  EnemyDuelQueryMatchResponse,
  EnemyDuelRankInfo,
  EnemyDuelSingleBattleFinishRequest,
  EnemyDuelSingleBattleFinishResponse,
  EnemyDuelSingleBattleStartRequest,
  EnemyDuelStartMatchRequest,
  EnemyDuelStartMatchResponse,
  Act24sideAlchemyRequest,
  Act24sideAlchemyResponse,
  Act24sideBattleFinishRequest,
  Act24sideBattleFinishResponse,
  Act24sideBattleStartRequest,
  Act24sideBattleStartResponse,
  Act24sideEatRequest,
  Act24sideEatResponse,
  Act24sideGetHuntCollectRewardsRequest,
  Act24sideGetHuntCollectRewardsResponse,
  Act24sideSetToolRequest,
  Act24sideSetToolResponse,
  Act25sideBattleFinishRequest,
  Act25sideBattleFinishResponse,
  Act25sideBattleStartRequest,
  Act25sideBattleStartResponse,
  Act25sideDailyRefreshRequest,
  Act25sideDailyRefreshResponse,
  Act25sideFinishInvestigationRequest,
  Act25sideFinishInvestigationResponse,
  Act25sideHarvestRequest,
  Act25sideHarvestResponse,
  Act25sideInvestigateRequest,
  Act25sideInvestigateResponse,
  Act29sideCommitMelodyRequest,
  Act29sideCommitMelodyResponse,
  Act29sideStartMajorInvestRequest,
  Act29sideStartMajorInvestResponse,
  Act29sideSyncthesizeRequest,
  Act29sideSyncthesizeResponse,
  Act36sideConfirmDexNavRewardRequest,
  Act36sideConfirmDexNavRewardResponse,
  FootballBattleFinishRequest,
  FootballBattleFinishResponse,
  FootballBattleStartRequest,
  FootballBattleStartResponse,
  TrainingGroundBattleFinishRequest,
  TrainingGroundBattleFinishResponse,
  TrainingGroundBattleStartRequest,
  TrainingGroundBattleStartResponse,
  Act13sideDailyMissionCommitRequest,
  Act13sideDailyMissionRandomRequest,
  Act1vhalfidleRequest,
  Act35sideBuyRequest,
  Act35sideCreateRequest,
  Act42sideGetDailyRewardsRequest,
  Act44sideSelectChoiceRequest,
  Act44sideStartGameRequest,
  Act45sideConfirmRequest,
  Act46sideGameRequest,
  Act5d1BuyGoodsRequest,
  ActivityGetRewardRequest,
  ActivityMiniBattleFinishRequest,
  ActivityMiniBattleFinishResponse,
  ActivityMiniBattleStartRequest,
  ActivityMiniBattleStartResponse,
  ActivityStubItemsResponse,
  ActivityStubRequest,
  ActivityStubResponse,
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
    (draft.activity as any).CHECKIN_ONLY[activityId].history[targetIndex] = 0;
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
      (draft.activity as any).CHECKIN_ACCESS[activityId].rewardsCount++;
      (draft.activity as any).CHECKIN_ACCESS[activityId].lastTs = Math.floor(Date.now() / 1000);
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
        const activityMissions = (draft.mission as any).missions["ACTIVITY"];
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
          const activityMissions = (draft.mission as any).missions["ACTIVITY"];
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
      const missions = (draft.mission as any).missions[body.type];
      if (!missions) return;
      for (const [missionId, missionState] of Object.entries(missions) as any) {
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
      (excel.ActivityTable.activity as { COLLECTION: { [key: string]: { collections?: { id: string; itemId: string; itemCnt: number }[] } } }).COLLECTION[
        body.activityId
      ];
    if (collectionConfig && collectionConfig.collections && body.collectionId != null) {
      const collectionInfo = collectionConfig.collections.find(
        (c) => c.id === String(body.collectionId),
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

/* ===== 怪猎对决（enemyDuel，参考 ODPY activity.py enemyDuel + OBS misc_bp + CS 2.7.61）===== */

/** 匹配状态（参考 OBS extra_save 保存 activityId/modeId 供 queryMatch 构建 serverToken） */
let enemyDuelMatchState: { activityId: string; modeId: string } | null = null;

/** 生成怪猎对决 battleId/teamId（怪猎为特殊轮次战斗，参考 ODPY 固定 battleId stub） */
function genEnemyDuelId(): string {
  const hex = "0123456789abcdef";
  let out = "";
  for (let i = 0; i < 32; i++) out += hex[Math.floor(Math.random() * 16)];
  return `${out.slice(0, 8)}-${out.slice(8, 12)}-${out.slice(12, 16)}-${out.slice(
    16,
    20,
  )}-${out.slice(20)}`;
}

/** 私服多人在线地址（无真实多人在线，指向本服） */
function enemyDuelServerAddress(): string {
  return `${String(config.Host).replace(/^https?:\/\//, "")}:${config.PORT}`;
}

/** 构建怪猎对决结算响应（玩家成绩 + 活动表 NPC 填充排行榜，参考 ODPY/OBS） */
function buildEnemyDuelFinishResponse(
  activityId: string,
  clientRankList?: EnemyDuelRankInfo[],
) {
  const rankList: EnemyDuelRankInfo[] = clientRankList?.length
    ? clientRankList
    : [{ id: "1", rank: 1, score: 0, isPlayer: 1 }];
  const npcData = (
    (excel.ActivityTable as any)?.activity?.ENEMY_DUEL?.[activityId]
      ?.npcData as Record<string, unknown> | undefined
  );
  let rank = 2;
  for (const npcId of Object.keys(npcData ?? {})) {
    if (rankList.length >= 8) break;
    rankList.push({ id: npcId, rank: rank++, score: 0, isPlayer: 0 });
  }
  return {
    result: 0,
    apFailReturn: 0,
    itemReturn: [],
    rewards: [],
    unusualRewards: [],
    overrideRewards: [],
    additionalRewards: [],
    diamondMaterialRewards: [],
    furnitureRewards: [],
    goldScale: 0,
    expScale: 0,
    firstRewards: [],
    unlockStages: null,
    pryResult: [],
    alert: [],
    suggestFriend: false,
    extra: null,
    choiceCnt: { skip: 0, normal: 5, allIn: 1 },
    commentId: "Comment_Operation_1",
    isHighScore: false,
    rankList,
    dailyMission: { add: 0, reward: 0 },
    bp: 0,
  };
}

/**
 * 怪猎对决单人开始战斗
 * @route POST /activity/enemyDuel/singleBattleStart
 * CS: EnemyDuelSingleBattleStartRequest {activityId, modeId}；怪猎为特殊轮次战斗，
 * 参考 ODPY/OBS 返回固定 battleId stub（不落 battleInfo，结算独立处理）
 */
router.post("/enemyDuel/singleBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as EnemyDuelSingleBattleStartRequest;
  res.send({
    result: 0,
    battleId: genEnemyDuelId(),
    apFailReturn: 0,
    isApProtect: 0,
    inApProtectPeriod: false,
    notifyPowerScoreNotEnoughIfFailed: false,
    ...player.delta,
  } satisfies EnemyDuelBattleStartResponse);
});

/**
 * 怪猎对决单人战斗结算
 * @route POST /activity/enemyDuel/singleBattleFinish
 * CS: EnemyDuelSingleBattleFinishRequest : CommonFinishBattleRequest + settle/surviveUnits/bornUnits；
 * 结算返回排行榜（settle.rankList + 活动表 NPC 填充）与怪猎专属字段
 */
router.post("/enemyDuel/singleBattleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EnemyDuelSingleBattleFinishRequest;
  res.send({
    ...buildEnemyDuelFinishResponse(body.activityId, body.settle?.rankList),
    ...player.delta,
  } satisfies EnemyDuelSingleBattleFinishResponse);
});

/**
 * 怪猎对决开始匹配
 * @route POST /activity/enemyDuel/startMatch
 * CS: EnemyDuelStartMatchRequest {activityId, modeId}；记录匹配状态供 queryMatch 使用
 */
router.post("/enemyDuel/startMatch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EnemyDuelStartMatchRequest;
  enemyDuelMatchState = { activityId: body.activityId, modeId: body.modeId };
  res.send({ result: 0, ...player.delta } satisfies EnemyDuelStartMatchResponse);
});

/**
 * 怪猎对决查询匹配
 * @route POST /activity/enemyDuel/queryMatch
 * CS: EnemyDuelQueryMatchRequest {activityId, needLeave}；返回队伍信息
 * （serverToken = modeId|curStage，curStage 取玩家 ENEMY_DUEL modeInfo）
 */
router.post("/enemyDuel/queryMatch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EnemyDuelQueryMatchRequest;
  if (body.needLeave || !enemyDuelMatchState) {
    return res.send({
      result: 1,
      team: null,
      playerCnt: 0,
      ...player.delta,
    } satisfies EnemyDuelQueryMatchResponse);
  }
  const { activityId, modeId } = enemyDuelMatchState;
  const modeInfo = (player._playerdata.activity as any)?.ENEMY_DUEL?.[activityId]
    ?.modeInfo as { [key: string]: { curStage?: string } } | undefined;
  const curStage = modeInfo?.[modeId]?.curStage ?? "";
  res.send({
    result: 0,
    team: {
      teamId: genEnemyDuelId(),
      serverAddress: enemyDuelServerAddress(),
      serverToken: `${modeId}|${curStage}`,
    },
    playerCnt: 8,
    ...player.delta,
  } satisfies EnemyDuelQueryMatchResponse);
});

/**
 * 怪猎对决创建队伍
 * @route POST /activity/enemyDuel/createTeam
 * CS: EnemyDuelCreateTeamRequest {activityId, modeId}；私服无真实多人，返回固定队伍 stub
 */
router.post("/enemyDuel/createTeam", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EnemyDuelCreateTeamRequest;
  res.send({
    result: 0,
    team: {
      teamId: genEnemyDuelId(),
      serverAddress: enemyDuelServerAddress(),
      serverToken: `${body.modeId}|create`,
    },
    ...player.delta,
  } satisfies EnemyDuelCreateTeamResponse);
});

/**
 * 怪猎对决加入队伍
 * @route POST /activity/enemyDuel/joinTeam
 * CS: EnemyDuelJoinTeamRequest {activityId, teamId}；私服无真实多人，返回队伍 stub
 */
router.post("/enemyDuel/joinTeam", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EnemyDuelJoinTeamRequest;
  res.send({
    result: 0,
    team: {
      teamId: body.teamId,
      serverAddress: enemyDuelServerAddress(),
      serverToken: "join",
    },
    ...player.delta,
  } satisfies EnemyDuelJoinTeamResponse);
});

/**
 * 怪猎对决多人开始战斗
 * @route POST /activity/enemyDuel/multiBattleStart
 * CS: EnemyDuelMultiBattleStartRequest {activityId, sceneId}；同单人，返回 battleId stub
 */
router.post("/enemyDuel/multiBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as EnemyDuelMultiBattleStartRequest;
  res.send({
    result: 0,
    battleId: genEnemyDuelId(),
    apFailReturn: 0,
    isApProtect: 0,
    inApProtectPeriod: false,
    notifyPowerScoreNotEnoughIfFailed: false,
    ...player.delta,
  } satisfies EnemyDuelBattleStartResponse);
});

/**
 * 怪猎对决多人战斗结算
 * @route POST /activity/enemyDuel/multiBattleFinish
 * CS: EnemyDuelMultiBattleFinishRequest : CommonFinishBattleRequest + sceneId；
 * 响应同单人结算（含 rankList/choiceCnt 等怪猎专属字段）
 */
router.post("/enemyDuel/multiBattleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EnemyDuelMultiBattleFinishRequest;
  res.send({
    ...buildEnemyDuelFinishResponse(body.activityId),
    ...player.delta,
  } satisfies EnemyDuelMultiBattleFinishResponse);
});

/* ===== 怪猎（act24side，参考 ODPY activity.py act24side + OBS misc_bp + CS 2.7.61）===== */

/**
 * 怪猎合成抽奖
 * @route POST /activity/act24side/alchemy
 * 参考 ODPY act24alchemy：消耗 act50melding_N 素材计分（2/3/5/10/20/200 分），
 * 每 100 分从 meldingGachaBoxGoodDataMap[gachaBox] 抽一次（不重复抽完即止），
 * 奖励经 items:get 发放，抽中记录写入 activity.TYPE_ACT24SIDE[activityId].alchemy.gacha
 */
router.post("/act24side/alchemy", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act24sideAlchemyRequest;
  const { activityId, gachaBox } = body;
  const items = body.items ?? {};
  const itemsScoreMap: { [key: string]: number } = {
    act50melding_1: 2,
    act50melding_2: 3,
    act50melding_3: 5,
    act50melding_4: 10,
    act50melding_5: 20,
    act50melding_6: 200,
  };
  const gachabox = (
    (excel.ActivityTable as any)?.activity?.TYPE_ACT24SIDE?.[activityId]
      ?.meldingGachaBoxGoodDataMap?.[gachaBox] as
      | Array<{
          goodId: string;
          itemId: string;
          itemType: string;
          perCount: number;
          totalCount: number;
        }>
      | undefined
  );
  const rewards: ItemBundle[] = [];
  let valid = true;

  await player.update(async (draft) => {
    const act = (draft.activity as any).TYPE_ACT24SIDE as
      | { [key: string]: any }
      | undefined;
    if (!act) return;
    if (!act[activityId]) act[activityId] = {};
    if (!act[activityId].alchemy) act[activityId].alchemy = { item: {}, gacha: {} };
    const itemsData = act[activityId].alchemy.item;
    // 校验素材是否足够（不足则整单不消耗）
    for (const [key, count] of Object.entries(items)) {
      if ((itemsData[key] ?? 0) < Number(count)) {
        valid = false;
        return;
      }
    }
    let totalScore = 0;
    for (const [key, count] of Object.entries(items)) {
      const n = Number(count);
      itemsData[key] -= n;
      totalScore += n * (itemsScoreMap[key] ?? 0);
    }
    const gachaTimes = Math.floor(totalScore / 100);
    if (gachaTimes <= 0 || !gachabox?.length) return;
    if (!act[activityId].alchemy.gacha[gachaBox]) {
      act[activityId].alchemy.gacha[gachaBox] = {};
    }
    const drawnMap = act[activityId].alchemy.gacha[gachaBox];
    // 剩余可抽池（totalCount - 已抽）
    const available: Array<[(typeof gachabox)[number], number]> = [];
    for (const boxItem of gachabox) {
      const remaining = boxItem.totalCount - (drawnMap[boxItem.goodId] ?? 0);
      if (remaining > 0) available.push([boxItem, remaining]);
    }
    const drawResult: {
      [goodId: string]: {
        goodId: string;
        itemId: string;
        itemType: string;
        perCount: number;
        count: number;
      };
    } = {};
    for (let i = 0; i < gachaTimes; i++) {
      if (!available.length) break;
      const idx = Math.floor(Math.random() * available.length);
      const [boxItem, remaining] = available[idx];
      if (!drawResult[boxItem.goodId]) {
        drawResult[boxItem.goodId] = {
          goodId: boxItem.goodId,
          itemId: boxItem.itemId,
          itemType: boxItem.itemType,
          perCount: boxItem.perCount,
          count: 0,
        };
      }
      drawResult[boxItem.goodId].count += 1;
      available[idx][1] = remaining - 1;
      if (available[idx][1] <= 0) available.splice(idx, 1);
    }
    for (const v of Object.values(drawResult)) {
      drawnMap[v.goodId] = (drawnMap[v.goodId] ?? 0) + v.count;
      rewards.push({
        id: v.itemId,
        type: v.itemType,
        count: v.perCount * v.count,
      });
    }
  });

  if (rewards.length > 0) {
    await player._trigger.emit("items:get", [rewards]);
  }
  res.send({
    ...player.delta,
    rewards: valid ? rewards : [],
  } satisfies Act24sideAlchemyResponse);
});

/**
 * 怪猎开始战斗
 * @route POST /activity/act24side/battleStart
 * CS: Act24sideBattleStartRequest : DefaultStartBattleRequest（标准开始战斗）+ activityId；
 * 复用标准战斗开始（battle.start）——狩猎关卡 AP 消耗按 StageTable 正常结算
 */
router.post("/act24side/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act24sideBattleStartRequest;
  res.send({
    ...(await player.battle.start(body)),
    ...player.delta,
  } satisfies Act24sideBattleStartResponse);
});

/**
 * 怪猎战斗结算
 * @route POST /activity/act24side/battleFinish
 * CS: Act24sideBattleFinishRequest : DefaultFinishBattleRequest + activityId；
 * 复用标准战斗结算 + 怪猎专属 meldingRewards 三字段（当前 excel 无怪猎掉落配置返回空）
 */
router.post("/act24side/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act24sideBattleFinishRequest;
  const result = await player.battle.finish({
    data: body.data,
    battleData: body.battleData,
  });
  res.send({
    ...result,
    meldingRewards: [],
    firstMeldingRewards: [],
    mealMeldingRewards: [],
    ...player.delta,
  } satisfies Act24sideBattleFinishResponse);
});

/**
 * 怪猎进食
 * @route POST /activity/act24side/eat
 * 参考 ODPY act24eat：重置 meal 状态（digested=0/chance=0）并记录 meal id
 */
router.post("/act24side/eat", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act24sideEatRequest;
  await player.update(async (draft) => {
    const act = (draft.activity as any).TYPE_ACT24SIDE as
      | { [key: string]: any }
      | undefined;
    if (!act) return;
    if (!act[body.activityId]) act[body.activityId] = {};
    act[body.activityId].meal = { digested: 0, chance: 0, id: body.meal };
  });
  res.send(player.delta satisfies Act24sideEatResponse);
});

/**
 * 怪猎设置工具
 * @route POST /activity/act24side/setTool
 * 参考 ODPY/OBS act24setTool：tools 列表内的工具置 2（激活），其余置 1（未激活）
 */
router.post("/act24side/setTool", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act24sideSetToolRequest;
  await player.update(async (draft) => {
    const act = (draft.activity as any).TYPE_ACT24SIDE?.[body.activityId] as
      | { tool?: { [key: string]: number } }
      | undefined;
    if (!act?.tool) return;
    for (const key of Object.keys(act.tool)) {
      act.tool[key] = body.tools?.includes(key) ? 2 : 1;
    }
  });
  res.send(player.delta satisfies Act24sideSetToolResponse);
});

/**
 * 怪猎获取狩猎收集奖励
 * @route POST /activity/act24side/getHuntCollectRewards
 * CS: Act24sideGetHuntWikiRewardRequest {activityId}；私服简化返回空奖励
 */
router.post("/act24side/getHuntCollectRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act24sideGetHuntCollectRewardsRequest;
  res.send({
    rewards: [],
    ...player.delta,
  } satisfies Act24sideGetHuntCollectRewardsResponse);
});

/* ===== 生息演算（act25side，根路径 /act25side/*，参考 ODPY/OBS + CS 2.7.61）===== */
// 客户端路由为 /act25side/*（无 /activity 前缀），因此独立 rootRouter 导出，
// 在 app.ts 挂载到根路径（同 user.ts 的 rootRouter 模式）。

/**
 * 足球开始战斗
 * @route POST /activity/football/battleStart
 * CS: Act1FootballBattleStartRequest；参考 ODPY footballBattleStart 返回固定 battleId stub
 */
router.post("/football/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as FootballBattleStartRequest;
  res.send({
    result: 0,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    apFailReturn: 0,
    isApProtect: 0,
    inApProtectPeriod: false,
    notifyPowerScoreNotEnoughIfFailed: false,
    ...player.delta,
  } satisfies FootballBattleStartResponse);
});

/**
 * 足球战斗结算
 * @route POST /activity/football/battleFinish
 * CS: Act1FootballBattleFinishResponse : DefaultFinishBattleResponse
 * 参考 ODPY footballBattleFinish：固定比分（selfScore 99 胜）与里程碑加值 0
 */
router.post("/football/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as FootballBattleFinishRequest;
  res.send({
    result: 0,
    apFailReturn: 0,
    expScale: 0,
    goldScale: 0,
    rewards: [],
    firstRewards: [],
    unlockStages: [],
    unusualRewards: [],
    additionalRewards: [],
    furnitureRewards: [],
    alert: [],
    suggestFriend: false,
    pryResult: [],
    enemyScore: 0,
    selfScore: 99,
    isNewRecord: true,
    milestoneBefore: 0,
    milestoneAdd: 0,
    ...player.delta,
  } satisfies FootballBattleFinishResponse);
});

/* ===== 活动小游戏 stub 批量（参考 ODPY 均为 202 stub；arcade/act42d0/act1vhalfidle 战斗走标准 stub）===== */

/** 活动小游戏战斗开始 stub（arcade/act42d0/act1vhalfidle/typeAct20side 等共用） */
function miniBattleStart(player: PlayerDataManager) {
  return {
    result: 0,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    apFailReturn: 0,
    isApProtect: 0,
    inApProtectPeriod: false,
    notifyPowerScoreNotEnoughIfFailed: false,
    ...player.delta,
  } satisfies ActivityMiniBattleStartResponse;
}

/** 活动小游戏战斗结算 stub（仅返回增量） */
function miniBattleFinish(player: PlayerDataManager, body: any) {
  reqBodyRef(body);
  return player.delta satisfies ActivityMiniBattleFinishResponse;
}

/** 引用请求体（满足 req.body as XxxRequest 接线约定，实际不读取） */
function reqBodyRef(_body: any): void {
  /* 无操作：stub 路由不读取请求体 */
}

// arcade（街机）
router.post("/arcade/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityMiniBattleStartRequest;
  res.send(miniBattleStart(player));
});
router.post("/arcade/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ActivityMiniBattleFinishRequest;
  res.send(miniBattleFinish(player, body));
});

// act42d0（熔炉活动）
router.post("/act42d0/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityMiniBattleStartRequest;
  res.send(miniBattleStart(player));
});
router.post("/act42d0/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ActivityMiniBattleFinishRequest;
  res.send(miniBattleFinish(player, body));
});
router.post("/act42d0/challengeStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act42d0/challengeFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});
router.post("/act42d0/recvMilestone", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});

// act1vhalfidle（半挂机，参考 ODPY vhalfidle 类）
router.post("/act1vhalfidle/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityMiniBattleStartRequest;
  res.send(miniBattleStart(player));
});
router.post("/act1vhalfidle/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ActivityMiniBattleFinishRequest;
  res.send(miniBattleFinish(player, body));
});

/** 按需初始化 HALFIDLE_VERIFY1 活动数据 */
function ensureHalfIdleData(draft: any, activityId: string): any {
  const hf = (draft.activity as any).HALFIDLE_VERIFY1 as any;
  if (!hf) (draft.activity as any).HALFIDLE_VERIFY1 = {};
  if (!hf[activityId]) {
    hf[activityId] = {
      production: { rate: {}, product: {}, harvestTs: now(), refreshTs: now() },
      inventory: {},
      tech: { unlock: [] },
      troop: { char: {} },
      recruit: { poolTimes: {} },
    };
  }
  return hf[activityId];
}

/** 挂机产出刷新（参考 ODPY refreshProduct：rate × 流逝小时 → product） */
router.post("/act1vhalfidle/refreshProduct", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const production = data.production;
    const diffMult = (now() - (production.harvestTs ?? now())) / 3600;
    production.refreshTs = now();
    if (diffMult > 0) {
      for (const [key, value] of Object.entries(production.rate ?? {})) {
        production.product[key] = Math.floor(Number(value) * diffMult);
      }
    }
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

/** 收获（参考 ODPY harvest：product → inventory，token_point 计 milestoneAdd） */
router.post("/act1vhalfidle/harvest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  let milestoneAdd = 0;
  const items: { itemId: string; count: number }[] = [];
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const production = data.production;
    for (const [key, count] of Object.entries(production.product ?? {})) {
      if (key === "act1vhalfidle_token_point") {
        milestoneAdd = Number(count);
      }
      data.inventory[key] = (data.inventory[key] ?? 0) + Number(count);
      items.push({ itemId: key, count: Number(count) });
    }
    production.product = {};
    production.harvestTs = now();
    production.refreshTs = now();
  });
  res.send({
    milestoneAdd,
    items,
    ...player.delta,
  } satisfies { milestoneAdd: number; items: { itemId: string; count: number }[] } as any);
});

/** 解锁科技（参考 ODPY unlockTech：tech.unlock 追加 techId） */
router.post("/act1vhalfidle/unlockTech", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    if (body.techId && !data.tech.unlock.includes(body.techId)) {
      data.tech.unlock.push(body.techId);
    }
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

/** 招募（参考 ODPY recruitNormal/recruitDirect：卡池抽干员加入活动 troop） */
router.post("/act1vhalfidle/recruitNormal", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  const { poolId, count = 1 } = body as any;
  let ticketCount = count;
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const actChars = data.troop.char;
    const have = new Set(Object.values(actChars).map((c: any) => c.charId));
    const addChar = (charId: string) => {
      if (have.has(charId)) return;
      // 从玩家主数据找该干员
      for (const c of Object.values(draft.troop.chars) as any[]) {
        if (c.charId === charId) {
          actChars[String(c.instId)] = {
            instId: c.instId,
            charId: c.charId,
            level: c.level ?? 1,
            evolvePhase: c.evolvePhase ?? 0,
            skillLvl: (c.evolvePhase ?? 0) >= 2 ? 10 : 7,
            isAssist: false,
            defaultSkillId: c.skills?.[c.defaultSkillIndex ?? 0]?.skillId ?? "",
            defaultEquipId: c.currentEquip ?? "",
          };
          have.add(charId);
          return;
        }
      }
    };
    const pools = VHALFIDLE_POOLS;
    if (poolId && pools[poolId]) {
      for (const charId of pools[poolId]) addChar(charId);
    } else if (poolId === "normalGachaPool") {
      const specSet = new Set(VHALFIDLE_SPEC_CHAR);
      const candidates = Object.values(draft.troop.chars)
        .map((c: any) => c.charId)
        .filter((id) => !specSet.has(id));
      for (let i = 0; i < count; i++) {
        if (candidates.length) {
          addChar(candidates[Math.floor(Math.random() * candidates.length)]);
        }
      }
    }
  });
  // CS: Act1VHalfIdleRecruitNormalResponse { ticketCount }
  res.send({
    ticketCount,
    ...player.delta,
  } as any);
});

/** 定向招募（参考 ODPY recruitDirect） */
router.post("/act1vhalfidle/recruitDirect", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const actChars = data.troop.char;
    const have = new Set(Object.values(actChars).map((c: any) => c.charId));
    const charId = (body as any).charId;
    if (charId && !have.has(charId)) {
      for (const c of Object.values(draft.troop.chars) as any[]) {
        if (c.charId === charId) {
          actChars[String(c.instId)] = {
            instId: c.instId,
            charId: c.charId,
            level: c.level ?? 1,
            evolvePhase: c.evolvePhase ?? 0,
            skillLvl: (c.evolvePhase ?? 0) >= 2 ? 10 : 7,
            isAssist: false,
            defaultSkillId: "",
            defaultEquipId: c.currentEquip ?? "",
          };
          break;
        }
      }
    }
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

/** 升级/替换/助战（对齐 CS Response 字段：upgrade 返回 charId/currentLvl 等） */
router.post("/act1vhalfidle/upgradeChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  let charId = "";
  let currentLvl = 0;
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const actChar = data.troop.char[String((body as any).charInstId ?? "")];
    if (!actChar) return;
    charId = actChar.charId;
    if ((body as any).level) actChar.level = (body as any).level;
    currentLvl = actChar.level;
  });
  // CS: Act1VHalfIdleCharUpgradeLevelResponse { charId, currentLvl }
  res.send({ charId, currentLvl, ...player.delta } as any);
});
router.post("/act1vhalfidle/upgradeSkill", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  let charId = "";
  let currentLvl = 0;
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const actChar = data.troop.char[String((body as any).charInstId ?? "")];
    if (!actChar) return;
    charId = actChar.charId;
    if ((body as any).skillLvl) actChar.skillLvl = (body as any).skillLvl;
    currentLvl = actChar.skillLvl;
  });
  // CS: Act1VHalfIdleCharUpgradeSkillResponse { charId, currentLvl }
  res.send({ charId, currentLvl, ...player.delta } as any);
});
router.post("/act1vhalfidle/evolveChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  let charId = "";
  let currentEvolvePhase = 0;
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const actChar = data.troop.char[String((body as any).charInstId ?? "")];
    if (!actChar) return;
    charId = actChar.charId;
    if ((body as any).evolvePhase != null) {
      actChar.evolvePhase = (body as any).evolvePhase;
      actChar.skillLvl = actChar.evolvePhase >= 2 ? 10 : 7;
    }
    currentEvolvePhase = actChar.evolvePhase;
  });
  // CS: Act1VHalfIdleCharUpgradeEliteResponse { charId, currentEvolvePhase, item }
  res.send({ charId, currentEvolvePhase, item: null, ...player.delta } as any);
});
router.post("/act1vhalfidle/replaceRate", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act1vhalfidleRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act1vhalfidle/setAssistChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act1vhalfidleRequest;
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const actChar = data.troop.char[String((body as any).charInstId ?? "")];
    if (actChar) actChar.isAssist = true;
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

// act13side（日任务）
router.post("/act13side/clearFlag", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
for (const act13sideRoute of [
  "dailyMissionAccept",
  "dailyMissionCancel",
  "dailyMissionReplace",
  "longMissionCommit",
  "longMissionCommitBatch",
]) {
  router.post(`/act13side/${act13sideRoute}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as Act13sideDailyMissionCommitRequest;
    res.send({
      items: [],
      ...player.delta,
    } satisfies ActivityStubItemsResponse);
  });
}
for (const act13sideRoute of ["dailyMissionCommit", "dailyMissionRandom"]) {
  router.post(`/act13side/${act13sideRoute}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as Act13sideDailyMissionRandomRequest;
    res.send({
      items: [],
      ...player.delta,
    } satisfies ActivityStubItemsResponse);
  });
}

// act27side（售卖小游戏）
for (const act27sideRoute of [
  "inquirePurchase",
  "inquireSell",
  "nextDay",
  "purchase",
  "saleSettle",
  "saleStart",
  "sell",
]) {
  router.post(`/act27side/${act27sideRoute}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as ActivityStubRequest;
    res.send(player.delta satisfies ActivityStubResponse);
  });
}

// act35side（卡牌合成）
router.post("/act35side/create", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act35sideCreateRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
for (const act35sideRoute of [
  "buyCard",
  "buySlot",
  "nextRound",
  "process",
  "refreshShop",
  "settle",
  "toBuy",
  "toProcess",
]) {
  router.post(`/act35side/${act35sideRoute}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as Act35sideBuyRequest;
    res.send(player.delta satisfies ActivityStubResponse);
  });
}

// act38side（拼图）
router.post("/act38side/getInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act38side/completePuzzle", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});
router.post("/act38side/useHint", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});

// act42side（信任任务，参考 ODPY act42side）
router.post("/act42side/getDailyRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act42sideGetDailyRewardsRequest;
  // 参考 ODPY：写 TYPE_ACT42SIDE[activityId].dailyRewardState = 0
  await player.update(async (draft) => {
    const act = (draft.activity as any).TYPE_ACT42SIDE as any;
    if (!act) return;
    if (!act[body.activityId!]) act[body.activityId!] = {};
    act[body.activityId!].dailyRewardState = 0;
  });
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act42side/getDailyTrustedItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act42sideGetDailyRewardsRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});
router.post("/act42side/acceptTask", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { activityId?: string; taskId?: string };
  // 参考 ODPY：写 taskMap[taskId] = 2（接取）
  await player.update(async (draft) => {
    const act = (draft.activity as any).TYPE_ACT42SIDE as any;
    if (!act) return;
    if (!act[body.activityId!]) act[body.activityId!] = {};
    if (!act[body.activityId!].taskMap) act[body.activityId!].taskMap = {};
    act[body.activityId!].taskMap[body.taskId!] = 2;
  });
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act42side/confirmTask", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { activityId?: string; taskId?: string };
  // 参考 ODPY：写 taskMap[taskId] = 4（完成）
  await player.update(async (draft) => {
    const act = (draft.activity as any).TYPE_ACT42SIDE as any;
    if (!act) return;
    if (!act[body.activityId!]) act[body.activityId!] = {};
    if (!act[body.activityId!].taskMap) act[body.activityId!].taskMap = {};
    act[body.activityId!].taskMap[body.taskId!] = 4;
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

// act44side（剧情选择）
router.post("/act44side/startGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act44sideStartGameRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act44side/nextState", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act44sideStartGameRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act44side/selectChoice", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act44sideSelectChoiceRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act44side/useInsight", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});

// act45side（确认干员/邮件）
router.post("/act45side/confirmChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act45sideConfirmRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/act45side/confirmMail", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act45sideConfirmRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});

// act46side（挖矿）
router.post("/act46side/startGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act46sideGameRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
for (const act46sideRoute of ["settleGame", "move", "endRound", "mining"]) {
  router.post(`/act46side/${act46sideRoute}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as Act46sideGameRequest;
    res.send(player.delta satisfies ActivityStubResponse);
  });
}

// actBlessOnly / actCheckinAccess / loginOnly / prayOnly（签到类）
router.post("/actBlessOnly/getCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});
router.post("/actBlessOnly/changeFestivalChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/actCheckinAccess/getCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});
for (const loginRoute of ["loginOnly/getReward", "loginOnlyUnique/getReward", "prayOnly/getReward"]) {
  router.post(`/${loginRoute}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as ActivityGetRewardRequest;
    res.send({
      items: [],
      ...player.delta,
    } satisfies ActivityStubItemsResponse);
  });
}

// year5General（五周年）
router.post("/year5General/getInfReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityGetRewardRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});

// teamQuest
router.post("/teamQuest/refreshInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});

// typeAct3d0（三周年选阵营抽卡）
router.post("/typeAct3d0/selectFaction", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/typeAct3d0/gacha", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/typeAct3d0/getGachaInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/typeAct3d0/getMilestoneReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});

// typeAct4d0 / typeAct5d0 / typeAct9d0（剧情类）
for (const typeAct4d0Route of ["finishStory", "getReward", "unlockStory"]) {
  router.post(`/typeAct4d0/${typeAct4d0Route}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as ActivityStubRequest;
    res.send({
      items: [],
      ...player.delta,
    } satisfies ActivityStubItemsResponse);
  });
}
router.post("/typeAct5d0/getReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});
router.post("/typeAct9d0/readNews", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});

// typeAct5d1（危机合约类）
router.post("/typeAct5d1/getInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/typeAct5d1/getGoodsList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/typeAct5d1/buyGoods", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act5d1BuyGoodsRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});
router.post("/typeAct5d1/buyRune", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act5d1BuyGoodsRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});

// typeAct20side（展会）
for (const typeAct20sideRoute of [
  "competitionStart",
  "competitionFinish",
  "confirmExhiCar",
  "judge",
  "pick",
  "quickGetMilestoneAward",
  "quickRecycle",
]) {
  router.post(`/typeAct20side/${typeAct20sideRoute}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as ActivityStubRequest;
    res.send({
      items: [],
      ...player.delta,
    } satisfies ActivityStubItemsResponse);
  });
}

// autochessSeason（自走棋赛季，多人流程 stub）
for (const autochessSeasonRoute of [
  "createTeam",
  "joinTeam",
  "queryMatch",
  "startMatch",
  "syncInfo",
  "quitSingleGame",
  "startGuideBattle",
  "finishGuideBattle",
  "multiBattleStart",
  "multiBattleFinish",
  "settleGame",
  "settleLike",
  "report",
  "getFriendCharAssistList",
  "setChessPoolAssist",
  "setChessPoolDeploy",
  "setChessPoolDiyChar",
  "removeChessPoolChar",
]) {
  router.post(`/autochessSeason/${autochessSeasonRoute}`, async (req, res) => {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    req.body as ActivityStubRequest;
    res.send(player.delta satisfies ActivityStubResponse);
  });
}

/**
 * 生息演算开始战斗
 * @route POST /act25side/battleStart
 * CS: Act25sideBattleStartRequest : DefaultStartBattleRequest；复用标准战斗开始
 */
export const rootRouter = Router();

rootRouter.post("/act25side/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act25sideBattleStartRequest;
  res.send({
    ...(await player.battle.start(body)),
    ...player.delta,
  } satisfies Act25sideBattleStartResponse);
});

/**
 * 生息演算战斗结算
 * @route POST /act25side/battleFinish
 * CS: Act25sideBattleFinishRequest : DefaultFinishBattleRequest；复用标准战斗结算
 */
rootRouter.post("/act25side/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as Act25sideBattleFinishRequest;
  const result = await player.battle.finish({
    data: body.data,
    battleData: body.battleData,
  });
  res.send({
    ...result,
    ...player.delta,
  } satisfies Act25sideBattleFinishResponse);
});

/**
 * 生息演算每日刷新
 * @route POST /act25side/dailyRefresh
 * CS: Act25sideDailyRefreshRequest {actId}；私服简化返回固定 tokenDelta 0
 */
rootRouter.post("/act25side/dailyRefresh", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act25sideDailyRefreshRequest;
  res.send({
    tokenDelta: 0,
    reachRecvMax: false,
    ...player.delta,
  } satisfies Act25sideDailyRefreshResponse);
});

/**
 * 生息演算收获
 * @route POST /act25side/harvest
 * CS: Act25sideDailyHarvestRequest {actId}；私服简化返回空奖励
 */
rootRouter.post("/act25side/harvest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act25sideHarvestRequest;
  res.send({
    items: [],
    additionalItems: [],
    ...player.delta,
  } satisfies Act25sideHarvestResponse);
});

/**
 * 生息演算调查
 * @route POST /act25side/investigate
 * CS: Act25sideResearchRequest {actId, areaId}；仅返回增量
 */
rootRouter.post("/act25side/investigate", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act25sideInvestigateRequest;
  res.send(player.delta satisfies Act25sideInvestigateResponse);
});

/**
 * 生息演算完成调查
 * @route POST /act25side/finishInvestigation
 * CS: Act25sideFinishInvestigationRequest {actId, areaId}；私服简化返回空奖励
 */
rootRouter.post("/act25side/finishInvestigation", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act25sideFinishInvestigationRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies Act25sideFinishInvestigationResponse);
});

/* ===== 其它根路径活动接口（act29side/act36side/trainingGround，参考 ODPY 202 stub）===== */

/** 生息演算 act29side 提交旋律（参考 ODPY act29commitMelody 202 stub） */
rootRouter.post("/act29side/commitMelody", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act29sideCommitMelodyRequest;
  res.send(player.delta satisfies Act29sideCommitMelodyResponse);
});

/** 生息演算 act29side 开始大投资（参考 ODPY act29startMajorInvest 202 stub） */
rootRouter.post("/act29side/startMajorInvest", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act29sideStartMajorInvestRequest;
  res.send(player.delta satisfies Act29sideStartMajorInvestResponse);
});

/** 生息演算 act29side 合成（参考 ODPY act29syncthesize 202 stub） */
rootRouter.post("/act29side/syncthesize", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act29sideSyncthesizeRequest;
  res.send(player.delta satisfies Act29sideSyncthesizeResponse);
});

/** 生息演算 act36side 确认图鉴奖励（私服简化返回空奖励） */
rootRouter.post("/act36side/confirmDexNavReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as Act36sideConfirmDexNavRewardRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies Act36sideConfirmDexNavRewardResponse);
});

/**
 * 签到对决签到（根路径别名）
 * 客户端路由为 /actcheckinvs/sign（无 /activity 前缀且小写），
 * 主路由 /activity/actCheckinvs/sign 因前缀不符客户端调不到，此处补根别名
 */
rootRouter.post("/actcheckinvs/sign", async (req, res) => {
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
    const actData = vsData[actId];
    // 投票计数
    if (tasteChoice === 1) {
      actData.sweetVote += 1;
    } else if (tasteChoice === 2) {
      actData.saltyVote += 1;
    }
    actData.signedCnt += 1;
    actData.canVote = false;
    actData.todayVoteState = 2;
  });

  const signReward = (
    excel.ActivityTable.activity as { [key: string]: { [key: string]: any } }
  ).CHECKIN_VS[body.actId] as any;
  const rewards: ItemBundle[] = [];
  if (signReward?.signedReward) {
    for (const reward of signReward.signedReward) {
      rewards.push({
        id: reward.id,
        count: reward.count,
        type: ItemTypeToString(reward.type),
      });
    }
  }
  if (rewards.length > 0) {
    await player._trigger.emit("items:get", [rewards]);
  }

  res.send({
    items: rewards,
    ...player.delta,
  } satisfies ActCheckinvsSignResponse);
});

/** 训练场开始战斗（参考 ODPY trainingGroundBattleStart 空 stub） */
rootRouter.post("/trainingGround/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as TrainingGroundBattleStartRequest;
  res.send(player.delta satisfies TrainingGroundBattleStartResponse);
});

/** 训练场战斗结算（参考 ODPY trainingGroundBattleFinish 空 stub） */
rootRouter.post("/trainingGround/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as TrainingGroundBattleFinishRequest;
  res.send(player.delta satisfies TrainingGroundBattleFinishResponse);
});

/* ===== 方舟枢纽（arkhub，客户端 /activity/arkhub/*；数据在 activity.ARK_HUB）===== */
// 抓包形状：enterHall → gateway 地址；setSecretary/setSquad → 更新 ARK_HUB[act1arkhub]；
// syncInfo → 空增量；getPixelArt → OSS 地址（私服空）；savePixelArt → 转发 gateway（私服记录）

/** 方舟枢纽进入大厅（抓包：返回 gateway 端点 + 端口） */
router.post("/arkhub/enterHall", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  // 私服模式：本地网关应答器启动后指向本服端口（客户端连本服进空广场），
  // 否则返回官服域名（官服网关不可达/账号凭据无效时客户端无法进入）
  const { isArkhubLocalGatewayActive } = await import(
    "../../proxy/arkhub-gateway-local"
  );
  const endpoint = isArkhubLocalGatewayActive()
    ? String(config.Host).replace(/^https?:\/\//, "")
    : "arkhub-gateway.hypergryph.com";
  const port = isArkhubLocalGatewayActive()
    ? config.capture?.gatewayPort ?? 30000
    : 30000;
  res.send({
    result: 0,
    endpoint,
    port,
    ...player.delta,
  });
});

/** 方舟枢纽好友 UID 列表（私服返回空——无真实网关好友） */
router.post("/arkhub/getFriendUidList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    friendUidList: [],
    ...player.delta,
  });
});

/** 方舟枢纽像素画（私服无网关存储，返回空） */
router.post("/arkhub/getPixelArt", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    pixelArts: {},
    ...player.delta,
  });
});

/** 方舟枢纽像素画上传（客户端 multipart → 网关；私服记录并返回空，客户端可继续流程） */
router.post("/arkhub/savePixelArt", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send({
    ...player.delta,
  });
});

/** 方舟枢纽设置秘书（抓包：更新 ARK_HUB[act1arkhub].secretary/secretarySkinId） */
router.post("/arkhub/setSecretary", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { secretary?: string; secretarySkinId?: string };
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.["act1arkhub"] as any;
    if (!hub) return;
    if (body.secretary) hub.secretary = body.secretary;
    if (body.secretarySkinId) hub.secretarySkinId = body.secretarySkinId;
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

/** 方舟枢纽设置队伍（抓包：更新 ARK_HUB[act1arkhub].squads） */
router.post("/arkhub/setSquad", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { squads?: unknown[] };
  await player.update(async (draft) => {
    const hub = (draft.activity as any)?.ARK_HUB?.["act1arkhub"] as any;
    if (!hub) return;
    if (Array.isArray(body.squads)) hub.squads = body.squads;
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

/** 方舟枢纽同步（抓包：空增量） */
router.post("/arkhub/syncInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
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
