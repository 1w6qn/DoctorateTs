/**
 * 活动路由：milestone（由 router/activity.ts 拆分而来，实现未改动）
 */
import { Router } from "express";
import { confirmOneActivityMission, autoConfirmActivityMissionsIn, ItemTypeToString } from "../shared";
import * as ReqSchema from "../../../domain/contracts/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../request-context";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { logger } from "@utils/logger";
import { activityDictKey } from "../../manager/activity/unlockActivity";
import { recordPurchase } from "../../../domain/util/purchase-record";
import {
  informantNextState,
  informantSelectChoice,
  informantStartGame,
  informantUseInsight,
  resolveAct44Data,
} from "../act44side/informant";
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
  Act44sideNextStateRequest,
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
} from "../../../domain/contracts/activity";
import { validateBody } from "../../../domain/contracts/validate-body";

const router = Router();
router.post("/rewardMilestone", validateBody(ReqSchema.rewardMilestoneSchema), async (req, res) => {
  const player = getPlayer();
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
    // act44side（「墟」情报屋）：领取状态写 TYPE_ACT44SIDE[actId].milestone.got
    //（客户端读该字段而非 MILESTONE_ONLY），并按 mileStoneList 配置发放 rewardItem；
    // point 未达 needPointCnt 时防御性拒绝（正常仅达标项可点）
    const act44 = (draft.activity as any).TYPE_ACT44SIDE?.[body.activityId] as
      | { milestone?: { point?: number; got?: string[] } }
      | undefined;
    if (act44?.milestone && body.milestoneId) {
      if (!Array.isArray(act44.milestone.got)) act44.milestone.got = [];
      if (act44.milestone.got.includes(body.milestoneId)) return;
      const ms = resolveAct44Data(body.activityId)?.mileStoneList?.find(
        (m) => m.mileStoneId === body.milestoneId,
      );
      if (!ms || (act44.milestone.point ?? 0) < (ms.needPointCnt ?? 0)) {
        logger.warn(
          "Act44side",
          `里程碑不可领 milestoneId=${body.milestoneId} point=${act44.milestone.point}`,
        );
        return;
      }
      act44.milestone.got.push(body.milestoneId);
      if (ms.rewardItem) rewards.push(ms.rewardItem);
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

  // act44side 奖励入账（与既有领奖路由一致：emit items:get 落库存）
  if (rewards.length > 0) {
    await player._trigger.emit("items:get", [rewards]);
  }

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

router.post("/rewardAllMilestone", validateBody(ReqSchema.rewardAllMilestoneSchema), async (req, res) => {
  const player = getPlayer();
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

router.post("/confirmActivityMission", validateBody(ReqSchema.confirmActivityMissionSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as ConfirmActivityMissionRequest;
  const rewards = await confirmOneActivityMission(player, body.missionId);

  res.send({
    ...player.delta,
    items: rewards,
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

router.post("/confirmActivityMissionList", validateBody(ReqSchema.confirmActivityMissionListSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as ConfirmActivityMissionListRequest;
  const allRewards: ItemBundle[] = [];

  // 与单条版共用 confirmOneActivityMission（此前列表版为复制体，漏做了
  // act1arkhub_token_seal → ARK_HUB.coin/tshop.coin 同步，行为已分叉——现统一）
  for (const missionId of body.missionIdList || []) {
    allRewards.push(
      ...(await confirmOneActivityMission(player, missionId, {
        tolerateFailure: true,
      })),
    );
  }

  res.send({
    ...player.delta,
    items: allRewards,
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

router.post("/confirmActivityMissionGroup", validateBody(ReqSchema.confirmActivityMissionGroupSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as ConfirmActivityMissionGroupRequest;
  let rewards: ItemBundle[] = [];

  // 修复：同 confirmActivityMission——按 MissionTable.missionGroups 归属分流，
  // 避免原 try/catch 依赖 confirmMissionGroup 抛错触发兜底（其已改为未知组静默返回）
  if (excel.MissionTable.missionGroups[body.missionGroupId]) {
    try {
      await player.mission.confirmMissionGroup({
        missionGroupId: body.missionGroupId,
      });
    } catch {
      logger.warn(
        "activity",
        `confirmMissionGroup ${body.missionGroupId} 失败，跳过`,
      );
    }
  } else {
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
    items: rewards,
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

router.post("/autoConfirmMissions", validateBody(ReqSchema.autoConfirmMissionsSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as AutoConfirmMissionsRequest;
  const allRewards: ItemBundle[] = [];

  // 活动任务（ACTIVITY）：MissionManager 不跟踪运行时播种的活动任务（无 MissionProgress
  // 实例），且 confirmMission 对 state==2 的任务不发放 → 原 try 路径返回空且不抛错，
  // catch 兜底死代码 → 活动任务自动领取失效；ACTIVITY 类型直接走手动遍历
  if (body.type === "ACTIVITY") {
    allRewards.push(...(await autoConfirmActivityMissionsIn(player, "ACTIVITY")));
    if (allRewards.length > 0) {
      await player._trigger.emit("items:get", [allRewards]);
    }
  } else {
    try {
      const items = await player.mission.autoConfirmMissions({
        type: body.type,
      });
      allRewards.push(...items);
    } catch {
      // 兜底逻辑：直接遍历玩家数据中的任务
      allRewards.push(
        ...(await autoConfirmActivityMissionsIn(player, body.type)),
      );
      if (allRewards.length > 0) {
        await player._trigger.emit("items:get", [allRewards]);
      }
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

router.post("/exchangeActivityShopItem", validateBody(ReqSchema.exchangeActivityShopItemSchema), async (req, res) => {
  const player = getPlayer();
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
    // 记录购买（与 shop.SOCIAL.info / crisis.shop.info 同一「存在累加否则追加」语义，
    // 共享实现见 @game/util/purchase-record）
    recordPurchase(shop.info, body.goodId, count);
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

router.post("/getActivityCollectionReward", validateBody(ReqSchema.getActivityCollectionRewardSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as GetActivityCollectionRewardRequest;
  const rewards: ItemBundle[] = [];
  let claimed = false;

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
    // 修复：已领取过的收集奖励不再发放（原实现写标记但从不读 → 可重复领）
    if (body.collectionId != null && collectionData[body.activityId][body.collectionId] !== undefined) {
      claimed = true;
      return;
    }
    // 从配置表查找收集奖励
    // 修复：excel activity 字典键大小写随数据版本多变（cOLLECTION 旧坏键/collection 规范键）
    // ——动态查键，不再依赖固定大小写
    const collectionKey = activityDictKey("COLLECTION") ?? "cOLLECTION";
    const collectionConfig = (
      excel.ActivityTable.activity as {
        [key: string]: {
          [key: string]: {
            collections?: { id: string; itemId: string; itemCnt: number }[];
          };
        };
      }
    )[collectionKey]?.[body.activityId];
    if (
      collectionConfig &&
      collectionConfig.collections &&
      body.collectionId != null
    ) {
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

  if (!claimed && rewards.length > 0) {
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

router.post("/getActivityShopInfo", validateBody(ReqSchema.getActivityShopInfoSchema), async (req, res) => {
  const player = getPlayer();
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
export default router;
