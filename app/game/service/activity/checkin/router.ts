/**
 * 活动路由：checkin（由 router/activity.ts 拆分而来，实现未改动）
 */
import { Router } from "express";
import { ItemTypeToString } from "../shared";
import * as ReqSchema from "../../../domain/activity/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../request-context";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { now } from "@utils/time";
import { activityDictKey } from "../../player/unlockActivity";
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
} from "../../../domain/activity/activity";
import { validateBody } from "../../../domain/contracts/validate-body";

const router = Router();
router.post("/getChainLogInReward", validateBody(ReqSchema.getChainLogInRewardSchema), async (req, res) => {
  const player = getPlayer();
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

router.post("/getChainLogInFinalRewards", validateBody(ReqSchema.getChainLogInFinalRewardsSchema), async (req, res) => {
  const player = getPlayer();
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

router.post("/getOpenServerCheckInReward", validateBody(ReqSchema.getOpenServerCheckInRewardSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as GetOpenServerCheckInRewardRequest;
  // 读类缺参校验：index 为必填，缺失时返回业务错误
  if (body.index == null) {
    return res.send({ result: 1, ...player.delta });
  }
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

router.post("/getActivityCheckInReward", validateBody(ReqSchema.getActivityCheckInRewardSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as GetActivityCheckInRewardRequest;
  // 缺参校验：activityId/index 为必填，缺失时返回业务错误
  if (body.activityId == null || body.index == null) {
    return res.send({ result: 1, ...player.delta });
  }

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

router.post("/actCheckinvs/sign", validateBody(ReqSchema.actCheckinvsSignSchema), async (req, res) => {
  const player = getPlayer();
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

router.post("/getSwitchOnlyReward", validateBody(ReqSchema.getSwitchOnlyRewardSchema), async (req, res) => {
  const player = getPlayer();
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

router.post("/getCheckInReward", validateBody(ReqSchema.getCheckInRewardSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as GetCheckInRewardRequest;

  const activityId = body.activityId;
  // 缺参校验：activityId 为必填，缺失时返回业务错误（避免 activityId.endsWith 抛 TypeError → 500）
  if (activityId == null) {
    return res.send({ result: 1, ...player.delta });
  }

  if (activityId.endsWith("access")) {
    const REWARDS: ItemBundle[] = [
      { type: "AP_SUPPLY", id: "ap_supply_lt_80", count: 1 },
      { type: "DIAMOND_SHD", id: "4003", count: 200 },
    ];
    let already = false;
    await player.update(async (draft) => {
      if (!draft.activity.CHECKIN_ACCESS[activityId]) {
        draft.activity.CHECKIN_ACCESS[activityId] = {
          rewardsCount: 0,
          currentStatus: 0,
          lastTs: 0,
        };
      }
      const data = (draft.activity as any).CHECKIN_ACCESS[activityId];
      // 修复：每日限领一次（原实现 rewardsCount 无限累加、无任何限制）
      const dayKey = Math.floor(Date.now() / 86400000);
      if (Math.floor((data.lastTs || 0) / 86400000) === dayKey) {
        already = true;
        return;
      }
      data.rewardsCount++;
      data.lastTs = Math.floor(Date.now() / 1000);
    });

    // 修复：奖励入账（原实现只回显 items 从不 emit items:get → 领了但没到账）
    if (!already) {
      await player._trigger.emit("items:get", [REWARDS]);
    }
    res.send({
      ...player.delta,
      items: already ? [] : REWARDS,
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

router.post("/changeFestivalChar", validateBody(ReqSchema.changeFestivalCharSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as ChangeFestivalCharRequest;
  // 缺参校验：activityId/index/newChar 缺失时返回业务错误
  if (body.activityId == null || body.index == null || body.newChar == null) {
    return res.send({ result: 1, ...player.delta });
  }

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

router.post("/actBlessOnly/getCheckInReward", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});

router.post("/actBlessOnly/changeFestivalChar", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityStubRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});

router.post("/actCheckinAccess/getCheckInReward", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityStubRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});
for (const loginRoute of ["loginOnly/getReward", "loginOnlyUnique/getReward", "prayOnly/getReward"]) {
  router.post(`/${loginRoute}`, validateBody(ReqSchema.activityGetRewardSchema), async (req, res) => {
    const player = getPlayer();
    req.body as ActivityGetRewardRequest;
    res.send({
      items: [],
      ...player.delta,
    } satisfies ActivityStubItemsResponse);
  });
}

// year5General（五周年）

router.post("/year5General/getInfReward", validateBody(ReqSchema.activityGetRewardSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityGetRewardRequest;
  res.send({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
});

// teamQuest
export const rootRouter = Router();
rootRouter.post("/actcheckinvs/sign", validateBody(ReqSchema.actCheckinvsSignSchema), async (req, res) => {
  const player = getPlayer();
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
    // 修复：签到次数限制（availSignCnt 未校验 → 无限签到刷奖励）
    if ((actData.signedCnt ?? 0) >= (actData.availSignCnt ?? 1)) {
      return;
    }
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

  // 修复：excel activity 字典键大小写随数据版本多变（cHECKIN_VS 旧坏键/checkinVs 规范键）
  // ——动态查键，不再依赖固定大小写
  const checkinVsKey = activityDictKey("CHECKIN_VS") ?? "cHECKIN_VS";
  const signReward = (
    excel.ActivityTable.activity as { [key: string]: { [key: string]: any } }
  )[checkinVsKey]?.[body.actId] as any;
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
export default router;
