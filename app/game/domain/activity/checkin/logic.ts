/**
 * 活动路由：checkin（由 router/activity.ts 拆分而来，实现未改动）
 */
import { Router } from "express";
import { ItemTypeToString } from "../shared";
import * as ReqSchema from "../../../domain/activity/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../request-context";
import { ItemBundle, ItemType } from "@excel/excel";
import excel from "@excel/excel";
import { now } from "@utils/time";
import { activityDictKey } from "@game/service/player/unlockActivity";
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
import { PlayerDataManager } from "@game/service/PlayerDataManager";

/**
 * checkin 活动族业务逻辑（建议 11：族包五件套——router 仅路由注册，业务收敛于 logic）
 *
 * 由 router.ts 内联 handler 提取（实现未改动）：每个活动接口一个具名函数，
 * 输入 player + 请求体，返回响应对象（原 res.send 载荷）。
 */

export async function handleGetChainLogInReward(player: PlayerDataManager, body: GetChainLogInRewardRequest) {
  return ({
    reward: await player.openServer.getChainLogInReward(body),
    ...player.delta,
  } satisfies GetChainLogInRewardResponse);
}

export async function handleGetChainLogInFinalRewards(player: PlayerDataManager, body: GetChainLogInFinalRewardsRequest) {
  return ({
    reward: await player.openServer.getChainLogInFinalRewards(),
    ...player.delta,
  } satisfies GetChainLogInFinalRewardsResponse);
}

export async function handleGetOpenServerCheckInReward(player: PlayerDataManager, body: GetOpenServerCheckInRewardRequest) {
  // 读类缺参校验：index 为必填，缺失时返回业务错误
  if (body.index == null) {
    return ({ result: 1, ...player.delta });
  }
  return ({
    reward: await player.openServer.getCheckInReward(body),
    ...player.delta,
  } satisfies GetOpenServerCheckInRewardResponse);
}

export async function handleGetActivityCheckInReward(player: PlayerDataManager, body: GetActivityCheckInRewardRequest) {
  // 缺参校验：activityId/index 为必填，缺失时返回业务错误
  if (body.activityId == null || body.index == null) {
    return ({ result: 1, ...player.delta });
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
   return ({
    ...player.delta,
    items: [],
  } satisfies GetActivityCheckInRewardResponse);
}

export async function handleActCheckinvssign(player: PlayerDataManager, body: ActCheckinvsSignRequest) {
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
   return ({
    ...player.delta,
    items: [
      { type: "AP_SUPPLY" as ItemType, id: "ap_supply_lt_120", count: 1 },
      { type: "GOLD" as ItemType, id: "4001", count: 30000 },
    ],
  } satisfies ActCheckinvsSignResponse);
}

export async function handleGetSwitchOnlyReward(player: PlayerDataManager, body: GetSwitchOnlyRewardRequest) {
   await player.update(async (draft) => {
    const activityId = body.activityId;
    const rewardId = body.reward;
     const switchData = draft.activity.SWITCH_ONLY as any;
    if (!switchData[activityId]) {
      switchData[activityId] = {};
    }
    switchData[activityId][rewardId] = 0;
  });
   return (player.delta satisfies GetSwitchOnlyRewardResponse);
}

export async function handleGetCheckInReward(player: PlayerDataManager, body: GetCheckInRewardRequest) {
   const activityId = body.activityId;
  // 缺参校验：activityId 为必填，缺失时返回业务错误（避免 activityId.endsWith 抛 TypeError → 500）
  if (activityId == null) {
    return ({ result: 1, ...player.delta });
  }
   if (activityId.endsWith("access")) {
    const REWARDS: ItemBundle[] = [
      { type: "AP_SUPPLY" as ItemType, id: "ap_supply_lt_80", count: 1 },
      { type: "DIAMOND_SHD" as ItemType, id: "4003", count: 200 },
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
    return ({
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
     return ({
      ...player.delta,
      items: [],
    } satisfies GetCheckInRewardResponse);
  } else {
    return ({
      ...player.delta,
      items: [],
    } satisfies GetCheckInRewardResponse);
  }
}

export async function handleChangeFestivalChar(player: PlayerDataManager, body: ChangeFestivalCharRequest) {
  // 缺参校验：activityId/index/newChar 缺失时返回业务错误
  if (body.activityId == null || body.index == null || body.newChar == null) {
    return ({ result: 1, ...player.delta });
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
   return (player.delta satisfies ChangeFestivalCharResponse);
}

export async function handleActBlessOnlygetCheckInReward(player: PlayerDataManager, body: ActivityStubRequest) {
  return ({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
}

export async function handleActBlessOnlychangeFestivalChar(player: PlayerDataManager, body: ActivityStubRequest) {
  return (player.delta satisfies ActivityStubResponse);
}

export async function handleActCheckinAccessgetCheckInReward(player: PlayerDataManager, body: ActivityStubRequest) {
  return ({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
}

export async function handleYear5GeneralgetInfReward(player: PlayerDataManager, body: ActivityGetRewardRequest) {
  return ({
    items: [],
    ...player.delta,
  } satisfies ActivityStubItemsResponse);
}

// ===== 顶层辅助函数（由 router.ts 拆分时保留，原样迁移）=====

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
        type: ItemTypeToString(reward.type) as ItemType,
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

export default router;
