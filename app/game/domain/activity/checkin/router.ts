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
import { handleGetChainLogInReward, handleGetChainLogInFinalRewards, handleGetOpenServerCheckInReward, handleGetActivityCheckInReward, handleActCheckinvssign, handleGetSwitchOnlyReward, handleGetCheckInReward, handleChangeFestivalChar, handleActBlessOnlygetCheckInReward, handleActBlessOnlychangeFestivalChar, handleActCheckinAccessgetCheckInReward, handleYear5GeneralgetInfReward } from "./logic";

router.post("/getChainLogInReward", validateBody(ReqSchema.getChainLogInRewardSchema), async (req, res) => {
  res.send(await handleGetChainLogInReward(getPlayer(), req.body as GetChainLogInRewardRequest));
});

router.post("/getChainLogInFinalRewards", validateBody(ReqSchema.getChainLogInFinalRewardsSchema), async (req, res) => {
  res.send(await handleGetChainLogInFinalRewards(getPlayer(), req.body as GetChainLogInFinalRewardsRequest));
});

router.post("/getOpenServerCheckInReward", validateBody(ReqSchema.getOpenServerCheckInRewardSchema), async (req, res) => {
  res.send(await handleGetOpenServerCheckInReward(getPlayer(), req.body as GetOpenServerCheckInRewardRequest));
});

router.post("/getActivityCheckInReward", validateBody(ReqSchema.getActivityCheckInRewardSchema), async (req, res) => {
  res.send(await handleGetActivityCheckInReward(getPlayer(), req.body as GetActivityCheckInRewardRequest));
});

router.post("/actCheckinvs/sign", validateBody(ReqSchema.actCheckinvsSignSchema), async (req, res) => {
  res.send(await handleActCheckinvssign(getPlayer(), req.body as ActCheckinvsSignRequest));
});

router.post("/getSwitchOnlyReward", validateBody(ReqSchema.getSwitchOnlyRewardSchema), async (req, res) => {
  res.send(await handleGetSwitchOnlyReward(getPlayer(), req.body as GetSwitchOnlyRewardRequest));
});

router.post("/getCheckInReward", validateBody(ReqSchema.getCheckInRewardSchema), async (req, res) => {
  res.send(await handleGetCheckInReward(getPlayer(), req.body as GetCheckInRewardRequest));
});

router.post("/changeFestivalChar", validateBody(ReqSchema.changeFestivalCharSchema), async (req, res) => {
  res.send(await handleChangeFestivalChar(getPlayer(), req.body as ChangeFestivalCharRequest));
});

router.post("/actBlessOnly/getCheckInReward", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  res.send(await handleActBlessOnlygetCheckInReward(getPlayer(), req.body as ActivityStubRequest));
});

router.post("/actBlessOnly/changeFestivalChar", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  res.send(await handleActBlessOnlychangeFestivalChar(getPlayer(), req.body as ActivityStubRequest));
});

router.post("/actCheckinAccess/getCheckInReward", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  res.send(await handleActCheckinAccessgetCheckInReward(getPlayer(), req.body as ActivityStubRequest));
});

router.post("/year5General/getInfReward", validateBody(ReqSchema.activityGetRewardSchema), async (req, res) => {
  res.send(await handleYear5GeneralgetInfReward(getPlayer(), req.body as ActivityGetRewardRequest));
});

export default router;

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

/** 训练场开始战斗（参考 ODPY trainingGroundBattleStart 空 stub） */
