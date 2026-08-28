/**
 * 活动路由：act24side（由 router/activity.ts 拆分而来，实现未改动）
 */
import { Router } from "express";
import * as ReqSchema from "../shared/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../kernel/http/request-context";
import { ItemBundle, ItemType } from "@excel/excel";
import excel from "@excel/excel";
import { activityDictKey } from "../shared/unlockActivity";
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
} from "../shared/activity";
import { validateBody } from "../../../kernel/http/validate-body";

const router = Router();
router.post("/act24side/alchemy", validateBody(ReqSchema.act24sideAlchemySchema), async (req, res) => {
  const player = getPlayer();
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
  // 修复：excel activity 字典键为首字母小写（tYPE_ACT24SIDE）——原枚举大小写恒 undefined
  const gachabox = (
    (excel.ActivityTable as any)?.activity?.[
      activityDictKey("TYPE_ACT24SIDE") ?? "tYPE_ACT24SIDE"
    ]?.[activityId]
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
      rewards.push({ id: v.itemId, type: v.itemType as ItemType, count: v.perCount * v.count,
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

router.post("/act24side/battleStart", validateBody(ReqSchema.act24sideBattleStartSchema), async (req, res) => {
  const player = getPlayer();
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

router.post("/act24side/battleFinish", validateBody(ReqSchema.act24sideBattleFinishSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act24sideBattleFinishRequest;
  // 缺参校验：battle data 缺失时返回业务错误
  if (body.data == null) {
    return res.send({ result: 1, ...player.delta });
  }
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

router.post("/act24side/eat", validateBody(ReqSchema.act24sideEatSchema), async (req, res) => {
  const player = getPlayer();
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

router.post("/act24side/setTool", validateBody(ReqSchema.act24sideSetToolSchema), async (req, res) => {
  const player = getPlayer();
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

router.post("/act24side/getHuntCollectRewards", validateBody(ReqSchema.act24sideGetHuntCollectRewardsSchema), async (req, res) => {
  const player = getPlayer();
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
export default router;
