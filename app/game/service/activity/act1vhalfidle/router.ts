/**
 * 活动路由：act1vhalfidle（由 router/activity.ts 拆分而来，实现未改动）
 */
import { Router } from "express";
import { miniBattleStart, miniBattleFinish } from "../shared";
import * as ReqSchema from "../../../domain/contracts/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../request-context";
import { now } from "@utils/time";
import { VHALFIDLE_POOLS, VHALFIDLE_SPEC_CHAR } from "../../../domain/data/vhalfidle";
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
router.post("/act1vhalfidle/battleStart", validateBody(ReqSchema.activityMiniBattleStartSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityMiniBattleStartRequest;
  res.send(miniBattleStart(player));
});

router.post("/act1vhalfidle/battleFinish", validateBody(ReqSchema.activityMiniBattleFinishSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as ActivityMiniBattleFinishRequest;
  res.send(miniBattleFinish(player, body));
});

/** 按需初始化 HALFIDLE_VERIFY1 活动数据 */
function ensureHalfIdleData(draft: any, activityId: string): any {
  // 修复：draft.activity / HALFIDLE_VERIFY1 缺失时可能为 undefined，先兜底再重读引用，
  // 避免赋值后本地变量仍为 undefined，导致 hf[activityId] 抛「reading 'undefined'」500。
  if (!draft.activity) draft.activity = {};
  if (!draft.activity.HALFIDLE_VERIFY1) {
    draft.activity.HALFIDLE_VERIFY1 = {};
  }
  const hf = draft.activity.HALFIDLE_VERIFY1;
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

router.post("/act1vhalfidle/refreshProduct", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
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

router.post("/act1vhalfidle/harvest", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
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

router.post("/act1vhalfidle/unlockTech", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    if (body.techId && !data.tech.unlock.includes(body.techId)) {
      data.tech.unlock.push(body.techId);
    }
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

/** 招募（参考 ODPY recruitNormal/recruitDirect：卡池抽干员加入活动 troop） */

router.post("/act1vhalfidle/recruitNormal", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
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

router.post("/act1vhalfidle/recruitDirect", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
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

router.post("/act1vhalfidle/upgradeChar", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
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

router.post("/act1vhalfidle/upgradeSkill", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
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

router.post("/act1vhalfidle/evolveChar", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
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

router.post("/act1vhalfidle/replaceRate", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  req.body as Act1vhalfidleRequest;
  res.send(player.delta satisfies ActivityStubResponse);
});

router.post("/act1vhalfidle/setAssistChar", validateBody(ReqSchema.act1vhalfidleSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as Act1vhalfidleRequest;
  if (!body.activityId) return res.send({ result: 1, ...player.delta });
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const actChar = data.troop.char[String((body as any).charInstId ?? "")];
    if (actChar) actChar.isAssist = true;
  });
  res.send(player.delta satisfies ActivityStubResponse);
});

// act13side（日任务）
export default router;
