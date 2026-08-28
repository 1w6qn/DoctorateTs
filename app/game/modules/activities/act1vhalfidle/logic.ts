/**
 * 活动路由：act1vhalfidle（由 router/activity.ts 拆分而来，实现未改动）
 */
import { Router } from "express";
import { miniBattleStart, miniBattleFinish } from "../shared/shared";
import * as ReqSchema from "../shared/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../kernel/http/request-context";
import { now } from "@utils/time";
import { VHALFIDLE_POOLS, VHALFIDLE_SPEC_CHAR } from "./vhalfidle";
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
import { PlayerDataManager } from "../../../kernel/PlayerDataManager";

/**
 * act1vhalfidle 活动族业务逻辑（建议 11：族包五件套——router 仅路由注册，业务收敛于 logic）
 *
 * 由 router.ts 内联 handler 提取（实现未改动）：每个活动接口一个具名函数，
 * 输入 player + 请求体，返回响应对象（原 res.send 载荷）。
 */

export async function handleAct1vhalfidlebattleStart(player: PlayerDataManager, body: ActivityMiniBattleStartRequest) {
  return (miniBattleStart(player));
}

export async function handleAct1vhalfidlebattleFinish(player: PlayerDataManager, body: ActivityMiniBattleFinishRequest) {
  return (miniBattleFinish(player, body));
}

export async function handleAct1vhalfidlerefreshProduct(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
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
  return (player.delta satisfies ActivityStubResponse);
}

export async function handleAct1vhalfidleharvest(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
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
  return ({
    milestoneAdd,
    items,
    ...player.delta,
  } satisfies { milestoneAdd: number; items: { itemId: string; count: number }[] } as any);
}

export async function handleAct1vhalfidleunlockTech(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    if (body.techId && !data.tech.unlock.includes(body.techId)) {
      data.tech.unlock.push(body.techId);
    }
  });
  return (player.delta satisfies ActivityStubResponse);
}

export async function handleAct1vhalfidlerecruitNormal(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
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
  return ({
    ticketCount,
    ...player.delta,
  } as any);
}

export async function handleAct1vhalfidlerecruitDirect(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
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
  return (player.delta satisfies ActivityStubResponse);
}

export async function handleAct1vhalfidleupgradeChar(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
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
  return ({ charId, currentLvl, ...player.delta } as any);
}

export async function handleAct1vhalfidleupgradeSkill(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
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
  return ({ charId, currentLvl, ...player.delta } as any);
}

export async function handleAct1vhalfidleevolveChar(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
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
  return ({ charId, currentEvolvePhase, item: null, ...player.delta } as any);
}

export async function handleAct1vhalfidlereplaceRate(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  return (player.delta satisfies ActivityStubResponse);
}

export async function handleAct1vhalfidlesetAssistChar(player: PlayerDataManager, body: Act1vhalfidleRequest) {
  if (!body.activityId) return ({ result: 1, ...player.delta });
  await player.update(async (draft) => {
    const data = ensureHalfIdleData(draft, body.activityId!);
    const actChar = data.troop.char[String((body as any).charInstId ?? "")];
    if (actChar) actChar.isAssist = true;
  });
  return (player.delta satisfies ActivityStubResponse);
}

// ===== 顶层辅助函数（由 router.ts 拆分时保留，原样迁移）=====

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

export default router;
