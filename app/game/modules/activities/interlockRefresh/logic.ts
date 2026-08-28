/**
 * 活动路由：interlockRefresh（由 router/activity.ts 拆分而来，实现未改动）
 */
import { Router } from "express";
import * as ReqSchema from "../shared/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../kernel/http/request-context";
import { ItemBundle, ItemType } from "@excel/excel";
import excel from "@excel/excel";
import { logger } from "@utils/logger";
import config from "@core/config/index";
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
 * interlockRefresh 活动族业务逻辑（建议 11：族包五件套——router 仅路由注册，业务收敛于 logic）
 *
 * 由 router.ts 内联 handler 提取（实现未改动）：每个活动接口一个具名函数，
 * 输入 player + 请求体，返回响应对象（原 res.send 载荷）。
 */

export async function handleInterlockrefreshSquad(player: PlayerDataManager, body: ActivityStubRequest) {
  return (player.delta satisfies ActivityStubResponse);
}

// ===== 顶层辅助函数（由 router.ts 拆分时保留，原样迁移）=====

async function confirmOneActivityMission(
  player: PlayerDataManager,
  missionId: string,
  opts: { tolerateFailure?: boolean } = {},
): Promise<ItemBundle[]> {
  const rewards: ItemBundle[] = [];
  if (excel.MissionTable.missions[missionId]) {
    try {
      const items = await player.mission.confirmMission({ missionId });
      rewards.push(...items);
    } catch (e) {
      if (!opts.tolerateFailure) throw e;
      logger.warn("activity", `confirmMission ${missionId} 失败，跳过`);
    }
    return rewards;
  }
  // 兜底逻辑：从 ActivityTable.missionData 中查找任务奖励
  const missionInfo = excel.ActivityTable.missionData.find(
    (m) => m.id === missionId,
  );
  if (!missionInfo) return rewards;
  for (const reward of missionInfo.rewards) {
    rewards.push({
      id: reward.id,
      count: reward.count,
      type: ItemTypeToString(reward.type) as ItemType,
    });
  }
  await player.update(async (draft) => {
    const activityMissions = (draft.mission as any).missions["ACTIVITY"];
    if (activityMissions && activityMissions[missionId]) {
      activityMissions[missionId].state = 3;
    }
    // 枢纽任务奖励 → ARK_HUB.coin / tshop.shop_act1arkhub.coin 同步（官服形状，
    // 与 mission manager 的 _confirmActivityTableMission 保持一致）
    const seal = missionInfo.rewards.find(
      (r) => r.id === "act1arkhub_token_seal",
    );
    if (seal?.count) {
      const hub = (draft.activity as any)?.ARK_HUB?.act1arkhub;
      if (hub) hub.coin = (hub.coin ?? 0) + seal.count;
      const shop = (draft.tshop as any)?.["shop_act1arkhub"];
      if (shop) shop.coin = (shop.coin ?? 0) + seal.count;
    }
  });
  await player._trigger.emit("items:get", [rewards]);
  return rewards;
}

async function autoConfirmActivityMissionsIn(
  player: PlayerDataManager,
  group: string,
): Promise<ItemBundle[]> {
  const rewards: ItemBundle[] = [];
  await player.update(async (draft) => {
    const missions = (draft.mission as any).missions[group];
    if (!missions) return;
    for (const [missionId, missionState] of Object.entries(missions) as any) {
      const isCompleted =
        missionState.state === 2 &&
        missionState.progress.length > 0 &&
        missionState.progress[0].target != null &&
        missionState.progress[0].value >= (missionState.progress[0].target as number);
      if (!isCompleted) continue;
      missionState.state = 3;
      // 查找任务奖励
      const missionInfo = excel.ActivityTable.missionData.find(
        (m) => m.id === missionId,
      );
      if (missionInfo) {
        for (const reward of missionInfo.rewards) {
          rewards.push({
            id: reward.id,
            count: reward.count,
            type: ItemTypeToString(reward.type) as ItemType,
          });
        }
      }
    }
  });
  return rewards;
}

function collectRawBody(req: import("express").Request): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function arkhubFullHost(): string {
  const host = String(config.Host).replace(/\/$/, "");
  const authority = host.replace(/^https?:\/\//, "");
  return /:\d+$/.test(authority) ? host : `${host}:${config.PORT}`;
}

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

export default router;
