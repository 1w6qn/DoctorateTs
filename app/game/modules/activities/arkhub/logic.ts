/**
 * 活动路由：arkhub（由 router/activity.ts 拆分而来，实现未改动）
 */
import { collectRawBody, arkhubFullHost } from "../shared/shared";
import * as ReqSchema from "../shared/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../kernel/http/request-context";
import config from "@core/config/index";
import {
  arkhubPixelPublished,
  arkhubPixelCollected,
} from "./arkhub";
import { parseMultipartForm } from "../../../kernel/util/multipart";
import {
  savePixel,
  loadPixelBytes,
  buildPixelArtResp,
  computeNewCollects,
  consumePixelUploadToken,
  ARKPIXEL_MAX_PUBLISH,
} from "./arkpixel";
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

import { PlayerDataManager } from "../../../kernel/PlayerDataManager";

/**
 * arkhub 活动族业务逻辑（建议 11：族包五件套——router 仅路由注册，业务收敛于 logic）
 *
 * 由 router.ts 内联 handler 提取（实现未改动）：每个活动接口一个具名函数，
 * 输入 player + 请求体，返回响应对象（原 res.send 载荷）。
 */

export async function handleArkhubenterHall(player: PlayerDataManager, body: ActivityStubRequest) {
  // 私服模式：本地网关应答器启动后指向本服端口（客户端连本服进空广场），
  // 否则返回官服域名（官服网关不可达/账号凭据无效时客户端无法进入）
  const { isArkhubLocalGatewayActive, getArkhubLocalGatewayPort } = await import(
    "./gateway/local"
  );
  const endpoint = isArkhubLocalGatewayActive()
    ? String(config.Host).replace(/^https?:\/\//, "")
    : "arkhub-gateway.hypergryph.com";
  // 实际监听端口（本地网关端口被占自动避让后的真实端口；未启动回退配置端口）
  const port = isArkhubLocalGatewayActive()
    ? getArkhubLocalGatewayPort() || (config.capture?.gatewayPort ?? 30000)
    : 30000;
  return ({
    result: 0,
    endpoint,
    port,
    ...player.delta,
  });
}

export async function handleArkhubgetFriendUidList(player: PlayerDataManager, body: ActivityStubRequest) {
  return ({
    friendUidList: [],
    ...player.delta,
  });
}



export async function handleArkhubgetPixelArt(player: PlayerDataManager, body: any) {
  const ids = Array.isArray(body.pixelArtIds) ? body.pixelArtIds : [];
  // 收集计数：非本人发布且未收集过的画像（computeNewCollects 去重）
  const hub = (player._playerdata.activity as any)?.ARK_HUB?.act1arkhub;
  const collectedIds: number[] = Array.isArray(hub?.pixelCollectedIds) ? hub.pixelCollectedIds : [];
  const fresh = computeNewCollects(String((player._playerdata.status as any)?.uid ?? ""), ids, collectedIds);
  if (fresh.length > 0) {
    await player.update(async (draft) => {
      const h = (draft.activity as any)?.ARK_HUB?.act1arkhub;
      if (!h) return;
      h.pixelCollectedIds = [...collectedIds, ...fresh];
    });
    await arkhubPixelCollected(player, collectedIds.length + fresh.length);
  }
  return ({
    pixelArts: buildPixelArtResp(ids, arkhubFullHost()),
    ...player.delta,
  });
}

export async function handleArkhubsetSecretary(player: PlayerDataManager, body: any) {
  await player.update(async (draft) => {
    const act = draft.activity as any;
    if (!act.ARK_HUB) act.ARK_HUB = {};
    const hub = (act.ARK_HUB["act1arkhub"] = act.ARK_HUB["act1arkhub"] ?? {
      coin: 0,
      secretary: "",
      secretarySkinId: "",
      secretarySkinSp: false,
      protectTs: -1,
      squads: [],
      globalBan: false,
    });
    if (body.secretary) hub.secretary = body.secretary;
    if (body.secretarySkinId) hub.secretarySkinId = body.secretarySkinId;
  });
  return (player.delta satisfies ActivityStubResponse);
}

export async function handleArkhubsetSquad(player: PlayerDataManager, body: any) {
  await player.update(async (draft) => {
    const act = draft.activity as any;
    if (!act.ARK_HUB) act.ARK_HUB = {};
    const hub = (act.ARK_HUB["act1arkhub"] = act.ARK_HUB["act1arkhub"] ?? {
      coin: 0,
      secretary: "",
      secretarySkinId: "",
      secretarySkinSp: false,
      protectTs: -1,
      squads: [],
      globalBan: false,
    });
    if (Array.isArray(body.squads)) hub.squads = body.squads;
  });
  return (player.delta satisfies ActivityStubResponse);
}

export async function handleArkhubsyncInfo(player: PlayerDataManager, body: ActivityStubRequest) {
  // 官服抓包对齐（R-1786877177293-0081）：syncInfo 返回枢纽进度增量
  // {mission.missions.ACTIVITY(1arkhubActivity_* 进度), medal.medals(枢纽勋章),
  //  activity.ARK_HUB.act1arkhub(状态)}——客户端据此刷新枢纽进度页。
  // 用 forcePatch 强制推送（纯读请求不产生 Immer 补丁，直接 res.delta 为空）。
  // 进度真实化（2026-08-17）：不再把未完成任务强制 [{1,1}]——任务模板监听事件
  // 驱动真实进度（播种 value:0/target:N），此处仅防御性保证 progress 为数组。
  const pd = player._playerdata as any;
  await player.update(async (draft) => {
    const actMissions = (draft.mission as any)?.missions?.["ACTIVITY"];
    for (const id of Object.keys(actMissions ?? {})) {
      if (!id.startsWith("1arkhubActivity_")) continue;
      const m = actMissions[id];
      if (m && !Array.isArray(m.progress)) {
        m.progress = [];
      }
    }
  });
  const actMissions = (pd.mission as any)?.missions?.["ACTIVITY"] ?? {};
  const hubMissions: Record<string, unknown> = {};
  for (const id of Object.keys(actMissions)) {
    if (id.startsWith("1arkhubActivity_")) hubMissions[id] = actMissions[id];
  }
  player.forcePatch(["mission", "missions", "ACTIVITY"], hubMissions);
  player.forcePatch(["medal", "medals"], pd.medal?.medals ?? {});
  player.forcePatch(["activity", "ARK_HUB"], pd.activity?.ARK_HUB ?? {});
  return (player.delta satisfies ActivityStubResponse);
}

export async function handleArkhubreport(player: PlayerDataManager, body: ActivityStubRequest) {
  return ({ result: 0, ...player.delta });
}

// ===== 顶层辅助函数（由 router.ts 拆分时保留，原样迁移）=====

