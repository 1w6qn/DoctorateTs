/**
 * 活动路由：arkhub（由 router/activity.ts 拆分而来，实现未改动）
 */
import { Router } from "express";
import { collectRawBody, arkhubFullHost } from "../shared";
import * as ReqSchema from "../../../domain/contracts/activity.schema";

import { getPlayer, getPlayerOptional } from "../../../request-context";
import config from "../../../../config";
import {
  arkhubPixelPublished,
  arkhubPixelCollected,
} from "./arkhub";
import {
  savePixel,
  loadPixelBytes,
  buildPixelArtResp,
  computeNewCollects,
  parseMultipartForm,
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
} from "../../../domain/contracts/activity";
import { validateBody } from "../../../domain/contracts/validate-body";

const router = Router();
router.post("/arkhub/enterHall", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityStubRequest;
  // 私服模式：本地网关应答器启动后指向本服端口（客户端连本服进空广场），
  // 否则返回官服域名（官服网关不可达/账号凭据无效时客户端无法进入）
  const { isArkhubLocalGatewayActive, getArkhubLocalGatewayPort } = await import(
    "../../../../proxy/arkhub-gateway-local"
  );
  const endpoint = isArkhubLocalGatewayActive()
    ? String(config.Host).replace(/^https?:\/\//, "")
    : "arkhub-gateway.hypergryph.com";
  // 实际监听端口（本地网关端口被占自动避让后的真实端口；未启动回退配置端口）
  const port = isArkhubLocalGatewayActive()
    ? getArkhubLocalGatewayPort() || (config.capture?.gatewayPort ?? 30000)
    : 30000;
  res.send({
    result: 0,
    endpoint,
    port,
    ...player.delta,
  });
});

/** 方舟枢纽好友 UID 列表（私服返回空——无真实网关好友） */

router.post("/arkhub/getFriendUidList", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityStubRequest;
  res.send({
    friendUidList: [],
    ...player.delta,
  });
});

/**
 * 方舟枢纽像素画上传（客户端 multipart → 网关；私服：落盘 data/arkhub/pixels + 发布计数）
 *
 * 官服链路（抓包 R-1786876787370-0074）：
 * - multipart/form-data：json part `{"brief":{"activityId","token"}}` + pixelData part（1728B RGB）
 * - 响应 `{"pixelArtId":<数字>}`（pixelArtId 由服务端分配；客户端随后 getPixelArt 拉取）
 * 私服：express.json 不解析 multipart——优先取 capture 模式 rawBody，否则收集原始流；
 * 发布次数上限 50（攻略），计数驱动任务 20-21（ArkhubPublishPixelArt）。
 */

router.post("/arkhub/savePixelArt", async (req, res) => {
  const player = getPlayer();
  const raw = (req as unknown as { rawBody?: Buffer }).rawBody ?? (await collectRawBody(req));
  let brief: { activityId?: string; token?: string } | undefined;
  let pixelData: Buffer | undefined;
  try {
    const parts = parseMultipartForm(raw, req.headers["content-type"]);
    const jsonPart = parts.get("json");
    const pixelPart = parts.get("pixelData");
    brief = jsonPart ? (JSON.parse(jsonPart.toString("utf-8"))?.brief ?? undefined) : undefined;
    pixelData = pixelPart;
  } catch {
    // 解析失败按无 brief 处理
  }
  if (brief?.activityId !== "act1arkhub" || !pixelData || pixelData.length !== 1728) {
    res.status(400).json({ error: "invalid pixel art payload", ...player.delta });
    return;
  }
  // 发布上限 50 次（攻略）
  const hub = (player._playerdata.activity as any)?.ARK_HUB?.act1arkhub;
  if ((hub?.pixelPublished ?? 0) >= ARKPIXEL_MAX_PUBLISH) {
    res.status(400).json({ error: "publish limit reached", ...player.delta });
    return;
  }
  let pixelArtId: number;
  try {
    // token 阶段（网关 RequestPixelArtUploadToken）预分配的 id——客户端上传成功后用该 id
    // 调 getPixelArt 加载画像，落盘必须沿用此 id（否则"上传成功但无法加载"）；消费一次性。
    const pending = consumePixelUploadToken(brief?.token ?? "");
    pixelArtId = savePixel(String((player._playerdata.status as any)?.uid ?? ""), pixelData, pending?.id);
  } catch (e) {
    res.status(400).json({ error: (e as Error).message, ...player.delta });
    return;
  }
  await arkhubPixelPublished(player, (hub?.pixelPublished ?? 0) + 1);
  res.send({ pixelArtId, ...player.delta });
});

/** 方舟枢纽像素画下载端点（getPixelArt 返回的 url 指向此处；GET /activity/arkhub/pixel/<id>.dat） */

router.get("/arkhub/pixel/:id.dat", (req, res) => {
  const bytes = loadPixelBytes(req.params.id);
  if (!bytes) {
    res.status(404).json({ error: "pixel art not found" });
    return;
  }
  res.type("application/octet-stream").send(bytes);
});

/**
 * 方舟枢纽像素画查询（官服抓包 R-1786680304215-0147 形状）
 * 请求 `{activityId, pixelArtIds:[...]}` → `{"pixelArts":{<id>:{"url","isBanned"}}}`。
 * 私服：返回本服下载 URL；拉取他人画像计为"收集"（任务 22-23/勋章 01，去重）。
 */

router.post("/arkhub/getPixelArt", validateBody(ReqSchema.arkhubGetPixelArtSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as { activityId?: string; pixelArtIds?: number[] };
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
  res.send({
    pixelArts: buildPixelArtResp(ids, arkhubFullHost()),
    ...player.delta,
  });
});

/** 方舟枢纽设置秘书（抓包：更新 ARK_HUB[act1arkhub].secretary/secretarySkinId） */

router.post("/arkhub/setSecretary", validateBody(ReqSchema.arkhubSetSecretarySchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as { secretary?: string; secretarySkinId?: string };
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
  res.send(player.delta satisfies ActivityStubResponse);
});

/** 方舟枢纽设置队伍（抓包：更新 ARK_HUB[act1arkhub].squads） */

router.post("/arkhub/setSquad", validateBody(ReqSchema.arkhubSetSquadSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as { squads?: unknown[] };
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
  res.send(player.delta satisfies ActivityStubResponse);
});

/** 方舟枢纽同步（抓包：返回枢纽进度增量——活动任务进度 + 勋章 + 枢纽状态） */

router.post("/arkhub/syncInfo", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityStubRequest;
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
  res.send(player.delta satisfies ActivityStubResponse);
});

/**
 * 方舟枢纽上报（抓包：result 0 + 空增量）
 * CS: Torappu.UI.ActArkhub.ActArkhubService（/activity/arkhub/report）
 */

router.post("/arkhub/report", validateBody(ReqSchema.activityStubSchema), async (req, res) => {
  const player = getPlayer();
  req.body as ActivityStubRequest;
  res.send({ result: 0, ...player.delta });
});

/**
 * 锁链作战刷新队伍（CS: Torappu.Activity.Act1Lock.Act1LockRefreshSquadRequest）
 * 私服单机无多人锁链，返回空增量
 */
export default router;
