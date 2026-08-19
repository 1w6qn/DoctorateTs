/**
 * 肉鸽V2（集成战略）路由
 * 请求/响应类型见 @game/model/protocol/rlv2（参考 CS 2.7.61 协议类）
 *
 * 响应约定（2026-08-10 修复）：客户端需要完整 rlv2 子树（官方抓包确认
 * modified.rlv2 = { current, outer } 全量）。控制器子管理器（status/map/inventory/
 * troop/module）为内存态，不经 Immer 产生补丁 → 纯 player.delta 为空 modified，
 * 客户端收不到任何状态。rlv2Response 把控制器 toJSON 全量并入 modified.rlv2。
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { RoguelikePushMessage } from "../model/protocol/common";
import {
  FinishBattleRewardRequest,
  FinishBattleRewardResponse,
  RL03ConfirmPredictRequest,
  RL03ConfirmPredictResponse,
  RL03UseTotemRequest,
  RL03UseTotemResponse,
  RL04LoseFragmentRequest,
  RL04LoseFragmentResponse,
  RL04UseInspirationRequest,
  RL04UseInspirationResponse,
  RoguelikeActivateTicketRequest,
  RoguelikeActivateTicketResponse,
  RoguelikeAlchemyRequest,
  RoguelikeAlchemyResponse,
  RoguelikeAlchemyRewardRequest,
  RoguelikeAlchemyRewardResponse,
  RoguelikeBankInvestRequest,
  RoguelikeBankInvestResponse,
  RoguelikeBankWithdrawRequest,
  RoguelikeBankWithdrawResponse,
  RoguelikeBattlePassGetRewardRequest,
  RoguelikeBattlePassGetRewardResponse,
  RoguelikeBuyGoodsRequest,
  RoguelikeBuyGoodsResponse,
  RoguelikeCloseTicketRequest,
  RoguelikeCloseTicketResponse,
  RoguelikeConfirmNodeMissionRequest,
  RoguelikeConfirmNodeMissionResponse,
  RoguelikeCopperRedrawRequest,
  RoguelikeCopperRedrawResponse,
  RoguelikeDiceChoiceRequest,
  RoguelikeDiceChoiceResponse,
  RoguelikeExpedReturnRequest,
  RoguelikeExpedReturnResponse,
  RoguelikeExpeditionRequest,
  RoguelikeExpeditionResponse,
  RoguelikeFinishBattleRequest,
  RoguelikeFinishBattleResponse,
  RoguelikeFinishEventRequest,
  RoguelikeFinishEventResponse,
  RoguelikeGameSettleRequest,
  RoguelikeGameSettleResponse,
  RoguelikeGetTicketAssistListRequest,
  RoguelikeGetTicketAssistListResponse,
  RoguelikeGildRequest,
  RoguelikeGildResponse,
  RoguelikeGiveUpNodeMissionRequest,
  RoguelikeGiveUpNodeMissionResponse,
  RoguelikeGridZoneEmptyStepRequest,
  RoguelikeGridZoneEmptyStepResponse,
  RoguelikeGridZoneMoveAndBattleStartRequest,
  RoguelikeGridZoneMoveAndBattleStartResponse,
  RoguelikeGridZoneMoveToRequest,
  RoguelikeGridZoneMoveToResponse,
  RoguelikeGridZoneReadStepZeroRequest,
  RoguelikeGridZoneReadStepZeroResponse,
  RoguelikeMoveToRequest,
  RoguelikeMoveToResponse,
  RoguelikePinTopicRequest,
  RoguelikePinTopicResponse,
  RoguelikeReadEndingChangeRequest,
  RoguelikeReadEndingChangeResponse,
  RoguelikeTopicRefreshMissionResponse,
  RoguelikeReadMissionTipRequest,
  RoguelikeReadMissionTipResponse,
  RoguelikeRecruitAssistCharRequest,
  RoguelikeRecruitAssistCharResponse,
  RoguelikeRecruitCharRequest,
  RoguelikeRecruitCharResponse,
  RoguelikeRollNodeRequest,
  RoguelikeRollNodeResponse,
  RoguelikeSacrificeRequest,
  RoguelikeSacrificeResponse,
  RoguelikeScrapChangeVehicleRequest,
  RoguelikeScrapChangeVehicleResponse,
  RoguelikeScrapLoseRequest,
  RoguelikeScrapLoseResponse,
  RoguelikeScrapRequest,
  RoguelikeScrapResponse,
  RoguelikeSelectChoiceRequest,
  RoguelikeSelectChoiceResponse,
  RoguelikeSelectInitialExploreToolRequest,
  RoguelikeSelectInitialExploreToolResponse,
  RoguelikeSelectInitialRecruitSetRequest,
  RoguelikeSelectInitialRecruitSetResponse,
  RoguelikeSelectInitialRelicRequest,
  RoguelikeSelectInitialRelicResponse,
  RoguelikeSelectRewardRequest,
  RoguelikeSelectRewardResponse,
  RoguelikeShopActionRequest,
  RoguelikeShopActionResponse,
  RoguelikeShopBattleRequest,
  RoguelikeShopBattleResponse,
  RoguelikeShopRefreshRequest,
  RoguelikeShopRefreshResponse,
  RoguelikeSpecialZoneLeaveRequest,
  RoguelikeSpecialZoneLeaveResponse,
  RoguelikeStashTicketRequest,
  RoguelikeStashTicketResponse,
  RoguelikeStashedTicketUseRequest,
  RoguelikeStashedTicketUseResponse,
  RoguelikeStepMoveToAndStartBattleRequest,
  RoguelikeStepMoveToAndStartBattleResponse,
  RoguelikeTopicCreateGameRequest,
  RoguelikeTopicCreateGameResponse,
  RoguelikeTopicGiveUpGameRequest,
  RoguelikeTopicGiveUpGameResponse,
  RoguelikeTraderReturnRequest,
  RoguelikeTraderReturnResponse,
  RoguelikeUpgradeNodeRequest,
  RoguelikeUpgradeNodeResponse,
  RoguelikeZoneRewardRequest,
  RoguelikeZoneRewardResponse,
  SetTroopCarryRequest,
  SetTroopCarryResponse,
} from "../model/protocol/rlv2";

const router = Router();

/**
 * 每请求开始时清空 pushMessage 收集器。
 * 控制器为玩家持久实例，`_pushMessages` 跨请求累积；新增收藏品/散件/载具/天气/结局等
 * 推送由多种端点触发，此处统一在进入端点前复位，保证推送只随触发它的那次响应下发、
 * 不泄漏到后续请求（与 createGame/gridZone/moveTo 内各自的手动复位等价且冗余安全）。
 */
router.use((_req, _res, next) => {
  const player = httpContext.get<PlayerDataManager>("playerData");
  if (player?.rlv2?._pushMessages?.length) {
    player.rlv2._pushMessages = [];
  }
  next();
});

/**
 * 官方各路由响应包含的 current 节（抓包 2026-08-11/08-18 统计）。
 * 核心节 player/inventory/record/buff 几乎总是出现；map/module 仅在生成/变化时出现；
 * game/troop 仅 createGame/gameSettle/recruitChar 等变更时出现。
 * 2026-08-18 按官服抓包逐路由校准（finishEvent/selectChoice/recruitSet/ticket/recruitChar/giveUpGame）：
 *   chooseInitialRelic/finishEvent(INIT)/selectChoice/battleFinish = CORE
 *   finishEvent(进层)/gridZone 移动 = CORE_MAP_MODULE
 *   chooseInitialRecruitSet = player/inventory/record（无 buff）
 *   activeRecruitTicket = player/inventory（无 record/buff）
 *   recruitChar = player/inventory/record/buff/troop/module（无 map/game）
 *   giveUpGame = player/record（极少）
 */
const SEC = {
  ALL: undefined, // 全量（createGame/gameSettle）
  CORE: ["player", "inventory", "record", "buff"],
  CORE_MAP: ["player", "inventory", "record", "buff", "map"],
  CORE_MODULE: ["player", "inventory", "record", "buff", "module"],
  CORE_MAP_MODULE: ["player", "inventory", "record", "buff", "map", "module"],
  RECRUIT: ["player", "inventory", "record", "troop"],
  PLAYER: ["player"],
  // 官服增量节（2026-08-18 校准）
  RECRUIT_SET: ["player", "inventory", "record"],
  TICKET: ["player", "inventory"],
  RECRUIT_CHAR: ["player", "inventory", "record", "buff", "troop", "module"],
  GIVEUP: ["player", "record"],
} as const;

/**
 * rlv2 统一响应：并入控制器 toJSON 的 rlv2 子树。
 * 官方抓包确认：客户端按 modified.rlv2 合并状态，但每路由只发送"发生变化"的
 * current 节（createGame/gameSettle 全量；其余为增量节）——多发的 game/troop 等
 * 节会破坏客户端状态合并导致崩溃。rlv2Response 按 sections 过滤 current。
 *
 * 2026-08-18 对齐官服抓包修正：
 * 1. pinned 不输出（官服所有 rlv2 响应均无 pinned——置顶主题由其他接口下发）
 * 2. outer 仅显式要求（outerKeys 非空，createGame/gameSettle/gridZone moveAndBattleStart）
 *    时输出当前主题指定键（官服各路由 outer 内容不同：createGame={record,monthTeam}、
 *    gameSettle=7 键全量、moveAndBattleStart={record}）；其余路由不带
 *    （原实现 theme 存在即输出，且 {...full} 泄漏全量 6 主题 outer → 255KB 冗余）
 * 3. sections=undefined 全量时也只取 current 自身，不再展开 full.outer/full.pinned
 */
export function rlv2Response<T extends object>(
  player: PlayerDataManager,
  extra?: T,
  sections?: readonly string[],
  outerKeys?: readonly string[],
  pushMessages?: RoguelikePushMessage[],
) {
  // 内存态（status/map/module/troop 等 manager）写回存档——供重登"继续探索"
  // （controller 重建走 rlv2:continue 恢复）使用；否则 current.player 等为空
  player.rlv2.persistCurrent();
  const base = player.delta;
  const full = player.rlv2.toJSON();
  const current = full.current as any;
  const currentOut: any = {};
  if (sections) {
    for (const s of sections) {
      if (s in current) currentOut[s] = current[s];
    }
  } else {
    Object.assign(currentOut, current);
  }
  const rlv2: any = { current: currentOut };
  if (outerKeys && outerKeys.length > 0) {
    const theme = current?.game?.theme as string | undefined;
    const fullOuter = full.outer as Record<string, any> | undefined;
    if (theme && fullOuter?.[theme]) {
      const o = fullOuter[theme];
      const picked: Record<string, unknown> = {};
      for (const k of outerKeys) {
        if (k in o) picked[k] = o[k];
      }
      rlv2.outer = { [theme]: picked };
    }
  }
  return {
    ...(extra ?? ({} as T)),
    ...(pushMessages && pushMessages.length > 0 ? { pushMessage: pushMessages } : {}),
    playerDataDelta: {
      modified: {
        ...base.playerDataDelta.modified,
        rlv2,
      },
      deleted: base.playerDataDelta.deleted,
    },
  };
}

/**
 * 缺参校验辅助：必填字段缺失时返回业务错误（HTTP 200 + result≠0），
 * 避免 undefined 传入控制器抛 TypeError → 全局 500。响应结构同正常 rlv2。
 */
function rlv2MissingParam(player: PlayerDataManager): any {
  return rlv2Response(player, { result: 1 } as any, SEC.ALL);
}

/** 放弃游戏（CS: RoguelikeTopicGiveUpGameRequest）——官方响应带 result:"ok"，
 *  current 节仅 [record, player]（2026-08-18 官服 giveUpGame 抓包校准） */
router.post("/giveUpGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeTopicGiveUpGameRequest;
  await player.rlv2.giveUpGame();
  res.send(
    rlv2Response(player, { result: "ok" } as any, SEC.GIVEUP) satisfies RoguelikeTopicGiveUpGameResponse,
  );
});

/** 创建游戏（CS: RoguelikeTopicCreateGameRequest） */
router.post("/createGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeTopicCreateGameRequest;
  if (body.theme == null || body.mode == null || body.modeGrade == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.createGame(body);
  res.send(rlv2Response(player, undefined, SEC.ALL, ["record", "monthTeam"], player.rlv2.takePushMessages()) satisfies RoguelikeTopicCreateGameResponse);
});

/** 游戏结算（抓包 POST /rlv2/gameSettle，body {}；响应带 game/outer 结算数据） */
router.post("/gameSettle", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeGameSettleRequest;
  await player.rlv2.gameSettle();
  res.send(
    // 官服 gameSettle rlv2.outer = 当前主题 7 键全量（record/bank/buff/bp/collect/mission/activity）——
    // 2026-08-18 抓包校准（非 createGame 的 {record,monthTeam} 精简）
    rlv2Response(player, player.rlv2.buildSettleResponse() as any, SEC.ALL, [
      "record", "bank", "buff", "bp", "collect", "mission", "activity",
    ]) satisfies RoguelikeGameSettleResponse,
  );
});

/** 选择初始密文（CS: RoguelikeSelectInitialRelicRequest） */
router.post("/chooseInitialRelic", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectInitialRelicRequest;
  await player.rlv2.chooseInitialRelic(body);
  res.send(
    rlv2Response(player, undefined, SEC.CORE, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeSelectInitialRelicResponse,
  );
});

/** 选择初始招募组（CS: RoguelikeSelectInitialRecruitSetRequest） */
router.post("/chooseInitialRecruitSet", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectInitialRecruitSetRequest;
  await player.rlv2.chooseInitialRecruitSet(body);
  res.send(
    // 官服 chooseInitialRecruitSet current=[inventory,record,player]（无 buff）——2026-08-18 抓包校准
    rlv2Response(player, undefined, SEC.RECRUIT_SET) satisfies RoguelikeSelectInitialRecruitSetResponse,
  );
});

/** 选择初始探索工具（CS: RoguelikeSelectInitialExploreToolRequest） */
router.post("/chooseInitialExploreTool", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectInitialExploreToolRequest;
  await player.rlv2.chooseInitialExploreTool(body);
  res.send(
    rlv2Response(player) satisfies RoguelikeSelectInitialExploreToolResponse,
  );
});

/** 激活招募票（CS: RoguelikeActivateTicketRequest） */
router.post("/activeRecruitTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeActivateTicketRequest;
  if (body.id == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.activeRecruitTicket(body);
  // 官服 activeRecruitTicket current=[inventory,player]（无 record/buff）——2026-08-18 抓包校准
  res.send(rlv2Response(player, undefined, SEC.TICKET) satisfies RoguelikeActivateTicketResponse);
});

/** 招募干员（CS: RoguelikeRecruitCharRequest） */
router.post("/recruitChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeRecruitCharRequest;
  if (body.ticketIndex == null || body.optionId == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  res.send(
    // 官服 recruitChar current=[inventory,troop,buff,player,module,record]（无 map/game）——2026-08-18 抓包校准
    rlv2Response(player, {
      chars: await player.rlv2.recruitChar(body),
    }, SEC.RECRUIT_CHAR) satisfies RoguelikeRecruitCharResponse,
  );
});

/** 获取招募票助战列表（CS: RoguelikeGetTicketAssistListRequest） */
router.post("/getTicketAssistList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeGetTicketAssistListRequest;
  await player.rlv2.getTicketAssistList(body);
  res.send(
    rlv2Response(player) satisfies RoguelikeGetTicketAssistListResponse,
  );
});

/** 招募助战干员（CS: RoguelikeRecruitAssistCharRequest） */
router.post("/recruitAssistChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeRecruitAssistCharRequest;
  await player.rlv2.recruitAssistChar(body);
  res.send(rlv2Response(player) satisfies RoguelikeRecruitAssistCharResponse);
});

/** 结束事件（CS: RoguelikeFinishEventRequest） */
router.post("/finishEvent", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeFinishEventRequest;
  // 修复：无进行中游戏（或游戏主题无效）时返回业务错误，避免状态机在空态下异常调用崩溃
  //（如冒烟空 body 探测触发 zone:new → 地图生成读取 undefined game.theme → details[undefined].stages → 500）
  const game = player.rlv2.current?.game;
  if (!game || !game.theme) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.finishEvent();
  // 官服 finishEvent 响应节动态：初始阶段（未进层）只发 CORE（player/inventory/record/buff）；
  // 消费完初始事件进入第一层（WAIT_MOVE，地图生成）追加 map/module（CORE_MAP_MODULE）。
  // 2026-08-18 官服抓包校准：finishEvent#1(INIT) current=[record,player,buff,inventory]；
  // finishEvent#2(进层) current=[record,player,module,map,buff,inventory]。
  const feState = player.rlv2.current?.player?.state;
  const feSections = feState === "WAIT_MOVE" ? SEC.CORE_MAP_MODULE : SEC.CORE;
  res.send(rlv2Response(player, undefined, feSections, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeFinishEventResponse);
});

/**
 * 选择事件选项（CS: RoguelikeSelectChoiceRequest）
 * 控制器 selectChoice 已实现（buff/遗物/下一场景构建），此前漏接线
 */
router.post("/selectChoice", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectChoiceRequest;
  if (body.choice == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.selectChoice(body);
  // 官服 selectChoice 响应节 = CORE（player/inventory/record/buff）——2026-08-18 抓包校准
  res.send(rlv2Response(player, undefined, SEC.CORE, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeSelectChoiceResponse);
});

/** 移动（CS: RoguelikeMoveToRequest） */
router.post("/moveTo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeMoveToRequest;
  if (!body.to || body.to.x == null || body.to.y == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.moveTo(body);
  res.send(rlv2Response(player, undefined, undefined, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeMoveToResponse);
});

/** 移动并开始战斗（CS: RoguelikeStepMoveToAndStartBattleRequest） */
router.post("/moveAndBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeStepMoveToAndStartBattleRequest;
  if (!body.to || body.to.x == null || body.to.y == null || body.stageId == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.moveAndBattleStart(body);
  res.send(
    rlv2Response(player, undefined, undefined, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeStepMoveToAndStartBattleResponse,
  );
});

/** 战斗结算（CS: RoguelikeFinishBattleRequest）——官服 current=[record,player,buff,inventory] */
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeFinishBattleRequest;
  await player.rlv2.battleFinish(body);
  res.send(rlv2Response(player, undefined, SEC.CORE) satisfies RoguelikeFinishBattleResponse);
});

/** 选择战斗奖励（CS: RoguelikeSelectRewardRequest） */
router.post("/chooseBattleReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSelectRewardRequest;
  if (body.index == null || body.sub == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  player.rlv2.chooseBattleReward(body);
  res.send(rlv2Response(player) satisfies RoguelikeSelectRewardResponse);
});

/** 完成战斗奖励（服务端自定义） */
router.post("/finishBattleReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as FinishBattleRewardRequest;
  await player.rlv2.finishBattleReward(body);
  res.send(rlv2Response(player, undefined, undefined, undefined, player.rlv2.takePushMessages()) satisfies FinishBattleRewardResponse);
});

/** 设置队伍携带（服务端自定义） */
router.post("/setTroopCarry", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SetTroopCarryRequest;
  player.rlv2.setTroopCarry(body);
  res.send(rlv2Response(player) satisfies SetTroopCarryResponse);
});

/** 丢失密文（CS: RL04LoseFragmentRequest） */
router.post("/loseFragment", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RL04LoseFragmentRequest;
  player.rlv2.loseFragment(body);
  res.send(rlv2Response(player) satisfies RL04LoseFragmentResponse);
});

/** 使用灵感（CS: RL04UseInspirationRequest） */
router.post("/useInspiration", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RL04UseInspirationRequest;
  player.rlv2.useInspiration(body);
  res.send(rlv2Response(player) satisfies RL04UseInspirationResponse);
});

/** 置顶主题（CS: RoguelikePinTopicRequest） */
router.post("/setPinned", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikePinTopicRequest;
  player.rlv2.setPinned(body);
  res.send(rlv2Response(player) satisfies RoguelikePinTopicResponse);
});

/** 刷新商店（CS: RoguelikeShopRefreshRequest） */
router.post("/refreshShop", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeShopRefreshRequest;
  await player.rlv2.refreshShop();
  res.send(rlv2Response(player) satisfies RoguelikeShopRefreshResponse);
});

/** 离开商店（CS: RoguelikeShopActionRequest） */
router.post("/leaveShop", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeShopActionRequest;
  await player.rlv2.leaveShop();
  res.send(rlv2Response(player) satisfies RoguelikeShopActionResponse);
});

/** 商店购买（CS: RoguelikeShopActionRequest；控制器 buyGoods 已实现此前漏接线，同 selectChoice） */
router.post("/buyGoods", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeBuyGoodsRequest;
  await player.rlv2.buyGoods({ select: body.select ?? 0 });
  res.send(rlv2Response(player, undefined, undefined, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeBuyGoodsResponse);
});

/** 商店操作（CS: RoguelikeShopActionRequest）：buy 数组 → buyGoods；否则离开商店 */
router.post("/shopAction", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeShopActionRequest;
  if (body.buy && body.buy.length > 0) {
    await player.rlv2.buyGoods({ select: parseInt(body.buy[0], 10) || 0 });
  } else {
    await player.rlv2.leaveShop();
  }
  res.send(rlv2Response(player, undefined, undefined, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeShopActionResponse);
});

/** 使用图腾（CS: RL03UseTotemRequest） */
router.post("/useTotem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RL03UseTotemRequest;
  if (!body.totemIndex || !body.nodeIndex) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.useTotem(body);
  res.send(rlv2Response(player) satisfies RL03UseTotemResponse);
});

/** 确认预言（CS: RL03ConfirmPredictRequest） */
router.post("/confirmPredict", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RL03ConfirmPredictRequest;
  await player.rlv2.confirmPredict();
  res.send(rlv2Response(player) satisfies RL03ConfirmPredictResponse);
});

/** 关闭招募票（CS: RoguelikeCloseTicketRequest） */
router.post("/closeRecruitTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeCloseTicketRequest;
  await player.rlv2.closeRecruitTicket(body);
  res.send(rlv2Response(player) satisfies RoguelikeCloseTicketResponse);
});

/** 读取结局变更（CS: RoguelikeReadEndingChangeRequest） */
router.post("/readEndingChange", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeReadEndingChangeRequest;
  await player.rlv2.readEndingChange();
  res.send(rlv2Response(player) satisfies RoguelikeReadEndingChangeResponse);
});

/** 月度任务刷新（CS: RoguelikeTopicRefreshMissionRequest { theme, index }） */
router.post("/normal/refreshMission", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { theme?: string; index?: number };
  await player.rlv2.refreshMission(body);
  res.send(rlv2Response(player) satisfies RoguelikeTopicRefreshMissionResponse);
});

/** 确认区域奖励（CS: RoguelikeZoneRewardRequest { itemType }） */
router.post("/confirmZoneReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeZoneRewardRequest;
  await player.rlv2.confirmZoneReward();
  res.send(rlv2Response(player, undefined, undefined, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeZoneRewardResponse);
});

/** 确认商人返回（CS: RoguelikeTraderReturnRequest） */
router.post("/confirmTraderReturn", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeTraderReturnRequest;
  await player.rlv2.confirmTraderReturn();
  res.send(rlv2Response(player) satisfies RoguelikeTraderReturnResponse);
});

/** 离开特殊区域（CS: RoguelikeSpecialZoneLeaveRequest） */
router.post("/specialZone/leave", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeSpecialZoneLeaveRequest;
  await player.rlv2.specialZoneLeave();
  res.send(rlv2Response(player) satisfies RoguelikeSpecialZoneLeaveResponse);
});

/** 战令领奖（抓包 { theme, rewards }） */
router.post("/battlePass/getReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeBattlePassGetRewardRequest;
  if (body.theme == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  const { items } = await player.rlv2.battlePassGetReward(
    body.theme,
    body.rewards,
  );
  res.send(
    rlv2Response(player, { items }) satisfies RoguelikeBattlePassGetRewardResponse,
  );
});

/** 战令领奖（客户端路径 /rlv2/battlePass_getReward，下划线风格——官方抓包确认） */
router.post("/battlePass_getReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeBattlePassGetRewardRequest;
  if (body.theme == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  const { items } = await player.rlv2.battlePassGetReward(
    body.theme,
    body.rewards,
  );
  res.send(
    rlv2Response(player, { items }) satisfies RoguelikeBattlePassGetRewardResponse,
  );
});

/** 银行存钱（CS: RoguelikeBankInvestRequest） */
router.post("/bankPut", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeBankInvestRequest;
  await player.rlv2.bankPut();
  res.send(rlv2Response(player) satisfies RoguelikeBankInvestResponse);
});

/** 银行取钱（CS: RoguelikeBankWithdrawRequest { count }） */
router.post("/bankWithdraw", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeBankWithdrawRequest;
  await player.rlv2.bankWithdraw(body);
  res.send(rlv2Response(player) satisfies RoguelikeBankWithdrawResponse);
});

/** 确认节点任务（CS: RoguelikeConfirmNodeMissionRequest） */
router.post("/nodeMission/confirm", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeConfirmNodeMissionRequest;
  await player.rlv2.nodeMissionConfirm();
  res.send(rlv2Response(player) satisfies RoguelikeConfirmNodeMissionResponse);
});

/** 放弃节点任务（CS: RoguelikeGiveUpNodeMissionRequest） */
router.post("/nodeMission/giveUp", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeGiveUpNodeMissionRequest;
  await player.rlv2.nodeMissionGiveUp();
  res.send(rlv2Response(player) satisfies RoguelikeGiveUpNodeMissionResponse);
});

/** 关闭节点任务提示（CS: RoguelikeReadMissionTipRequest） */
router.post("/nodeMission/closeTip", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeReadMissionTipRequest;
  await player.rlv2.nodeMissionCloseTip();
  res.send(rlv2Response(player) satisfies RoguelikeReadMissionTipResponse);
});

/**
 * 节点任务（客户端路径 /rlv2/nodeMission_confirm|giveUp|closeTip，下划线风格——
 * 官方抓包确认；斜杠路径保留兼容）
 */
router.post("/nodeMission_confirm", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeConfirmNodeMissionRequest;
  await player.rlv2.nodeMissionConfirm();
  res.send(rlv2Response(player) satisfies RoguelikeConfirmNodeMissionResponse);
});

router.post("/nodeMission_giveUp", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeGiveUpNodeMissionRequest;
  await player.rlv2.nodeMissionGiveUp();
  res.send(rlv2Response(player) satisfies RoguelikeGiveUpNodeMissionResponse);
});

router.post("/nodeMission_closeTip", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeReadMissionTipRequest;
  await player.rlv2.nodeMissionCloseTip();
  res.send(rlv2Response(player) satisfies RoguelikeReadMissionTipResponse);
});

/** 远征选择（CS: RoguelikeExpeditionRequest { choice, leave }） */
router.post("/expeditionChoice", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeExpeditionRequest;
  const ret = await player.rlv2.expeditionChoice(body);
  res.send(rlv2Response(player, ret) satisfies RoguelikeExpeditionResponse);
});

/** 确认远征返回（CS: RoguelikeExpedReturnRequest） */
router.post("/game/confirmExpeditonReturn", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeExpedReturnRequest;
  await player.rlv2.confirmExpeditonReturn();
  res.send(rlv2Response(player) satisfies RoguelikeExpedReturnResponse);
});

/** 骰子选择（CS: RoguelikeDiceChoiceRequest） */
router.post("/diceChoice", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeDiceChoiceRequest;
  const ret = await player.rlv2.diceChoice(body);
  res.send(rlv2Response(player, ret) satisfies RoguelikeDiceChoiceResponse);
});

/** 献祭选择（CS: RoguelikeSacrificeRequest { choice, leave }） */
router.post("/sacrificeChoice", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeSacrificeRequest;
  await player.rlv2.sacrificeChoice(body);
  res.send(rlv2Response(player) satisfies RoguelikeSacrificeResponse);
});

/** 铜币镀金（CS: RoguelikeGildRequest { choice, leave }） */
router.post("/copper/gild", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeGildRequest;
  await player.rlv2.copperGild(body);
  res.send(rlv2Response(player) satisfies RoguelikeGildResponse);
});

/** 铜币重抽（COPPER 模块） */
router.post("/copper/redraw", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeCopperRedrawRequest;
  const ret = await player.rlv2.copperRedraw();
  res.send(rlv2Response(player, ret) satisfies RoguelikeCopperRedrawResponse);
});

/** 商店战斗开始（CS: RoguelikeShopBattleRequest） */
router.post("/shopBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeShopBattleRequest;
  await player.rlv2.shopBattleStart();
  res.send(rlv2Response(player) satisfies RoguelikeShopBattleResponse);
});

/** 重掷节点（CS: RoguelikeRollNodeRequest { nodeIndex }） */
router.post("/rerollNode", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeRollNodeRequest;
  await player.rlv2.rerollNode(body);
  res.send(rlv2Response(player) satisfies RoguelikeRollNodeResponse);
});

/** 升级节点（CS: RoguelikeUpgradeNodeRequest { nodeType }） */
router.post("/upgradeNode", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeUpgradeNodeRequest;
  await player.rlv2.upgradeNode(body);
  res.send(rlv2Response(player) satisfies RoguelikeUpgradeNodeResponse);
});

/** 暂存招募票（CS: RoguelikeStashTicketRequest { index }） */
router.post("/stashRecruitTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeStashTicketRequest;
  await player.rlv2.stashRecruitTicket(body);
  res.send(rlv2Response(player) satisfies RoguelikeStashTicketResponse);
});

/** 使用暂存票（CS: RoguelikeStashedTicketUseRequest { id }） */
router.post("/useStashedTicket", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeStashedTicketUseRequest;
  await player.rlv2.useStashedTicket(body);
  res.send(rlv2Response(player) satisfies RoguelikeStashedTicketUseResponse);
});

/** 炼金（fragment 模块；抓包 { leave }） */
router.post("/alchemy", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeAlchemyRequest;
  await player.rlv2.alchemy(body);
  res.send(rlv2Response(player) satisfies RoguelikeAlchemyResponse);
});

/** 炼金奖励（抓包 { index }） */
router.post("/alchemyReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeAlchemyRewardRequest;
  await player.rlv2.alchemyReward({ index: 0 });
  res.send(rlv2Response(player) satisfies RoguelikeAlchemyRewardResponse);
});

/** 废品操作（rogue_6 SCRAP 模块） */
router.post("/scrap", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeScrapRequest;
  await player.rlv2.scrap();
  res.send(rlv2Response(player) satisfies RoguelikeScrapResponse);
});

/** 废品换乘（rogue_6 SCRAP MOVE 型；客户端 body { scrapInstId, toWalk }） */
router.post("/scrap/changeVehicle", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeScrapChangeVehicleRequest;
  await player.rlv2.scrapChangeVehicle(body);
  res.send(
    rlv2Response(player, undefined, undefined, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeScrapChangeVehicleResponse,
  );
});

/** 丢弃废品（rogue_6 SCRAP 模块；客户端 body { instId }） */
router.post("/scrap/loseScrap", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeScrapLoseRequest;
  // 缺 instId 时原实现会静默走 inventory[undefined] → 无任何效果也无错误提示
  if (body?.instId == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.loseScrap(body);
  res.send(rlv2Response(player, undefined, undefined, undefined, player.rlv2.takePushMessages()) satisfies RoguelikeScrapLoseResponse);
});

/** 废品鉴定（rogue_6 SCRAP 模块；抓包 body { count }，响应顶层 { scrap, legacy }） */
router.post("/scrap/identify", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { count?: number };
  const ret = await player.rlv2.scrapIdentify({ count: body?.count });
  res.send(
    rlv2Response(player, {
      scrap: ret.scrap,
      legacy: ret.legacy,
    }) as any,
  );
});

/* ===== rogue_6 GRID_ZONE 网格区域 ===== */

/** 网格区域移动（抓包 { route: [nodeIndex] }）——官服 current=CORE_MAP_MODULE */
router.post("/gridZone/moveTo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeGridZoneMoveToRequest;
  if (!Array.isArray(body.route) || body.route.length === 0) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.gridZoneMoveTo(body);
  res.send(
    // 节点到达推送（rlv2NodeArrive/rlv2NodeChange）随响应下发——原实现漏传
    // takePushMessages，而黑流树海的移动全走本路由 → 推送永不到达客户端
    rlv2Response(
      player,
      undefined,
      SEC.CORE_MAP_MODULE,
      undefined,
      player.rlv2.takePushMessages(),
    ) satisfies RoguelikeGridZoneMoveToResponse,
  );
});

/** 网格区域移动并开始战斗（抓包 { route, stageId, squad }）——官服 current=CORE_MAP_MODULE + outer */
router.post("/gridZone/moveAndBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as RoguelikeGridZoneMoveAndBattleStartRequest;
  if (!Array.isArray(body.route) || body.route.length === 0 || body.stageId == null) {
    res.send(rlv2MissingParam(player));
    return;
  }
  await player.rlv2.gridZoneMoveAndBattleStart(body);
  res.send(
    // 官服 gridZone/moveAndBattleStart rlv2.outer = {record}——2026-08-18 抓包校准
    rlv2Response(
      player,
      undefined,
      SEC.CORE_MAP_MODULE,
      ["record"],
      player.rlv2.takePushMessages(),
    ) satisfies RoguelikeGridZoneMoveAndBattleStartResponse,
  );
});

/** 网格区域空步（GRID_ZONE 节点消耗） */
router.post("/gridZone/emptyStep", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeGridZoneEmptyStepRequest;
  await player.rlv2.gridZoneEmptyStep();
  res.send(rlv2Response(player) satisfies RoguelikeGridZoneEmptyStepResponse);
});

/** 网格区域读取第 0 步（GRID_ZONE 模块） */
router.post("/gridZone/readStepZero", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as RoguelikeGridZoneReadStepZeroRequest;
  await player.rlv2.gridZoneReadStepZero();
  res.send(
    rlv2Response(player) satisfies RoguelikeGridZoneReadStepZeroResponse,
  );
});

export default router;
