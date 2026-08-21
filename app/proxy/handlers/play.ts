/**
 * arkhub 网关捕捉/对局/生物/交换处理（handlers——逻辑层）
 *
 * 草丛扫描（GetCaptureInfo/StartCapture/EncounterCreatureNotify/EndCapture）、
 * 拟合对局（JoinDuel/CancelDuel/StartDuel/RoundPrepare/…/DuelRoundResultReport）、
 * 生物管理（Delete/SetLike/SetFollowing/SetSquad）、交换（预设/发起/应答/列表）。
 * 帧形状对齐官服逆向（docs/arkhub-gateway-protocol.md §9.2/§9.3/§11）。
 * 路由注册入口：registerPlayHandlers(router)。
 */
import { logger } from "@utils/logger";
import {
  encodeFieldBytes as fb,
  encodeFieldVarint as fv,
} from "../arkhub-gateway-codec";
import { GW_CODE_OK } from "../arkhub-gateway-router";
import type {
  ArkhubFrameRouter,
  ArkhubGatewayHandlerContext,
  ArkhubGatewayFrame,
} from "../arkhub-gateway-router";
import { CAPTURE_MAP_IDS } from "./session";

/* ---------- 帧 subID（low32） ---------- */

/** 捕捉信息查询（GetCaptureInfoReq）→ GetCaptureInfoResp */
const GW_CAPTURE_INFO_REQ = BigInt(0xb7c2ad8b);
const GW_CAPTURE_INFO_RESP = BigInt(0xb7c2b4de);
/** 捕捉开始（StartCaptureReq）→ StartCaptureResp，随后服务端主动推 EncounterCreatureNotify */
const GW_START_CAPTURE_REQ = BigInt(0xb7c267d7);
const GW_START_CAPTURE_RESP = BigInt(0xb7c2b07e);
const GW_ENCOUNTER_CREATURE_NOTIFY = BigInt(0xb7c20f13);
/** 捕捉结束（EndCaptureReq）→ EndCaptureResp（ArkDexSettleInfo 结算） */
const GW_END_CAPTURE_REQ = BigInt(0xb7c204e8);
const GW_END_CAPTURE_RESP = BigInt(0xb7c26451);
/** 对局入座（JoinDuelReq）→ JoinDuelResp；入座后服务端主动推 OnJoinDuelNotify */
const GW_JOIN_DUEL_REQ = BigInt(0xb7c277bf);
const GW_JOIN_DUEL_RESP = BigInt(0xb7c2a2e2);
const GW_ON_JOIN_DUEL_NOTIFY = BigInt(0xb7c2ef4f);
/** 取消对局（CancelDuelReq）→ ACK */
const GW_CANCEL_DUEL_REQ = BigInt(0xb7c21661);
/** 对局开始（StartDuelReq）→ StartDuelResp{code} */
const GW_START_DUEL_REQ = BigInt(0xf8faa515);
const GW_START_DUEL_RESP = BigInt(0xf8fa2dce);
/** 回合准备 / 战报上传 / 加载完成 / 离开对局（服务端 fire-and-forget → ACK） */
const GW_ROUND_PREPARE_REQ = BigInt(0xf8fa9c6e);
const GW_UPLOAD_BATTLE_DATA_REQ = BigInt(0xf8faab16);
const GW_LOADING_FINISH_REQ = BigInt(0xf8faf090);
const GW_LEAVE_DUEL_REQ = BigInt(0xf8fad282);
/** 对局回合结算上报（DuelRoundResultReportReq）→ onDuelSettle（对局结算发券）+ ACK */
const GW_DUEL_ROUND_RESULT_REPORT_REQ = BigInt(0xf8fa293a);
/** 交换信息（GetAllCreatureExchangeInfoReq）→ GetAllCreatureExchangeInfoResp（本地空状态） */
const GW_GET_ALL_EXCHANGE_INFO_REQ = BigInt(0xb7c21f3a);
const GW_GET_ALL_EXCHANGE_INFO_RESP = BigInt(0xb7c25f13);
/** 预设交换 / 发起交换 / 应答交换（单机无真实玩家 → ACK） */
const GW_PRESET_EXCHANGE_REQ = BigInt(0xb7c2369e);
const GW_CREATE_EXCHANGE_REQ = BigInt(0xb7c2394d);
const GW_ANSWER_EXCHANGE_REQ = BigInt(0xb7c2be4f);
/** 交换状态广播（CreatureExchangeStateNotify，收到仅记录日志） */
const GW_EXCHANGE_STATE_NOTIFY = BigInt(0xb7c283a3);
/** 生物管理请求（单机本地回官方 resp 或 {1:100} ACK） */
const GW_DELETE_CREATURE_REQ = BigInt(0xb7c264e3);
const GW_SET_CREATURE_LIKE_REQ = BigInt(0xb7c28d19);
const GW_SET_FOLLOWING_CREATURE_REQ = BigInt(0xb7c20b13);
const GW_SET_CREATURE_SQUAD_REQ = BigInt(0xb7c2cbf4);
/** 生物变更广播（CreatureAlterNotify，收到仅记录日志） */
const GW_CREATURE_ALTER_NOTIFY = BigInt(0xb7c2d119);

/** 巡展捕抓关卡（stage_table：act1arkhub_15 = "奇象收录时间！"） */
const SCAN_STAGE_ID = "act1arkhub_15";
/** 拟合对局关卡（stage_table：act1arkhub_08 = "奇象拟合对战场"） */
const DUEL_STAGE_ID = "act1arkhub_08";
/**
 * 私服本地捕捉遭遇生物兜底（StartCaptureReq 时 encounterCreatures 为空则回填，
 * 用于 EncounterCreatureNotify 推送与 onScanSettle 结算入参——单机无真实随机遭遇）。
 */
const CAPTURE_ENCOUNTER_CREATURES: number[] = [19005, 19016, 19060];

/* ---------- 应答构建（生物/捕捉/对局/交换，字段号对齐官服逆向） ---------- */

/**
 * CreatureBrief 消息体：{1:unique_id(ulong), 2:template_id(uint), 3:persona(uint)}
 * 权威字段：CreatureBrief.cs ProtoMember(1/2/3)。
 *
 * @param uniqueId - 生物个体唯一 id（会话内稳定即可）
 * @param templateId - 生物模板 id（arkdex creature_numId）
 * @param persona - 个性/变体（缺省 0）
 */
function buildCreatureBrief(uniqueId: bigint, templateId: number, persona = 0): Buffer {
  return Buffer.concat([fv(1, uniqueId), fv(2, templateId), fv(3, persona)]);
}

/**
 * 由生物模板 id 列表生成 CreatureBrief 数组（每人个体 id 取 0x100000000 递增基底，
 * 保证 neg-id 空间独立且稳定——单机遭遇/结算均引用同一批）。
 */
function buildCreatureBriefs(creatureTemplates: number[]): Buffer[] {
  return (creatureTemplates ?? []).map((t, i) =>
    buildCreatureBrief(BigInt(0x100000000) + BigInt(i + 1), t, 0),
  );
}

/**
 * CreatureBattleInfo 消息体：{1:creatures[](CreatureBrief), 2:stage_id, 3:capture_type}
 * 权威字段：CreatureBattleInfo.cs ProtoMember(1/2/3)。
 */
function buildCreatureBattleInfo(creatureBriefs: Buffer[], stageId: string, captureType = 1): Buffer {
  return Buffer.concat([
    ...creatureBriefs.map((b) => fb(1, b)),
    fb(2, Buffer.from(stageId, "utf8")),
    fv(3, captureType),
  ]);
}

/**
 * 捕捉开始响应（StartCaptureResp）：{1:code(uint), 2:battle_id}
 * 权威字段：StartCaptureResp.cs ProtoMember(1/2)。会话 battleId 由时间戳生成。
 */
function buildStartCaptureResp(): Buffer {
  const battleId = `cap_${BigInt.asUintN(32, BigInt(Date.now())).toString(16)}`;
  return Buffer.concat([fv(1, GW_CODE_OK), fb(2, Buffer.from(battleId, "utf8"))]);
}

/**
 * 遭遇生物通知（EncounterCreatureNotify，服务端在 StartCapture 后主动推）：
 * {1:battle_info=CreatureBattleInfo{...}}——客户端据此展示本次捕捉遭遇生物。
 * 权威字段：EncounterCreatureNotify.cs ProtoMember(1)、CreatureBattleInfo.cs。
 */
function buildEncounterCreatureNotify(creatureBriefs: Buffer[], stageId: string): Buffer {
  return fb(1, buildCreatureBattleInfo(creatureBriefs, stageId));
}

/**
 * 捕捉结算响应（EndCaptureResp）：{1:settle_info=ArkDexSettleInfo{1:is_success,
 * 2:end_time, 3:creatures[]}}——权威字段：EndCaptureResp.cs/ArkDexSettleInfo.cs。
 */
function buildEndCaptureResp(isSuccess: boolean, creatureBriefs: Buffer[]): Buffer {
  const settle = Buffer.concat([
    fv(1, isSuccess ? 1 : 0),
    fv(2, BigInt(Date.now())),
    ...creatureBriefs.map((b) => fb(3, b)),
  ]);
  return fb(1, settle);
}

/**
 * 捕捉信息查询响应（GetCaptureInfoResp）：{1:code, 2:battle_info}
 * 权威字段：GetCaptureInfoResp.cs ProtoMember(1/2)。单机回当前遭遇（可为空）。
 */
function buildGetCaptureInfoResp(creatureBattleInfo: Buffer): Buffer {
  return Buffer.concat([fv(1, GW_CODE_OK), fb(2, creatureBattleInfo)]);
}

/**
 * 对局入座响应（JoinDuelResp）：{1:code(int), 2:mode_type(int)}
 * 权威字段：JoinDuelResp.cs ProtoMember(1/2)。
 */
function buildJoinDuelResp(): Buffer {
  return Buffer.concat([fv(1, GW_CODE_OK), fv(2, 0)]);
}

/**
 * 对局入座广播（OnJoinDuelNotify，服务端入座后主动推）：
 * {1:duel_id, 2:stage_id, 3:battle_id, 4:mode_type}——权威字段：JoinDuelNotify.cs。
 * 单机最小化：仅 duel_id + stage_id + mode_type=0。
 */
function buildOnJoinDuelNotify(): Buffer {
  return Buffer.concat([
    fb(1, Buffer.from(`duel_${BigInt.asUintN(32, BigInt(Date.now())).toString(16)}`, "utf8")),
    fb(2, Buffer.from(DUEL_STAGE_ID, "utf8")),
    fv(4, 0),
  ]);
}

/**
 * 对局开始响应（StartDuelResp）：{1:code(int)=100}
 * 权威字段：StartDuelResp.cs ProtoMember(1)。
 */
function buildStartDuelResp(): Buffer {
  return Buffer.from([0x08, GW_CODE_OK]);
}

/**
 * 交换信息响应（GetAllCreatureExchangeInfoResp）：本地空状态。
 * 权威字段：GetAllCreatureExchangeInfoRsp.cs——{1:requests[](空), 2:exchange_type,
 * 3:player_avatars(空)}；单机无真实交换请求，按 Data 结构给空状态（仅 exchange_type=0）。
 */
function buildEmptyExchangeInfoResp(): Buffer {
  return fv(2, 0);
}

/* ---------- 帧处理 ---------- */

/** 捕捉信息查询（GetCaptureInfoReq：{1:creature_inst_id}）→ GetCaptureInfoResp {1:code, 2:battle_info} */
function handleGetCaptureInfo(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  logger.info("arkhub-gateway", `捕捉信息查询 → 捕捉信息 (uid=${ctx.state.uid || "?"})`);
  ctx.send(
    8,
    (frame.subID & ~0xffffffffn) | GW_CAPTURE_INFO_RESP,
    buildGetCaptureInfoResp(
      buildCreatureBattleInfo(buildCreatureBriefs(ctx.state.encounterCreatures), SCAN_STAGE_ID),
    ),
  );
}

/**
 * 捕捉开始（StartCaptureReq：{1:param=ArkDexStartParam{1:creature_inst_id,
 * 2:troop_index, 3:troop_info}}）→ StartCaptureResp{1:code, 2:battle_id}；
 * 随后服务端主动推 EncounterCreatureNotify——客户端据此展示。
 * 捕捉区：onScanStart（arkhubStartEncounter 生成/记录遭遇）；遭遇非空直接用，
 * 空则回填本地兜底集（单机无法从客户端拿真实随机遭遇）。
 */
function handleStartCapture(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const { state, opts } = ctx;
  if (CAPTURE_MAP_IDS.includes(state.currentMapId)) {
    try {
      opts.onScanStart?.(state.uid, state.currentMapId);
    } catch (e) {
      logger.warn("arkhub-gateway", `捕捉遭遇生成失败: ${(e as Error).message}`);
    }
    if (state.encounterCreatures.length === 0) {
      state.encounterCreatures = [...CAPTURE_ENCOUNTER_CREATURES];
    }
  }
  const encounterBriefs = buildCreatureBriefs(state.encounterCreatures);
  logger.info(
    "arkhub-gateway",
    `捕捉开始 (map=${state.currentMapId}) → StartCaptureResp + 遭遇 ${state.encounterCreatures.join(",") || "无"} (${SCAN_STAGE_ID})`,
  );
  ctx.send(8, (frame.subID & ~0xffffffffn) | GW_START_CAPTURE_RESP, buildStartCaptureResp());
  ctx.send(
    8,
    (frame.subID & ~0xffffffffn) | GW_ENCOUNTER_CREATURE_NOTIFY,
    buildEncounterCreatureNotify(encounterBriefs, SCAN_STAGE_ID),
  );
}

/**
 * 捕捉结束（EndCaptureReq：{1:battle_id, 2:param=ArkDexEndParam{1:complete_state,
 * 2:captured(packed)}}）→ EndCaptureResp{1:settle_info}。
 * 本地遭遇生物非空即判成功：onScanSettle(uid, captured)（arkhubEndScan），随后清空。
 */
function handleEndCapture(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  const { state, opts } = ctx;
  const captured = [...state.encounterCreatures];
  const isSuccess = captured.length > 0;
  if (isSuccess) {
    try {
      opts.onScanSettle?.(state.uid, captured);
    } catch (e) {
      logger.warn("arkhub-gateway", `捕捉结算奖励处理失败: ${(e as Error).message}`);
    }
  }
  state.encounterCreatures = [];
  logger.info(
    "arkhub-gateway",
    `捕捉结束 ${isSuccess ? `(捕获 ${captured.join(",")})` : "(未捕获)"} → settle_info`,
  );
  ctx.send(
    8,
    (frame.subID & ~0xffffffffn) | GW_END_CAPTURE_RESP,
    buildEndCaptureResp(isSuccess, buildCreatureBriefs(captured)),
  );
}

/** 对局入座（JoinDuelReq）→ JoinDuelResp；随后服务端主动推 OnJoinDuelNotify */
function handleJoinDuel(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  logger.info("arkhub-gateway", `对局入座 → JoinDuelResp + OnJoinDuelNotify (uid=${ctx.state.uid || "?"})`);
  ctx.send(8, (frame.subID & ~0xffffffffn) | GW_JOIN_DUEL_RESP, buildJoinDuelResp());
  ctx.send(8, (frame.subID & ~0xffffffffn) | GW_ON_JOIN_DUEL_NOTIFY, buildOnJoinDuelNotify());
}

/** 对局开始（StartDuelReq：BattleParam{1:duel_id, 2:battle_id}）→ StartDuelResp{1:code=100} */
function handleStartDuel(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  logger.info("arkhub-gateway", `对局开始 → StartDuelResp (uid=${ctx.state.uid || "?"})`);
  ctx.send(8, (frame.subID & ~0xffffffffn) | GW_START_DUEL_RESP, buildStartDuelResp());
}

/**
 * 对局回合结算上报（DuelRoundResultReportReq）→ 对局结算发券（onDuelSettle）+ ACK
 */
function handleDuelRoundResultReport(
  ctx: ArkhubGatewayHandlerContext,
  frame: ArkhubGatewayFrame,
): void {
  try {
    ctx.opts.onDuelSettle?.(ctx.state.uid);
  } catch (e) {
    logger.warn("arkhub-gateway", `对局结算奖励处理失败: ${(e as Error).message}`);
  }
  logger.info("arkhub-gateway", `对局回合结算上报 → 发券 + ACK (uid=${ctx.state.uid || "?"})`);
  ctx.send(8, frame.subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
}

/** 交换信息（GetAllCreatureExchangeInfoReq：{1:exchange_type}）→ 本地空状态 */
function handleGetAllExchangeInfo(
  ctx: ArkhubGatewayHandlerContext,
  frame: ArkhubGatewayFrame,
): void {
  logger.info("arkhub-gateway", `交换信息查询 → 空状态 (uid=${ctx.state.uid || "?"})`);
  ctx.send(
    8,
    (frame.subID & ~0xffffffffn) | GW_GET_ALL_EXCHANGE_INFO_RESP,
    buildEmptyExchangeInfoResp(),
  );
}

/** 服务端 fire-and-forget 请求的通用 ACK（{1:100}，subID+1 对齐 req→resp 错位规律） */
function ack(ctx: ArkhubGatewayHandlerContext, frame: ArkhubGatewayFrame): void {
  ctx.send(8, frame.subID + BigInt(1), Buffer.from([0x08, GW_CODE_OK]));
}

/** 交换状态广播（服务端下发）——收到仅记录日志，不回帧 */
function logOnly(ctx: ArkhubGatewayHandlerContext, _frame: ArkhubGatewayFrame): void {
  logger.info("arkhub-gateway", `交换状态广播 (uid=${ctx.state.uid || "?"})`);
}

/** 生物变更广播（服务端下发）——收到仅记录日志，不回帧 */
function logOnlyCreatureAlter(
  ctx: ArkhubGatewayHandlerContext,
  _frame: ArkhubGatewayFrame,
): void {
  logger.info("arkhub-gateway", `生物变更广播 (uid=${ctx.state.uid || "?"})`);
}

/** 注册捕捉/对局/生物/交换路由 */
export function registerPlayHandlers(router: ArkhubFrameRouter): void {
  // 捕捉
  router.registerLow(8, GW_CAPTURE_INFO_REQ, "捕捉信息Req(GetCaptureInfoReq)", handleGetCaptureInfo);
  router.registerLow(8, GW_START_CAPTURE_REQ, "捕捉开始(StartCaptureReq)", handleStartCapture);
  router.registerLow(8, GW_END_CAPTURE_REQ, "捕捉结束(EndCaptureReq)", handleEndCapture);
  // 对局
  router.registerLow(8, GW_JOIN_DUEL_REQ, "对局入座(JoinDuelReq)", handleJoinDuel);
  router.registerLow(8, GW_START_DUEL_REQ, "对局开始(StartDuelReq)", handleStartDuel);
  router.registerLow(8, GW_CANCEL_DUEL_REQ, "取消对局(CancelDuelReq)", ack);
  router.registerLow(8, GW_ROUND_PREPARE_REQ, "回合准备(RoundPrepareReq)", ack);
  router.registerLow(8, GW_UPLOAD_BATTLE_DATA_REQ, "战报上传(UploadBattleDataReq)", ack);
  router.registerLow(8, GW_LOADING_FINISH_REQ, "加载完成(LoadingFinishReq)", ack);
  router.registerLow(8, GW_LEAVE_DUEL_REQ, "离开对局(LeaveDuelReq)", ack);
  router.registerLow(
    8,
    GW_DUEL_ROUND_RESULT_REPORT_REQ,
    "回合结算上报(DuelRoundResultReportReq)",
    handleDuelRoundResultReport,
  );
  // 对局阶段广播（服务端下发——客户端不会主动发；log-only 覆盖 §11 全表）
  router.registerLow(8, BigInt(0xf8faf4f3), "阶段广播(DuelStageChangeNotify)", logOnly);
  // 生物管理
  router.registerLow(8, GW_DELETE_CREATURE_REQ, "删除生物(DeleteCreatureReq)", ack);
  router.registerLow(8, GW_SET_CREATURE_LIKE_REQ, "生物点赞(SetCreatureLikeReq)", ack);
  router.registerLow(8, GW_SET_FOLLOWING_CREATURE_REQ, "跟随宠物(SetFollowingCreatureReq)", ack);
  router.registerLow(8, GW_SET_CREATURE_SQUAD_REQ, "生物编队(SetCreatureSquadReq)", ack);
  router.registerLow(8, GW_CREATURE_ALTER_NOTIFY, "生物变更广播(CreatureAlterNotify)", logOnlyCreatureAlter);
  // 交换
  router.registerLow(8, GW_GET_ALL_EXCHANGE_INFO_REQ, "交换信息Req(GetAllCreatureExchangeInfoReq)", handleGetAllExchangeInfo);
  router.registerLow(8, GW_PRESET_EXCHANGE_REQ, "预设交换(PresetCreatureExchangeReq)", ack);
  router.registerLow(8, GW_CREATE_EXCHANGE_REQ, "发起交换(CreateCreatureExchangeReq)", ack);
  router.registerLow(8, GW_ANSWER_EXCHANGE_REQ, "应答交换(AnswerCreatureExchangeReq)", ack);
  router.registerLow(8, GW_EXCHANGE_STATE_NOTIFY, "交换状态广播(CreatureExchangeStateNotify)", logOnly);
}
