/**
 * 终末地 ODC（arkodc）路由
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.UI.ArkOdc.ArkOdcBattleStartRequest/ArkOdcTaskSavePositionRequest/
 * ArkOdcTriggerActionRequest/ArkOdcTaskRestartRequest 系列类；
 * 路由参考 OBS misc_bp（/arkodc/* 根路径），状态逻辑参考 ODPY arkodc 类
 * （写入 user.arkodc.topics[topicId].position / rewards）。
 */
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { PlayerDeltaResponse } from "../model/protocol/common";

const router = Router();

/** 终末地 ODC 开始战斗请求（CS: ArkOdcBattleStartRequest : DefaultStartBattleRequest） */
export interface ArkOdcBattleStartRequest {
  groupId: string;
  topicId: string;
  stageId?: string;
}

/** 终末地 ODC 开始战斗响应（CS: ArkOdcBattleStartResponse : DefaultStartBattleResponse） */
export interface ArkOdcBattleStartResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  apFailReturn: number;
  isApProtect: number;
  inApProtectPeriod: boolean;
  notifyPowerScoreNotEnoughIfFailed: boolean;
}

/** 终末地 ODC 战斗结算请求（CS: ArkOdcBattleFinishRequest : DefaultFinishBattleRequest） */
export interface ArkOdcBattleFinishRequest {
  data: string;
  battleData: { isCheat: string; completeTime: number };
  operationId?: string;
  actorId?: string;
}

/** 终末地 ODC 战斗结算响应（CS: ArkOdcBattleFinishResponse : DefaultFinishBattleResponse） */
export interface ArkOdcBattleFinishResponse extends PlayerDeltaResponse {
  result?: number;
  apFailReturn?: number;
  expScale?: number;
  goldScale?: number;
  rewards?: ItemBundle[];
  firstRewards?: ItemBundle[];
  unlockStages?: string[];
  unusualRewards?: ItemBundle[];
  additionalRewards?: ItemBundle[];
  furnitureRewards?: ItemBundle[];
  alert?: unknown[];
  suggestFriend?: boolean;
  pryResult?: unknown[];
}

/** 终末地 ODC 保存位置请求（CS: ArkOdcTaskSavePositionRequest） */
export interface ArkOdcSavePositionRequest {
  groupId?: string;
  topicId: string;
  x: number;
  y: number;
  z: number;
}

/** 终末地 ODC 保存位置响应（CS: ArkOdcTaskSavePositionResponse） */
export type ArkOdcSavePositionResponse = PlayerDeltaResponse;

/** 终末地 ODC 触发互动请求（CS: ArkOdcTriggerActionRequest） */
export interface ArkOdcTriggerActionRequest {
  groupId?: string;
  topicId?: string;
  operationId?: string;
  actorId?: string;
  avgId?: string | null;
  awardId?: string | null;
}

/** 终末地 ODC 触发互动响应（CS: ArkOdcTriggerActionResponse { items }） */
export interface ArkOdcTriggerActionResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 终末地 ODC 重启任务请求（CS: ArkOdcTaskRestartRequest） */
export interface ArkOdcRestartRequest {
  groupId?: string;
  topicId?: string;
}

/** 终末地 ODC 重启任务响应（CS: ArkOdcTaskRestartResponse） */
export type ArkOdcRestartResponse = PlayerDeltaResponse;

/** 终末地 ODC 开始战斗（CS: ArkOdcBattleStartRequest；参考 OBS 固定 battleId stub） */
router.post("/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ArkOdcBattleStartRequest;
  res.send({
    result: 0,
    battleId: "00000000-0000-0000-0000-000000000000",
    apFailReturn: 0,
    isApProtect: 0,
    inApProtectPeriod: false,
    notifyPowerScoreNotEnoughIfFailed: false,
    ...player.delta,
  } satisfies ArkOdcBattleStartResponse);
});

/** 终末地 ODC 战斗结算（CS: ArkOdcBattleFinishRequest；参考 OBS 空奖励 stub） */
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ArkOdcBattleFinishRequest;
  res.send({
    result: 0,
    apFailReturn: 0,
    expScale: 1.2,
    goldScale: 1.2,
    rewards: [],
    firstRewards: [],
    unlockStages: [],
    unusualRewards: [],
    additionalRewards: [],
    furnitureRewards: [],
    alert: [],
    suggestFriend: false,
    pryResult: [],
    ...player.delta,
  } satisfies ArkOdcBattleFinishResponse);
});

/**
 * 终末地 ODC 保存位置（CS: ArkOdcTaskSavePositionRequest）
 * 参考 ODPY arkodc.savePosition：写入 arkodc.topics[topicId].position
 */
router.post("/savePosition", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ArkOdcSavePositionRequest;
  await player.update(async (draft) => {
    // PlayerDataModel 未声明 arkodc 字段（官服快照有），用 (draft as any) 访问
    const arkodc = (draft as any).arkodc as any;
    if (!arkodc?.topics?.[body.topicId]) return;
    arkodc.topics[body.topicId].position = { x: body.x, y: body.y, z: body.z };
  });
  res.send(player.delta satisfies ArkOdcSavePositionResponse);
});

/**
 * 终末地 ODC 触发互动（CS: ArkOdcTriggerActionRequest）
 * 参考 ODPY arkodc.triggerInteraction：awardId 存在且无 avgId 时标记
 * topics[topicId].rewards[awardId]=1；奖励返回空（参考 OBS）
 */
router.post("/triggerInteraction", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ArkOdcTriggerActionRequest;
  const { topicId, awardId, avgId } = body;
  await player.update(async (draft) => {
    // PlayerDataModel 未声明 arkodc 字段（官服快照有），用 (draft as any) 访问
    const arkodc = (draft as any).arkodc as any;
    if (!arkodc?.topics?.[topicId!]) return;
    if (awardId && !avgId) {
      if (!arkodc.topics[topicId!].rewards) {
        arkodc.topics[topicId!].rewards = {};
      }
      arkodc.topics[topicId!].rewards[awardId] = 1;
    }
  });
  res.send({
    items: [],
    ...player.delta,
  } satisfies ArkOdcTriggerActionResponse);
});

/** 终末地 ODC 重启任务（CS: ArkOdcTaskRestartRequest；stub 仅返回增量） */
router.post("/restart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  req.body as ArkOdcRestartRequest;
  res.send(player.delta satisfies ArkOdcRestartResponse);
});

export default router;
