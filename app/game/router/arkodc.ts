/**
 * 奇象巡展（arkodc，活动模式）路由
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
import excel from "@excel/excel";
import { decryptBattleData } from "@utils/crypt";
import { now } from "@utils/time";
import { PlayerDeltaResponse } from "../model/protocol/common";

const router = Router();

/** 当前 ODC 战斗 topic（battleStart 记录，battleFinish 消费；参考 ODPY global arkodc_topic） */
// 修复：模块级单例多账号串扰 → 按 uid 存储
const arkOdcTopics = new Map<string, string>();

/**
 * 应用 varSeqList 到 arkodc 主题状态（参考 ODPY：bool/end/removed 置 1，其余累加）
 */
function applyVarSeqList(
  arkodcTopic: any,
  varSeqList: string[] | undefined,
  blackSet: Set<string> = new Set(["bool", "end", "removed"]),
  skipContain?: string[],
): void {
  if (!varSeqList?.length) return;
  for (const varSeq of varSeqList) {
    if (blackSet.has(varSeq)) continue;
    if (skipContain?.some((s) => varSeq.includes(s))) continue;
    if (["bool", "end", "removed"].some((s) => varSeq.includes(s))) {
      arkodcTopic.varSeqs[varSeq] = 1;
    } else {
      arkodcTopic.varSeqs[varSeq] = (arkodcTopic.varSeqs[varSeq] ?? 0) + 1;
    }
  }
}

/**
 * 惰性获取（并播种）arkodc 主题——draft.arkodc.topics[topicId] 不存在时创建默认结构。
 * 奇象巡展主题未在解锁播种中创建（真实时间模式/旧存档）时，路由不再静默丢弃。
 */
function ensureArkOdcTopic(draft: any, topicId: string): any {
  if (!draft.arkodc) draft.arkodc = {};
  if (!draft.arkodc.topics) draft.arkodc.topics = {};
  let topic = draft.arkodc.topics[topicId];
  if (!topic) {
    topic = draft.arkodc.topics[topicId] = {
      varSeqs: {},
      rewards: {},
      position: { x: 0, y: 0, z: 0 },
    };
  }
  if (!topic.varSeqs) topic.varSeqs = {};
  if (!topic.rewards) topic.rewards = {};
  if (!topic.position) topic.position = { x: 0, y: 0, z: 0 };
  return topic;
}

/** 奇象巡展 ODC 开始战斗请求（CS: ArkOdcBattleStartRequest : DefaultStartBattleRequest） */
export interface ArkOdcBattleStartRequest {
  groupId: string;
  topicId: string;
  stageId?: string;
}

/** 奇象巡展 ODC 开始战斗响应（CS: ArkOdcBattleStartResponse : DefaultStartBattleResponse） */
export interface ArkOdcBattleStartResponse extends PlayerDeltaResponse {
  result: number;
  battleId: string;
  apFailReturn: number;
  isApProtect: number;
  inApProtectPeriod: boolean;
  notifyPowerScoreNotEnoughIfFailed: boolean;
}

/** 奇象巡展 ODC 战斗结算请求（CS: ArkOdcBattleFinishRequest : DefaultFinishBattleRequest） */
export interface ArkOdcBattleFinishRequest {
  data: string;
  battleData: { isCheat: string; completeTime: number };
  operationId?: string;
  actorId?: string;
}

/** 奇象巡展 ODC 战斗结算响应（CS: ArkOdcBattleFinishResponse : DefaultFinishBattleResponse） */
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

/** 奇象巡展 ODC 保存位置请求（CS: ArkOdcTaskSavePositionRequest） */
export interface ArkOdcSavePositionRequest {
  groupId?: string;
  topicId: string;
  x: number;
  y: number;
  z: number;
}

/** 奇象巡展 ODC 保存位置响应（CS: ArkOdcTaskSavePositionResponse） */
export type ArkOdcSavePositionResponse = PlayerDeltaResponse;

/** 奇象巡展 ODC 触发互动请求（CS: ArkOdcTriggerActionRequest） */
export interface ArkOdcTriggerActionRequest {
  groupId?: string;
  topicId?: string;
  operationId?: string;
  actorId?: string;
  avgId?: string | null;
  awardId?: string | null;
}

/** 奇象巡展 ODC 触发互动响应（CS: ArkOdcTriggerActionResponse { items }） */
export interface ArkOdcTriggerActionResponse extends PlayerDeltaResponse {
  items: ItemBundle[];
}

/** 奇象巡展 ODC 重启任务请求（CS: ArkOdcTaskRestartRequest） */
export interface ArkOdcRestartRequest {
  groupId?: string;
  topicId?: string;
}

/** 奇象巡展 ODC 重启任务响应（CS: ArkOdcTaskRestartResponse） */
export type ArkOdcRestartResponse = PlayerDeltaResponse;

/** 奇象巡展 ODC 开始战斗（CS: ArkOdcBattleStartRequest；参考 OBS 固定 battleId stub） */
router.post("/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ArkOdcBattleStartRequest;
  // 参考 ODPY：记录 topic 供 battleFinish 使用
  if (body.topicId) arkOdcTopics.set(player.uid, body.topicId);
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

/**
 * 奇象巡展 ODC 战斗结算（CS: ArkOdcBattleFinishRequest；参考 ODPY arkodcBattleFinish）
 * 解密战斗数据判定是否完成（q001_logic_after_bat_p1 需非中断/非放弃；
 * 其余按 completeState 2/3 为完成）——完成后按 actorData.actorShowCondition 推进 varSeqs
 */
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ArkOdcBattleFinishRequest;
  const { operationId, actorId } = body;
  const emptyResult = {
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
    wave: 0,
    milestoneBefore: 0,
    milestoneAdd: 0,
    isMileStoneMax: false,
    tokenAdd: 0,
    isTokenMax: false,
    items: [],
  };

  let complete = false;
  try {
    const battleData = await decryptBattleData(
      body.data,
      player._playerdata.pushFlags.status,
    );
    if (actorId === "q001_logic_after_bat_p1") {
      complete = !battleData.interrupt && !battleData.giveUp;
    } else {
      complete = battleData.completeState === 2 || battleData.completeState === 3;
    }
  } catch {
    complete = false;
  }
  if (!complete) {
    return res.send({
      ...emptyResult,
      ...player.delta,
    } satisfies ArkOdcBattleFinishResponse);
  }

  // 完成后推进 actorData.actorShowCondition 的 varSeqs
  const topicId = arkOdcTopics.get(player.uid) ?? "";
  const arkvent = (excel as any).ArkventTable;
  const actorData = arkvent?.arkventDataMap?.[topicId]?.taskData?.actorData?.[actorId!];
  if (actorData?.actorShowCondition) {
    await player.update(async (draft) => {
      const arkTopic = ensureArkOdcTopic(draft, topicId);
      for (const condition of actorData.actorShowCondition) {
        applyVarSeqList(arkTopic, condition.varSeqList);
      }
    });
  }
  arkOdcTopics.delete(player.uid);

  res.send({
    ...emptyResult,
    ...player.delta,
  } satisfies ArkOdcBattleFinishResponse);
});

/**
 * 奇象巡展 ODC 保存位置（CS: ArkOdcTaskSavePositionRequest）
 * 参考 ODPY arkodc.savePosition：写入 arkodc.topics[topicId].position
 */
router.post("/savePosition", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ArkOdcSavePositionRequest;
  await player.update(async (draft) => {
    const arkTopic = ensureArkOdcTopic(draft, body.topicId);
    arkTopic.position = { x: body.x, y: body.y, z: body.z };
  });
  res.send(player.delta satisfies ArkOdcSavePositionResponse);
});

/**
 * 奇象巡展 ODC 触发互动（CS: ArkOdcTriggerActionRequest）
 * 参考 ODPY arkodc.triggerInteraction：awardId 存在且无 avgId 时标记
 * topics[topicId].rewards[awardId]=1；奖励返回空（参考 OBS）
 */
router.post("/triggerInteraction", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ArkOdcTriggerActionRequest;
  const { topicId, awardId, avgId, actorId } = body;
  const arkvent = (excel as any).ArkventTable;
  let items: ItemBundle[] = [];

  await player.update(async (draft) => {
    const arkTopic = ensureArkOdcTopic(draft, topicId!);
    // 宝箱部分（awardId 存在且无 avgId，参考 ODPY）
    if (awardId && !avgId) {
      arkTopic.rewards[awardId] = 1;
      const rewardGroup = arkvent?.odcDataMap?.[topicId!]?.rewardGroups?.[awardId];
      if (rewardGroup) items = rewardGroup;
      // awardId 以 q 结尾 → 触发关联 actor 的 varSeqs 推进
      if (awardId.length >= 5 && awardId[awardId.length - 5] === "q") {
        const actorDataMap = arkvent?.arkventDataMap?.[topicId!]?.taskData?.actorData ?? {};
        for (const currentTaskData of Object.values(actorDataMap) as any[]) {
          const triggerOps = currentTaskData?.actorTriggerOperations ?? {};
          let found = false;
          for (const opsList of Object.values(triggerOps) as any[]) {
            if (!Array.isArray(opsList)) continue;
            for (const operation of opsList) {
              const awardIdValue = operation?.operationParams?.awardId ?? "";
              if (String(awardIdValue).startsWith(String(awardId))) {
                found = true;
                break;
              }
            }
            if (found) break;
          }
          if (found) {
            const showCond = currentTaskData?.actorShowCondition?.[1]?.varSeqList;
            if (Array.isArray(showCond)) {
              for (const varSeq of showCond) {
                const varSeqInt = (arkTopic.varSeqs[varSeq] ?? 0) + 1;
                arkTopic.varSeqs[varSeq] = varSeqInt;
                if (String(varSeq).endsWith("_banner_showed")) {
                  const varSeq1 = String(varSeq).slice(0, 4) + "_end";
                  arkTopic.varSeqs[varSeq1] = 1;
                }
              }
            }
            break;
          }
        }
      }
    } else if (avgId && !awardId && actorId) {
      // 任务部分（参考 ODPY：actorShowCondition varSeqList 推进，黑名单过滤）
      const blackSet = new Set(["act53side", "end", "banner_showed", "_unlocked"]);
      const actorData = arkvent?.arkventDataMap?.[topicId!]?.taskData?.actorData?.[actorId];
      if (!actorData) return;
      if (
        ["worker_a_", "worker_b_", "worker_c_"].some((s) => String(avgId).includes(s)) ||
        ["_a", "_b", "_c"].some((s) => String(avgId).endsWith(s)) ||
        ["_bat", "_pros_prog_5", "_fighting", "_open", "_jxt"].some((s) =>
          String(avgId).endsWith(s),
        ) ||
        ["q003_ia_right", "q003_ia_up"].some((s) => String(actorId).startsWith(s))
      ) {
        blackSet.add("_prog");
      }
      if (["zone_unlock", "global_unlock"].some((s) => String(actorId).startsWith(s))) {
        blackSet.delete("end");
        blackSet.delete("_unlocked");
      }
      const varSeqSet = new Set<string>();
      for (const condition of actorData.actorShowCondition ?? []) {
        for (const varSeq of condition.varSeqList ?? []) {
          if ([...blackSet].some((s) => String(varSeq).includes(s))) continue;
          varSeqSet.add(varSeq);
        }
      }
      const avgIdStr = String(avgId);
      if (avgIdStr.endsWith("intro")) {
        for (const v of [...varSeqSet]) {
          if (v.includes("talked") || v.includes("removed")) varSeqSet.delete(v);
        }
      }
      for (const varSeq of varSeqSet) {
        if (["bool", "end", "removed"].some((s) => varSeq.includes(s))) {
          arkTopic.varSeqs[varSeq] = 1;
        } else {
          arkTopic.varSeqs[varSeq] = (arkTopic.varSeqs[varSeq] ?? 0) + 1;
        }
      }
      if (actorId === "q003_trademan_open_p1") {
        arkTopic.varSeqs["q003_prog"] = (arkTopic.varSeqs["q003_prog"] ?? 0) + 1;
        arkTopic.varSeqs["q003_gpm_a_talk_done"] = 1;
        arkTopic.varSeqs["q003_gpm_b_talk_done"] = 1;
      }
    }
  });

  // 宝箱奖励真实发放（响应 items 仅客户端展示用，物品进背包经 items:get）
  if (items.length > 0) {
    await player._trigger.emit("items:get", [items]);
  }

  res.send({
    items,
    ...player.delta,
  } satisfies ArkOdcTriggerActionResponse);
});

/**
 * 奇象巡展 ODC 重启任务（CS: ArkOdcTaskRestartRequest；参考 ODPY arkodcRestart）
 * 重置主题 varSeqs（deleted delta 下发被删 key 列表）+ position 置空
 */
router.post("/restart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ArkOdcRestartRequest;
  let deletedKeys: string[] = [];
  await player.update(async (draft) => {
    const arkTopic = ensureArkOdcTopic(draft, body.topicId!);
    deletedKeys = Object.keys(arkTopic.varSeqs ?? {});
    arkTopic.varSeqs = {};
    arkTopic.position = null;
  });
  res.send({
    playerDataDelta: {
      modified: {
        arkodc: { topics: { [body.topicId!]: { varSeqs: {} } } },
      },
      deleted: {
        arkodc: { topics: { [body.topicId!]: { varSeqs: deletedKeys } } },
      },
    },
  } satisfies ArkOdcRestartResponse);
});

export default router;
