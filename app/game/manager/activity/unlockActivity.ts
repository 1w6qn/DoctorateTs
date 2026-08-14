/**
 * activity 播种（DoctoratePy unlockActivity 移植）
 *
 * 仅在冻结模式（config.developer.timestamp != -1，即活动切换开启）时执行：
 * 按（可能冻结的）时间戳 ts：
 * - 修剪：`playerdata.activity[type][id]` 中 ts > rewardEndTime 的过期活动删除
 * - 播种：basicInfo 中 startTime <= ts <= rewardEndTime 的活动——
 *   BOSS_RUSH / TYPE_ACT* 默认状态、活动任务（ACTIVITY 任务组，可领取态）、
 *   ARK_HUB（奇象巡展方舟枢纽）活动状态、arkodc 主题（ODC 地图 varSeqs/rewards/position）
 * - 关卡：unlockCondition 链扫描解锁可达关卡（仿 battle.finishStoryStage）
 *
 * 真实时间模式（timestamp 缺省/-1）不做任何改动，保持现有行为。
 */
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import excel from "@excel/excel";
import { userTimestamp } from "@utils/time";
import { logger } from "@utils/logger";
import config from "../../../config";

/** 解锁条件完成度（PlayerBattleRank 字符串）→ 关卡 state 数值档位（与 battle.ts 一致） */
const completeStateRank: Record<string, number> = { FAIL: 1, PASS: 2, COMPLETE: 3 };

/** excel activity 字典键：首字母小写（basicInfo.type 大写枚举 → activity 键 bOSS_RUSH） */
function activityDetailKey(type: string): string {
  return type.charAt(0).toLowerCase() + type.slice(1);
}

/**
 * 从 excel ActivityTable.activity 字典按枚举名定位实际键
 *
 * 修复：excel activity 字典键随数据版本大小写多变（旧数据 dEFAULT/tYPE_ACT3D0 等
 * 坏键、解码规范的 default/typeAct3D0），代码按 lowerFirst(枚举) 读取恒有错位风险；
 * 改为大小写/下划线不敏感匹配——任意版本下都能命中实际键。
 * @param type - basicInfo.type 枚举名（如 "TYPE_ACT3D0" / "COLLECTION"）
 * @returns 字典实际键（未命中返回 undefined）
 */
export function activityDictKey(type: string): string | undefined {
  const norm = type.replace(/_/g, "").toLowerCase();
  const dict = (excel.ActivityTable.activity ?? {}) as Record<string, unknown>;
  return Object.keys(dict).find(
    (k) => k.replace(/_/g, "").toLowerCase() === norm,
  );
}

/** BOSS_RUSH 默认遗物（relicList[0].relicId，缺省空） */
function defaultRelic(activityType: string, actId: string): string {
  const detail = (excel.ActivityTable.activity as Record<string, any>)?.[
    activityDictKey(activityType) ?? activityDetailKey(activityType)
  ]?.[actId];
  return detail?.relicList?.[0]?.relicId ?? "";
}

/** TYPE_ACT 信赖加成干员（charword startTimeWithTypeDict 按活动 startTime 匹配，缺省空） */
function favorListFor(startTime: number): string[] {
  try {
    const dict: any = (excel.CharWordTable as any)?.startTimeWithTypeDict;
    if (!dict) return [];
    for (const lang of Object.values(dict) as any[]) {
      for (const item of (lang ?? []) as any[]) {
        if (item?.timestamp === startTime && Array.isArray(item.charSet)) {
          return item.charSet;
        }
      }
    }
  } catch (error) {
    logger.warn("Activity", `charword 表读取失败，信赖列表留空: ${(error as Error).message}`);
  }
  return [];
}

/** 关卡解锁：unlockCondition 链扫描，条件满足且缺失的关卡写入默认 state */
function unlockStages(draft: any): void {
  if (!draft.dungeon) return;
  const stages = excel.StageTable.stages;
  const dungeonStages = (draft.dungeon.stages = draft.dungeon.stages || {});
  for (const [stageId, stage] of Object.entries(stages) as [string, any][]) {
    const conditions = stage?.unlockCondition ?? [];
    if (conditions.length === 0) {
      // 无条件关卡（主线起点等）直接解锁
      if (!dungeonStages[stageId]) {
        dungeonStages[stageId] = defaultStageState(stageId);
      }
      continue;
    }
    let pass = true;
    for (const condition of conditions) {
      const condStage = dungeonStages[condition.stageId];
      const need = completeStateRank[condition.completeState] ?? 0;
      if (!condStage || condStage.state < need) {
        pass = false;
        break;
      }
    }
    if (pass && !dungeonStages[stageId]) {
      dungeonStages[stageId] = defaultStageState(stageId);
    }
  }
}

/** ARK_HUB 活动默认状态（奇象巡展方舟枢纽；参考官服 syncData 快照形状） */
function defaultArkhubState(): object {
  // 空队伍槽 ×4（客户端展示 4 个可用编队位，参考官服快照 squads 数组形状）
  return {
    coin: 0,
    secretary: "",
    secretarySkinId: "",
    secretarySkinSp: false,
    protectTs: -1,
    squads: [
      { slots: [] },
      { slots: [] },
      { slots: [] },
      { slots: [] },
    ],
    globalBan: false,
  };
}

/** TYPE_ACT53SIDE（奇象巡展主活动）默认状态（官方形状：actCoin/campaignCnt/favorList） */
function defaultAct53SideState(startTime: number): object {
  return {
    actCoin: 0,
    campaignCnt: 0,
    favorList: favorListFor(startTime),
  };
}

/**
 * 播种 arkodc 主题（ODC 地图状态：topics[topicId].varSeqs/rewards/position）
 * topicId 取自 activity.tYPE_ACT53SIDE[actId].constData.arkOdcTopicId
 */
function seedArkOdcTopics(draft: any): void {
  // 修复：硬编码坏键 tYPE_ACT53SIDE → 动态查键（数据版本键名多变）
  const detail = excel.ActivityTable.activity?.[
    activityDictKey("TYPE_ACT53SIDE") ?? "tYPE_ACT53SIDE"
  ];
  if (!detail) return;
  for (const [actId, data] of Object.entries(detail) as [string, any][]) {
    const topicId = data?.constData?.arkOdcTopicId;
    if (!topicId) continue;
    if (!draft.arkodc) draft.arkodc = {};
    if (!draft.arkodc.topics) draft.arkodc.topics = {};
    if (!draft.arkodc.topics[topicId]) {
      draft.arkodc.topics[topicId] = {
        varSeqs: {},
        rewards: {},
        position: { x: 0, y: 0, z: 0 },
      };
    }
  }
}

/** 关卡默认状态（#f#/hard_/tr_ 开头为无体力/练习关卡——noCostCnt 0，其余 1） */
function defaultStageState(stageId: string): object {
  let noCostCnt = 1;
  for (const marker of ["#f#", "hard_", "tr_"]) {
    if (stageId.includes(marker)) {
      noCostCnt = 0;
      break;
    }
  }
  return {
    stageId,
    practiceTimes: 0,
    completeTimes: 0,
    startTimes: 0,
    state: 0,
    hasBattleReplay: 0,
    noCostCnt,
  };
}

/**
 * 活动播种入口（冻结模式执行；真实模式 no-op）
 * @param player - 目标玩家
 */
export async function unlockActivity(player: PlayerDataManager): Promise<void> {
  // 仅冻结模式（活动切换开启）执行——真实时间（-1/缺省）零改动
  const frozen = config.developer?.timestamp;
  if (frozen === undefined || frozen === -1) return;
  const ts = userTimestamp();
  await player.update(async (draft) => {
    const basicInfo = excel.ActivityTable.basicInfo;

    // 修剪：过期活动删除（ts > rewardEndTime）
    if (draft.activity) {
      for (const type of Object.keys(draft.activity)) {
        for (const actId of Object.keys(draft.activity[type])) {
          const info = basicInfo[actId];
          if (info && ts > info.rewardEndTime) {
            delete draft.activity[type][actId];
          }
        }
      }
    } else {
      draft.activity = {};
    }

    // 任务组播种依赖（ACTIVITY 任务组可能被 MissionManager.init 清空——播种在其后执行）
    draft.mission = draft.mission || ({} as any);
    draft.mission.missions = draft.mission.missions || {};

    // 播种：窗口内活动默认状态 + 活动任务 + 关卡
    for (const [actId, info] of Object.entries(basicInfo)) {
      // 防御：basicInfo 含 null 占位条目（20/331）
      if (!info || typeof info !== "object") continue;
      if (!(info.startTime <= ts && ts <= info.rewardEndTime)) continue;
      const type = info.type;
      draft.activity[type] = draft.activity[type] || {};
      const existing = draft.activity[type][actId];

      if (type === "BOSS_RUSH" && !existing) {
        const relic = defaultRelic(type, actId);
        draft.activity[type][actId] = {
          milestone: { point: 0, got: [] },
          relic: {
            token: { current: 0, total: 0 },
            unlockedRelicLevelDic: relic ? { [relic]: 1 } : {},
            selectingRelicId: "",
          },
          bestWaveDic: {},
        };
      } else if (type === "ARK_HUB" && !existing) {
        // 奇象巡展方舟枢纽（官方形状：coin/secretary/squads/globalBan）
        draft.activity[type][actId] = defaultArkhubState();
      } else if (type === "TYPE_ACT53SIDE" && !existing) {
        // 奇象巡展主活动（官方形状：actCoin/campaignCnt/favorList，与通用 TYPE_ACT 的 coin/news 不同）
        draft.activity[type][actId] = defaultAct53SideState(info.startTime);
      } else if (type.startsWith("TYPE_ACT") && !existing) {
        draft.activity[type][actId] = {
          coin: 0,
          favorList: favorListFor(info.startTime),
          news: {},
        };
      }

      // 活动任务：missionGroup[id].missionIds → ACTIVITY 组播种（state:2 + value==target，可直接领取）
      const group = excel.ActivityTable.missionGroup.find((g) => g.id === actId);
      if (group) {
        draft.mission.missions["ACTIVITY"] = draft.mission.missions["ACTIVITY"] || {};
        for (const missionId of group.missionIds) {
          if (!draft.mission.missions["ACTIVITY"][missionId]) {
            draft.mission.missions["ACTIVITY"][missionId] = {
              state: 2,
              progress: [{ value: 1, target: 1 }],
            };
          }
        }
      }
    }

    // 奇象巡展 ODC 主题（playerdata.arkodc.topics[topicId]）——客户端据此渲染 ODC 地图状态
    seedArkOdcTopics(draft);

    unlockStages(draft);
  });
}
