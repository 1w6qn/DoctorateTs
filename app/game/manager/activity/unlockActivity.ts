/**
 * activity 播种（DoctoratePy unlockActivity 移植）
 *
 * 仅在冻结模式（config.developer.timestamp != -1，即活动切换开启）时执行：
 * 按（可能冻结的）时间戳 ts：
 * - 修剪：`playerdata.activity[type][id]` 中 ts > rewardEndTime 的过期活动删除
 * - 播种：basicInfo 中 startTime <= ts <= rewardEndTime 的活动——
 *   BOSS_RUSH / TYPE_ACT* 默认状态、活动任务（ACTIVITY 任务组，可领取态）
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

/** BOSS_RUSH 默认遗物（relicList[0].relicId，缺省空） */
function defaultRelic(activityType: string, actId: string): string {
  const detail = (excel.ActivityTable.activity as Record<string, any>)?.[
    activityDetailKey(activityType)
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

    unlockStages(draft);
  });
}
