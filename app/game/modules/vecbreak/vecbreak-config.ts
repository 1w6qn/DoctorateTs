/**
 * 矢量突破V2（vecbreak）活动配置读取
 *
 * 数据源：excel `ActivityTable.activity.vecBreakV2[activityId]`（当前版本含 `act1break` 与 `act2break`）与
 * `ActivityTable.basicInfo[activityId]`（`startTime`/`endTime`）。
 * 每季配置含 `offenseStageDict`（核心突破 12 层）/ `hardStageDict`（全力以赴）/ `defenseBasicDict`（特别战线）
 * / `stageRewardDict`（各关卡的里程碑点数：首通 `completeRewardCnt`、重复 `normalRewardCnt`、限时 `limitReward`）
 * / `milestoneList` / `constData`。
 */
import excel from "@excel/excel";

/** 单关卡里程碑奖励配置（stageRewardDict[stageId]） */
export interface VecBreakStageReward {
  stageId: string;
  /** 首通奖励点数 */
  completeRewardCnt: number;
  /** 重复通关奖励点数 */
  normalRewardCnt: number;
  /** 限时奖励（特别战线用；窗口外不可领） */
  limitReward: { startTs: number; endTs: number; rewardCnt: number } | null;
}

/** vecBreakV2 活动字典 */
function vecBreakDict(): Record<string, any> {
  return ((excel.ActivityTable as any)?.activity?.vecBreakV2 ?? {}) as Record<string, any>;
}

/**
 * 活动字典中全部矢量突破赛季 id（按 basicInfo.startTime **降序**，最新一期在前）
 * @returns 赛季 id 列表
 */
export function vecBreakActivityIds(): string[] {
  const basic = ((excel.ActivityTable as any)?.basicInfo ?? {}) as Record<string, any>;
  return Object.keys(vecBreakDict()).sort(
    (a, b) => Number(basic[b]?.startTime ?? 0) - Number(basic[a]?.startTime ?? 0),
  );
}

/**
 * 当前（最新一期）矢量突破赛季 id
 *
 * 修复依据：原实现把赛季 id 硬编码为 `act1break`，而当前版本的活动配置键为 `act2break`
 * （`basicInfo.act2break.startTime = 1771920000` > `act1break.startTime = 1747296000`）。
 * @returns 赛季 id（无配置时回退 act2break）
 */
export function currentVecBreakActivityId(): string {
  return vecBreakActivityIds()[0] ?? "act2break";
}

/**
 * 取指定（或默认当前）赛季的配置
 * @param activityId - 赛季 id；缺省取当前赛季
 * @returns 赛季 id 与配置对象；未命中返回 undefined
 */
export function vecBreakDetail(
  activityId?: string,
): { activityId: string; detail: Record<string, any> } | undefined {
  const dict = vecBreakDict();
  const id = activityId && dict[activityId] ? activityId : currentVecBreakActivityId();
  const detail = dict[id];
  return detail ? { activityId: id, detail } : undefined;
}

/**
 * 取关卡里程碑点数配置
 * @param activityId - 赛季 id
 * @param stageId - 关卡 id
 * @returns 奖励配置；未命中返回 undefined
 */
export function vecBreakStageReward(
  activityId: string | undefined,
  stageId: string,
): VecBreakStageReward | undefined {
  const cfg = vecBreakDetail(activityId);
  const row = cfg?.detail?.stageRewardDict?.[stageId];
  return row ? (row as VecBreakStageReward) : undefined;
}

/**
 * 计算一次通关应发放的里程碑点数
 *
 * 官方口径（stageRewardDict）：关底首次通关给 `completeRewardCnt`，其后重复通关给 `normalRewardCnt`；
 * 特别战线（sp*）还有限时奖励 `limitReward.rewardCnt`（仅在 `[startTs, endTs]` 窗口内、且未领过时发放）。
 * @param activityId - 赛季 id
 * @param stageId - 关卡 id
 * @param firstClear - 是否首次通关
 * @param nowTs - 当前时间（秒）
 * @param timeLimitedClaimed - 该关限时奖励是否已领
 * @returns `{ point, timeLimited }`：点数与本次是否领取了限时奖励
 */
export function vecBreakMilestoneGain(
  activityId: string | undefined,
  stageId: string,
  firstClear: boolean,
  nowTs: number,
  timeLimitedClaimed: boolean,
): { point: number; timeLimited: boolean } {
  const row = vecBreakStageReward(activityId, stageId);
  if (!row) return { point: 0, timeLimited: false };
  let point = 0;
  if (firstClear) {
    point += Number(row.completeRewardCnt ?? 0);
  } else {
    point += Number(row.normalRewardCnt ?? 0);
  }
  let timeLimited = false;
  const limit = row.limitReward;
  if (
    firstClear &&
    !timeLimitedClaimed &&
    limit &&
    nowTs >= Number(limit.startTs ?? 0) &&
    nowTs <= Number(limit.endTs ?? 0)
  ) {
    point += Number(limit.rewardCnt ?? 0);
    timeLimited = true;
  }
  return { point, timeLimited };
}

/**
 * 赛季全部关卡 id（核心突破 + 全力以赴 + 特别战线）
 * @param activityId - 赛季 id
 * @returns 关卡 id 列表
 */
export function vecBreakStageIds(activityId?: string): string[] {
  const detail = vecBreakDetail(activityId)?.detail;
  if (!detail) return [];
  return [
    ...Object.keys(detail.offenseStageDict ?? {}),
    ...Object.keys(detail.hardStageDict ?? {}),
    ...Object.keys(detail.defenseBasicDict ?? {}),
  ];
}

/**
 * 核心突破关卡按层号升序（offenseStageDict[].level）
 * @param activityId - 赛季 id
 * @returns `{ stageId, level }` 列表
 */
export function vecBreakOffenseStages(
  activityId?: string,
): { stageId: string; level: number }[] {
  const dict = vecBreakDetail(activityId)?.detail?.offenseStageDict ?? {};
  return Object.values(dict)
    .map((s: any) => ({ stageId: String(s.stageId), level: Number(s.level ?? 0) }))
    .sort((a, b) => a.level - b.level);
}
