/**
 * 矢量突破V2（vecbreak）活动配置读取
 *
 * 数据源：excel `ActivityTable.activity.typeActVecBreakV2Data[activityId]`（当前版本含 `act1break` 与 `act2break`）
 * 与 `ActivityTable.basicInfo[activityId]`（`startTime`/`endTime`）。
 * 每季配置含 `offenseStageDict`（核心突破 12 层）/ `hardStageDict`（全力以赴）/ `defenseBasicDict`（特别战线）
 * / `stageRewardDict`（各关卡的里程碑点数：首通 `completeRewardCnt`、重复 `normalRewardCnt`、限时 `limitReward`）
 * / `milestoneList` / `constData`。
 *
 * 修复（2026-09-12）：原实现读 `activity.vecBreakV2`，而官方表字段名是
 * `activity.typeActVecBreakV2Data`（CS 签名 `ActivityTable.ActivityDetailTable.typeActVecBreakV2Data`，
 * 2.7.71 实锤）——赛季字典恒为空 → 关卡清单为空、里程碑点数恒不发放。
 */
import excel from "@excel/excel";
import { isJsonObject, type JsonObject, type JsonValue } from "@excel/json-value";

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

/** 限时奖励窗口 */
type VecBreakLimitReward = NonNullable<VecBreakStageReward["limitReward"]>;

/** 官方未建模 JSON 里的赛季字段（服务端消费面） */
type JsonDict = { [key: string]: JsonValue };

/**
 * 取非负有限数值（缺失/非数值/被转换管线误写成枚举名的字符串一律按 0）
 *
 * 官方数据实锤：`stageRewardDict.*.completeRewardCnt` 的少量行是枚举名
 * （`"MATERIAL_ISSUE_VOUCHER"` / `"PLOT_ITEM"`），而 CS 签名为 `System.Int32`
 * ——转换器把数值 0/1 按全局枚举名表转成了字符串。消费侧若直接 `Number()` 会得到
 * NaN 并写进存档，故此处保守按 0 计。
 * @param raw - 原始 JSON 值
 * @returns 数值（无法解析为有限数时 0）
 */
function toCount(raw: JsonValue | undefined): number {
  if (typeof raw === "number") return Number.isFinite(raw) ? raw : 0;
  if (typeof raw === "string") {
    const n = Number(raw);
    return Number.isFinite(n) ? n : 0;
  }
  return 0;
}

/** JsonValue → 字符串键字典（非对象按空表处理） */
function asDict(value: JsonValue | undefined): JsonDict {
  return isJsonObjectValue(value) ? value : {};
}

/**
 * `JsonValue | undefined` → JSON 对象收窄
 *
 * `json-value.ts` 的 {@link isJsonObject} 只接受 `JsonValue`（undefined 不在 JSON 域内），
 * 而本模块的取值链（可选表 → 可选字典项）天然产生 `JsonValue | undefined`，
 * 故在此收口：undefined 视为非对象。
 * @param value - 待判定值
 * @returns 是否为 JSON 对象
 */
function isJsonObjectValue(value: JsonValue | undefined): value is JsonObject {
  return value !== undefined && isJsonObject(value);
}

/**
 * 赛季字典（官方 `activity.typeActVecBreakV2Data`，键 = 赛季 id）
 * @returns 赛季 id → 赛季配置（未建模 JSON）
 */
function vecBreakDict(): JsonDict {
  return asDict(excel.ActivityTable?.activity?.typeActVecBreakV2Data);
}

/**
 * 活动字典中全部矢量突破赛季 id（按 basicInfo.startTime **降序**，最新一期在前）
 * @returns 赛季 id 列表
 */
export function vecBreakActivityIds(): string[] {
  const basic = excel.ActivityTable?.basicInfo ?? {};
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
 * @returns 赛季 id 与配置对象（未建模 JSON）；未命中返回 undefined
 */
export function vecBreakDetail(
  activityId?: string,
): { activityId: string; detail: JsonDict } | undefined {
  const dict = vecBreakDict();
  const id = activityId && isJsonObject(dict[activityId]) ? activityId : currentVecBreakActivityId();
  const detail = dict[id];
  return isJsonObject(detail) ? { activityId: id, detail } : undefined;
}

/**
 * 取关卡里程碑点数配置
 * @param activityId - 赛季 id
 * @param stageId - 关卡 id
 * @returns 奖励配置（数值已归一）；未命中返回 undefined
 */
export function vecBreakStageReward(
  activityId: string | undefined,
  stageId: string,
): VecBreakStageReward | undefined {
  const rows = vecBreakDetail(activityId)?.detail.stageRewardDict;
  if (!isJsonObjectValue(rows)) return undefined;
  const row = rows[stageId];
  if (!isJsonObjectValue(row)) return undefined;
  return {
    stageId: typeof row.stageId === "string" ? row.stageId : stageId,
    completeRewardCnt: toCount(row.completeRewardCnt),
    normalRewardCnt: toCount(row.normalRewardCnt),
    limitReward: toLimitReward(row.limitReward),
  };
}

/**
 * 限时奖励窗口（缺失/非法 → null = 无窗口）
 * @param raw - stageRewardDict[*].limitReward 原始值
 * @returns 窗口起止与点数
 */
function toLimitReward(raw: JsonValue | undefined): VecBreakLimitReward | null {
  if (!isJsonObjectValue(raw)) return null;
  return {
    startTs: toCount(raw.startTs),
    endTs: toCount(raw.endTs),
    rewardCnt: toCount(raw.rewardCnt),
  };
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
  let point = firstClear ? row.completeRewardCnt : row.normalRewardCnt;
  let timeLimited = false;
  const limit = row.limitReward;
  if (firstClear && !timeLimitedClaimed && limit && nowTs >= limit.startTs && nowTs <= limit.endTs) {
    point += limit.rewardCnt;
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
    ...Object.keys(asDict(detail.offenseStageDict)),
    ...Object.keys(asDict(detail.hardStageDict)),
    ...Object.keys(asDict(detail.defenseBasicDict)),
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
  const dict = asDict(vecBreakDetail(activityId)?.detail.offenseStageDict);
  return Object.values(dict)
    .map((stage) =>
      isJsonObject(stage)
        ? { stageId: String(stage.stageId ?? ""), level: toCount(stage.level) }
        : { stageId: "", level: 0 },
    )
    .sort((a, b) => a.level - b.level);
}
