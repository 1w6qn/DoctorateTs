/**
 * 保全派驻（爬塔）奖励与赛季进度引擎（纯函数 + 状态兜底，无 IO）
 *
 * 数据源：excel `climb_tower_table`
 * - `rewardInfoList` / `rewardInfoListHardMode`：每层首通奖励档（`stageSort` 1..6）
 * - `detailConst`：产出物品与账号持有上限（`lowerItemId`=mod_update_token_1 / `lowerItemLimit`=60、
 *   `higherItemId`=mod_update_token_2 / `higherItemLimit`=24）、`sweepCostCount`
 * - `levels[levelId].layerNum`：关卡 → 层号；`towers[towerId].levels`：层序
 * - `missionData` / `missionGroup`：赛季任务目标与奖励
 * - `seasonInfos`：赛季 → 当期塔（`canSweep` 判定用）
 *
 * 官服存档实证（`data/user/databases/1.json` → `tower.outer.towers[towerId]`）：
 * `{ best, reward: number[], unlockHard, hardBest, canSweep?, canSweepHard? }`，其中 `reward` 是
 * **已领取首通奖励的层号数组**（tower_n_01 best=8 reward=[1..8]；tower_n_07 best=4 reward=[1]
 * —— 通关 4 层但只领过第 1 层）。
 */
import excel, { ItemBundle } from "@excel/excel";

/** 每层首通奖励档 */
export interface TowerRewardRow {
  stageSort: number;
  lowerItemCount: number;
  higherItemCount: number;
}

/** 赛季任务推进上下文（settleGame / recruit 处提供） */
export interface TowerMissionCtx {
  godCardId?: string;
  towerId?: string;
  /** 本次通关层数 */
  clearedLayers?: number;
  /** 该塔总层数（普通模式） */
  totalLayers?: number;
  isHard?: boolean;
  /** 本次招募的干员职业（TowerRecruit 模板用） */
  recruitProfession?: string;
}

/**
 * 读 `climb_tower_table.detailConst`（缺表返回空对象）
 * @returns detailConst 原始对象
 */
export function towerDetailConst(): Record<string, any> {
  return ((excel.ClimbTowerTable as any)?.detailConst ?? {}) as Record<string, any>;
}

/**
 * 首通奖励档表（普通 / 困难）
 * @param isHard - 是否困难模式
 * @returns 奖励档数组
 */
export function towerLayerRows(isHard: boolean): TowerRewardRow[] {
  const table = excel.ClimbTowerTable as any;
  const rows = (isHard ? table?.rewardInfoListHardMode : table?.rewardInfoList) ?? [];
  return Array.isArray(rows) ? (rows as TowerRewardRow[]) : [];
}

/**
 * 取某层的首通奖励档
 * @param stageSort - 层号（1-based）
 * @param isHard - 是否困难模式
 * @returns 奖励档；越界返回 null
 */
export function towerLayerRewardRow(stageSort: number, isHard: boolean): TowerRewardRow | null {
  return towerLayerRows(isHard).find((r) => Number(r.stageSort) === stageSort) ?? null;
}

/**
 * 关卡 id → 层号（`levels[levelId].layerNum`）
 * @param levelId - 关卡 id（如 lt_17_03）
 * @returns 层号；未知返回 0
 */
export function towerLayerSort(levelId: string): number {
  const level = (excel.ClimbTowerTable as any)?.levels?.[levelId];
  return Number(level?.layerNum ?? 0) || 0;
}

/**
 * 归一化请求里的 layers 字段（层号数字或关卡 id 混用）
 * @param layers - 客户端传入的 layers
 * @returns 去重排序后的层号数组（过滤器剔除无法识别的项）
 */
export function normalizeTowerLayers(layers: unknown): number[] {
  if (!Array.isArray(layers)) return [];
  const out: number[] = [];
  for (const raw of layers) {
    let sort = 0;
    if (typeof raw === "number") sort = raw;
    else if (typeof raw === "string") {
      sort = towerLayerSort(raw) || Number(raw) || 0;
    }
    if (sort >= 1 && !out.includes(sort)) out.push(sort);
  }
  return out.sort((a, b) => a - b);
}

/**
 * 当期（now 所在时段）赛季信息
 * @param nowTs - 当前时间（秒）
 * @returns `seasonInfos` 中命中的赛季；无命中返回 undefined
 */
export function currentTowerSeason(nowTs: number): Record<string, any> | undefined {
  const infos = (excel.ClimbTowerTable as any)?.seasonInfos ?? {};
  for (const info of Object.values(infos) as any[]) {
    if (!info) continue;
    if (nowTs >= Number(info.startTs ?? 0) && nowTs <= Number(info.endTs ?? 0)) {
      return info;
    }
  }
  return undefined;
}

/**
 * 玩家 tower 状态兜底（`outer` / `season` 缺失字段按官服形状补齐）
 *
 * 私服初始存档可能完全没有 tower.outer/season（原实现从不写这两块），
 * 直接下标会 500。
 * @param draft - 玩家数据草稿
 * @returns `draft.tower`
 */
export function ensureTowerState(draft: any): any {
  if (!draft.tower) draft.tower = {};
  const tower = draft.tower;
  if (!tower.current) tower.current = {};
  if (!tower.outer) tower.outer = {};
  const outer = tower.outer;
  if (!outer.training) outer.training = {};
  if (!outer.towers) outer.towers = {};
  if (outer.hasTowerPass == null) outer.hasTowerPass = 0;
  if (!outer.pickedCardMap) outer.pickedCardMap = {};
  if (!outer.pickedGodCard) outer.pickedGodCard = {};
  if (!outer.tactical) outer.tactical = emptyTowerTactical();
  if (!outer.strategy) outer.strategy = "NONE";
  if (!Array.isArray(outer.squad)) outer.squad = [];
  if (!tower.season) tower.season = {};
  const season = tower.season;
  if (season.id == null) season.id = "";
  if (season.finishTs == null) season.finishTs = 0;
  if (!season.missions) season.missions = {};
  if (!season.passWithGodCard) season.passWithGodCard = {};
  if (!season.towerSlotsMap) season.towerSlotsMap = {};
  if (!season.slots) season.slots = {};
  if (!season.period) {
    season.period = { termTs: 0, items: {}, periodCurr: 0, periodCount: 0, cur: 0, len: 0 };
  }
  return tower;
}

/** 空战术配置（TowerTactical 八职业） */
function emptyTowerTactical(): Record<string, string> {
  return {
    PIONEER: "", WARRIOR: "", TANK: "", SNIPER: "",
    CASTER: "", SUPPORT: "", MEDIC: "", SPECIAL: "",
  };
}

/**
 * 取（必要时创建）`outer.towers[towerId]`
 * @param draft - 玩家数据草稿
 * @param towerId - 塔 id
 * @returns 该塔的进度记录（best/reward/unlockHard/hardBest）
 */
export function ensureTowerOuterTower(draft: any, towerId: string): any {
  ensureTowerState(draft);
  const towers = draft.tower.outer.towers;
  if (!towers[towerId]) {
    towers[towerId] = { best: 0, reward: [], unlockHard: false, hardBest: 0 };
  }
  const rec = towers[towerId];
  if (rec.best == null) rec.best = 0;
  if (!Array.isArray(rec.reward)) rec.reward = [];
  if (rec.unlockHard == null) rec.unlockHard = false;
  if (rec.hardBest == null) rec.hardBest = 0;
  return rec;
}

/**
 * 按 `missionData[].template` 推导赛季任务目标值
 *
 * 实证：TowerRecruit 取 `param[1]`（"在临时增调中累计招募15次术师干员" → 15）、
 * TowerSettleLayer 取 `param[3]`（"清理进度达到1层或以上2次" → 2），其余模板为 0/1 达成型。
 * @param mission - missionData 条目
 * @returns 目标值
 */
export function towerMissionTarget(mission: any): number {
  const param: any[] = Array.isArray(mission?.param) ? mission.param : [];
  switch (String(mission?.template ?? "")) {
    case "TowerRecruit":
      return Math.max(1, Number(param[1] ?? 1) || 1);
    case "TowerSettleLayer":
      return Math.max(1, Number(param[3] ?? 1) || 1);
    default:
      return 1;
  }
}

/**
 * 补齐当期赛季任务表（`season.missions`）
 *
 * 官服形状：`{ [missionId]: { value, target, hasRecv } }`，赛季 id 与
 * `missionGroup[seasonId].missionIds` 同源（如 tower_season_7 → tower_season7_1..8）。
 * @param draft - 玩家数据草稿
 * @param nowTs - 当前时间（秒）
 */
export function ensureTowerSeasonMissions(draft: any, nowTs: number): void {
  const tower = ensureTowerState(draft);
  const season = tower.season;
  if (!season.id) {
    const cur = currentTowerSeason(nowTs);
    if (cur) {
      season.id = String(cur.id);
      season.finishTs = Number(cur.endTs ?? 0);
    }
  }
  const groups = (excel.ClimbTowerTable as any)?.missionGroup ?? {};
  const group = groups[season.id];
  const ids: string[] = Array.isArray(group?.missionIds) ? group.missionIds : [];
  const missions = (excel.ClimbTowerTable as any)?.missionData ?? {};
  for (const id of ids) {
    if (season.missions[id]) continue;
    season.missions[id] = {
      value: 0,
      target: towerMissionTarget(missions[id]),
      hasRecv: false,
    };
  }
}

/**
 * 按 `detailConst` 的物品与上限给首通奖励封顶并计入库存
 * @param draft - 玩家数据草稿
 * @param towerId - 塔 id
 * @param sorts - 要领取的层号
 * @param isHard - 是否困难模式
 * @returns 实际发放的物品、新领取的层号与数量
 */
export function claimTowerLayerRewards(
  draft: any,
  towerId: string,
  sorts: number[],
  isHard: boolean,
): { granted: ItemBundle[]; newly: number[]; low: number; high: number } {
  const detail = towerDetailConst();
  const lowId = String(detail.lowerItemId ?? "mod_update_token_1");
  const highId = String(detail.higherItemId ?? "mod_update_token_2");
  const lowLimit = Number(detail.lowerItemLimit ?? 60);
  const highLimit = Number(detail.higherItemLimit ?? 24);
  const rec = ensureTowerOuterTower(draft, towerId);
  if (!draft.inventory) draft.inventory = {};
  let lowCap = Math.max(0, lowLimit - Number(draft.inventory[lowId] ?? 0));
  let highCap = Math.max(0, highLimit - Number(draft.inventory[highId] ?? 0));
  let low = 0;
  let high = 0;
  const newly: number[] = [];
  for (const sort of [...new Set(sorts)].sort((a, b) => a - b)) {
    if (sort <= 0 || rec.reward.includes(sort)) continue;
    const row = towerLayerRewardRow(sort, isHard);
    if (!row) continue;
    rec.reward.push(sort);
    newly.push(sort);
    const l = Math.min(Number(row.lowerItemCount ?? 0), lowCap);
    const h = Math.min(Number(row.higherItemCount ?? 0), highCap);
    lowCap -= l;
    highCap -= h;
    low += l;
    high += h;
  }
  if (low > 0) draft.inventory[lowId] = Number(draft.inventory[lowId] ?? 0) + low;
  if (high > 0) draft.inventory[highId] = Number(draft.inventory[highId] ?? 0) + high;
  const granted: ItemBundle[] = [];
  if (low > 0) granted.push({ id: lowId, count: low, type: "MATERIAL" as ItemBundle["type"] });
  if (high > 0) granted.push({ id: highId, count: high, type: "MATERIAL" as ItemBundle["type"] });
  return { granted, newly, low, high };
}

/**
 * 推进当期赛季任务进度（仅覆盖可由服务端结算数据判定的模板）
 *
 * 已覆盖：TowerCardPassLayer（神卡+层数）、TowerCardChallenge（神卡+指定塔通关）、
 * TowerSettlePass（指定塔通关）、TowerSettleLayer（累计层数次数）、TowerRecruit（累计招募职业次数）。
 * 未覆盖：TowerCardSquad / TowerCardSquadWithProfession（需编队职业/阵营统计）。
 * @param draft - 玩家数据草稿
 * @param ctx - 本次结算上下文
 * @returns 本次被推进的任务 id 列表
 */
export function advanceTowerSeasonMissions(draft: any, ctx: TowerMissionCtx): string[] {
  const tower = ensureTowerState(draft);
  const season = tower.season;
  const missions = (excel.ClimbTowerTable as any)?.missionData ?? {};
  const touched: string[] = [];
  const cleared = Number(ctx.clearedLayers ?? 0);
  const total = Number(ctx.totalLayers ?? 0);
  const fullClear = total > 0 && cleared >= total;
  for (const [id, state] of Object.entries(season.missions ?? {}) as [string, any][]) {
    const mission = missions[id];
    if (!mission || state.hasRecv) continue;
    const param: any[] = Array.isArray(mission.param) ? mission.param : [];
    const target = Math.max(1, Number(state.target ?? 1) || 1);
    let value = Number(state.value ?? 0);
    switch (String(mission.template ?? "")) {
      case "TowerCardPassLayer":
        if (ctx.godCardId && String(param[1]) === ctx.godCardId) {
          value = Math.max(value, cleared >= Number(param[2] ?? 0) ? 1 : 0);
        }
        break;
      case "TowerCardChallenge":
        if (
          ctx.godCardId && String(param[1]) === ctx.godCardId &&
          ctx.towerId && String(param[2]) === ctx.towerId && fullClear
        ) {
          value = 1;
        }
        break;
      case "TowerSettlePass":
        if (ctx.towerId && String(param[1]) === ctx.towerId && fullClear) value = 1;
        break;
      case "TowerSettleLayer":
        if (cleared >= Number(param[2] ?? 0)) value = Math.min(target, value + 1);
        break;
      case "TowerRecruit":
        if (ctx.recruitProfession && String(param[2]) === ctx.recruitProfession) {
          value = Math.min(target, value + 1);
        }
        break;
      default:
        break;
    }
    if (value !== Number(state.value ?? 0)) {
      state.value = value;
      touched.push(id);
    }
  }
  return touched;
}
