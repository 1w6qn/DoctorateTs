/**
 * 关卡默认状态与解锁链扫描（battle / activity 共享实现）
 *
 * 收敛三处历史等价实现的单一事实来源：
 * - `battle.start` 新关卡创建字面量（guide 关卡 noCostCnt 特例）
 * - `battle.finishStoryStage` / `battle.finish` 胜利路径的 unlockCondition 链扫描
 * - `unlockActivity.unlockStages` 活动播种的全表可达性扫描
 *
 * 行为零变化契约：三种调用点的分支语义差异（锚点判定项、条件谓词、null 伪键处理、
 * noCostCnt 规则、mainStageProgress 推进）通过参数显式保留，见各参数说明。
 *
 * 本文件属 util 层：只允许依赖 excel 数据模块，禁止 import player/*——
 * unlockActivity 与 battle 各自引用本文件即可，不引入 manager 间循环依赖。
 */
import excel from "@excel/excel";

/** 解锁条件完成度（PlayerBattleRank 字符串）→ 关卡 state 数值档位（FAIL/PASS/COMPLETE → 1/2/3） */
export const completeStateRank: Record<string, number> = {
  FAIL: 1,
  PASS: 2,
  COMPLETE: 3,
};

/** 无体力/练习关标记：关卡 id 含其一即视为无体力/练习关（noCostCnt 置 0） */
const NO_COST_MARKERS = ["#f#", "hard_", "tr_"] as const;

/**
 * 解锁条件条目（StageTable.stages[*].unlockCondition 的值）。
 * 运行时 completeState 为字符串枚举（"FAIL"/"PASS"/"COMPLETE"），经 completeStateRank 映射。
 */
export interface StageUnlockCondition {
  stageId: string;
  completeState: string;
}

/** 玩家存档单关卡状态（playerdata.dungeon.stages 值形状） */
export interface PlayerStageState {
  stageId: string;
  practiceTimes: number;
  completeTimes: number;
  startTimes: number;
  state: number;
  hasBattleReplay: number;
  noCostCnt: number;
}

/** defaultStageState 的 noCostCnt 规则选项（缺省恒 1） */
export interface DefaultStageStateOptions {
  /**
   * 无体力/练习关标记规则：stageId 含 #f#/hard_/tr_ → noCostCnt 0，否则 1。
   * 对应 battle.finish 条件解锁分支与活动播种（原 unlockActivity.defaultStageState 规则）。
   */
  noCostByMarker?: boolean;
  /**
   * guide 关卡特例规则：stageId 含 "guide" → noCostCnt 1，否则 0。
   * 对应 battle.start 新关卡创建规则；与 noCostByMarker 同时传入时优先本项。
   */
  guideNoCost?: boolean;
}

/**
 * 构造关卡默认状态（统一三处历史内联字面量）
 *
 * @param stageId - 关卡 id
 * @param opts    - noCostCnt 规则；缺省恒 1（battle.finishStoryStage 两分支与
 *                  battle.finish 无前置条件分支的原始行为）
 * @returns 默认关卡状态对象（state/practiceTimes/completeTimes/startTimes 全 0，
 *          hasBattleReplay 0，noCostCnt 按 opts 规则）
 */
export function defaultStageState(
  stageId: string,
  opts?: DefaultStageStateOptions,
): PlayerStageState {
  let noCostCnt = 1;
  if (opts?.guideNoCost) {
    // battle.start 规则：guide 关卡保留一次免体力次数
    noCostCnt = stageId.includes("guide") ? 1 : 0;
  } else if (opts?.noCostByMarker) {
    // 活动/条件解锁规则：无体力/练习关不给免体力次数
    noCostCnt = NO_COST_MARKERS.some((marker) => stageId.includes(marker)) ? 0 : 1;
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

/** 解锁链扫描锚点：刚结算的关卡及其判定档位 */
export interface UnlockChainAnchor {
  /** 刚结算的关卡 id（unlockCondition 引用该 id 时启用锚点判定项） */
  stageId: string;
  /**
   * 该关卡本次达成的完成度档位（与存档 state 同尺度比较）。
   * finishStoryStage 恒传 3（剧情结算即 COMPLETE）；finish 传 battleData.completeState。
   */
  state: number;
}

/** 扫描判定语义 */
export type UnlockChainMode =
  /** battle.finishStoryStage / battle.finish 胜利路径语义（默认） */
  | "battle"
  /** unlockActivity 播种的全表可达性扫描语义 */
  | "seed";

/** scanUnlockChain 选项 */
export interface ScanUnlockChainOptions {
  /** 判定语义（缺省 "battle"），两种模式的差异见 scanUnlockChain 说明 */
  mode?: UnlockChainMode;
  /**
   * 有前置条件的解锁分支新条目的 noCostCnt 规则（透传 defaultStageState）。
   * battle 模式的无前置条件分支恒用缺省规则（noCostCnt=1，原始行为如此）；
   * seed 模式两分支共用本规则。
   */
  noCost?: DefaultStageStateOptions;
  /**
   * MAIN/SUB 双向推进（仅 battle.finish 需要）：传入刚结算关卡的 stageType 启用——
   * 新解锁关卡同为 MAIN/SUB 时写 draft.status.mainStageProgress。省略则不推进。
   */
  clearedStageType?: string;
}

/** scanUnlockChain 结果（调用方按需取用） */
export interface ScanUnlockChainResult {
  /** 本次新写入存档的关卡 id（遍历序；battle.finishStoryStage/finish 的 unlockStages 数据源） */
  unlockedIds: string[];
  /** 新写入存档的完整状态对象（仅 battle 模式有前置条件分支收集；finish 的 unlockStagesObject 数据源） */
  unlockedStates: PlayerStageState[];
}

/**
 * 解锁链扫描：遍历 StageTable 全表，把「前置条件已满足且尚未入档」的关卡写入默认状态
 *
 * 两种模式逐分支对应历史实现：
 * - **battle**（finishStoryStage / finish）：数据表 null 伪键跳过；无前置条件分支缺失才补
 *   （noCostCnt 恒 1）；有前置条件分支按「存档命中 + 锚点命中」两个**独立累加项**计数，
 *   passCondition === 条件数才算通过（同条件双计致超长而失配属既有行为，保持不变）；
 *   存在性判定用 `in`。可选 MAIN/SUB 双向推进 mainStageProgress。
 * - **seed**（unlockActivity.unlockStages）：null/缺字段伪键视作无条件关卡直接播种；
 *   条件谓词为 need = rank ?? 0 的宽档位，「任一条件不满足即失败」短路，无锚点项；
 *   存在性判定用真值判断。draft.dungeon 缺失整体跳过（battle 调用点进入前已解引用，
 *   该守卫对它们不可达，不构成行为差异）。
 *
 * @param draft  - 玩家数据 draft（player.update 配方内）
 * @param anchor - 刚结算关卡锚点；seed 模式或纯全表扫描省略
 * @param opts   - 语义/noCostCnt/mainStageProgress 推进选项
 * @returns 新解锁关卡 id 列表与状态对象
 */
export function scanUnlockChain(
  draft: any,
  anchor?: UnlockChainAnchor,
  opts?: ScanUnlockChainOptions,
): ScanUnlockChainResult {
  const result: ScanUnlockChainResult = { unlockedIds: [], unlockedStates: [] };
  const mode = opts?.mode ?? "battle";
  if (!draft.dungeon) return result;
  const dungeonStages = (draft.dungeon.stages = draft.dungeon.stages || {});
  // MAIN/SUB 双向判定的左半边（右半边按新解锁关卡逐一判定）
  const advanceMainStage =
    opts?.clearedStageType !== undefined &&
    ["MAIN", "SUB"].includes(opts.clearedStageType);

  for (const [itemId, stageDef] of Object.entries(
    excel.StageTable.stages,
  ) as [string, any][]) {
    if (mode === "battle") {
      // 防御：数据表末尾字段名伪键（值 null）——读 stage.unlockCondition 会崩溃
      if (!stageDef || typeof stageDef !== "object") continue;
      const conditions = stageDef.unlockCondition as StageUnlockCondition[];
      if (conditions.length === 0) {
        // 无前置条件关卡：缺失才补默认状态（noCostCnt 恒 1，两处原始行为一致）
        if (!(itemId in dungeonStages)) {
          dungeonStages[itemId] = defaultStageState(itemId);
          result.unlockedIds.push(itemId);
        }
        continue;
      }
      let passCondition = 0;
      for (const condition of conditions) {
        // 存档命中项：前置关卡已入档且 state 达标
        if (condition.stageId in dungeonStages) {
          if (
            dungeonStages[condition.stageId].state >=
            completeStateRank[condition.completeState]
          ) {
            passCondition += 1;
          }
        }
        // 锚点命中项：条件直接引用刚结算关卡（与存档命中独立累加，可双计）
        if (anchor && anchor.stageId === condition.stageId) {
          if (anchor.state >= completeStateRank[condition.completeState]) {
            passCondition += 1;
          }
        }
      }
      if (passCondition === conditions.length && !(itemId in dungeonStages)) {
        const fresh = defaultStageState(itemId, opts?.noCost);
        if (
          advanceMainStage &&
          ["MAIN", "SUB"].includes(
            excel.StageTable.stages[itemId]?.stageType as string,
          )
        ) {
          draft.status.mainStageProgress = itemId;
        }
        dungeonStages[itemId] = fresh;
        result.unlockedIds.push(itemId);
        result.unlockedStates.push(fresh);
      }
    } else {
      // seed 模式：伪键/缺字段视作无条件关卡；rank ?? 0 宽档位 + 不满足即短路
      const conditions: StageUnlockCondition[] =
        stageDef?.unlockCondition ?? [];
      if (conditions.length === 0) {
        if (!dungeonStages[itemId]) {
          dungeonStages[itemId] = defaultStageState(itemId, opts?.noCost);
          result.unlockedIds.push(itemId);
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
      if (pass && !dungeonStages[itemId]) {
        dungeonStages[itemId] = defaultStageState(itemId, opts?.noCost);
        result.unlockedIds.push(itemId);
      }
    }
  }
  return result;
}
