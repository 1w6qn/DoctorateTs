/**
 * 关卡类任务模板（通关/击杀/演习/歼灭等）
 */
import type { MissionTemplateGroup } from "./types";
import excel from "@excel/excel";
import { BattleData, BattleStats } from "../../../kernel/battle-model";

/**
 * 战斗统计服务端视图
 *
 * 客户端模型 `BattleStats.packedRuneDataList` 声明为 `null`（服务端实为遗物/组件 id
 * 字符串列表），生成模型未覆盖该真值；此处就地收窄，不改动 kernel 公共模型。
 */
type BattleStatsView = Omit<BattleStats, "packedRuneDataList"> & {
  packedRuneDataList?: string[] | null;
};

/**
 * 判定值是否为字符串数组
 *
 * `stats.idList` 客户端模型声明为 `object[]`，服务端实为 charId 字符串列表；按运行期
 * 元素判定收窄（`object[]` 无法直接断言成 `string[]`）。
 * @param value - 待判定值
 * @returns 是否为字符串数组
 */
function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === "string");
}

export const stageTemplates: MissionTemplateGroup = {
  /**
   * 通关任意类型关卡累计次数
   *
   * 达成目标状态（param[2]，如 2=三星通关）即 +1，以累计通关场次为进度。
   * 典型用例：日常/周常「通关任意关卡 N 次」（如 daily_4801 param=[0,1,2]）。
   * @param param[0] 恒为 "0"（无实际作用，占位分支位）
   * @param param[1] 目标累计通关次数
   * @param param[2] 通关状态阈值（completeState >= 该值才计入）
   */
  CompleteStageAnyType: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        const { completeState } = args;
        if (completeState >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 指定关卡内击杀敌人（按分支细分击杀方式）
   *
   * param[0] 区分 6 种分支：
   *   0 / 3 —— 占位分支（同 param[0] 未启用），仅注册进度，update 为空
   *   1 —— 任意关卡三星通关后，按本场击杀数 killCnt 累计（日常/周常击杀任务）
   *   2 —— 指定敌人（param[2] 以 ^ 分隔 enemyId）击杀计数，标准 HP_ZERO 判定
   *   5 —— 指定关卡（param[1] ^ 分隔，可含 #f# 变体）三星后累计 killCnt
   *   6 —— 指定关卡（param[1]）内击杀达到 param[2] 即算完成 1 次
   * @param param[0] 分支标识
   * @param param[1] 目标值或关卡列表（依分支而定；目标场次/累计击杀用）
   * @param param[2] 敌人列表 / 关卡状态阈值 / 单场击杀下限（依分支而定）
   * @param param[3] 目标值或状态阈值（分支 6 用）
   */
  StageWithEnemyKill: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        const { completeState } = args;
        if (completeState >= 2) {
          mission.progress[0].value += args.killCnt;
        }
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        const enemies = mission.param[2].split("^");
        args.battleData.stats.enemyStats.forEach((stat) => {
          if (
            enemies.includes(stat.Key.enemyId) &&
            stat.Key.counterType == "HP_ZERO"
          ) {
            mission.progress[0].value += stat.Value;
          }
        });
      },
    },
    "3": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
    "5": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (stages.includes(args.stageId) && args.completeState >= 2) {
          mission.progress[0].value += args.killCnt;
        }
      },
    },
    "6": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState < parseInt(mission.param[3])) {
          return;
        }
        if (args.killCnt >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 任意关卡击杀敌人累计数
   *
   * 任意关卡通关状态达到 param[2] 后，累计本场击杀数 killCnt 为进度。
   * 典型用例：日常/周常「累计击杀敌人 N 个」（如 daily_4808 param=[0,100,2]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标累计击杀数
   * @param param[2] 通关状态阈值（completeState >= 该值才累计本场击杀）
   */
  EnemyKillInAnyStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        if (args.completeState < parseInt(mission.param[2])) {
          return;
        }
        mission.progress[0].value += args.killCnt;
      },
    },
  },

  /**
   * 携带助战干员通关
   *
   * 通关（completeState>=2）且本场使用助战（assistFriend 非空）即 +1，
   * 以累计携带助战通关场次为进度。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 无实际作用（如 daily_4813 param=[1,1]）
   * @param param[2] 目标场次（常为 1 或 5，如 weekly_713）
   */
  StageWithAssistChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args) => {
        if (args.completeState >= 2 && args.assistFriend) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  /**
   * 通关指定关卡（按分支细分通关类型）
   *
   * @param param[0] 分支标识：
   *   0 —— 指定关卡（param[1] 以 ^ 分隔 stageId）三星通关（completeState>=2）各计 1
   *   2 —— 任意关卡通关状态达到 param[2] 各计 1（文件主线外围任务）
   *   3 —— 演习（isPractice 非 0）三星通关各计 1
   *   4 —— 突袭关节（stageId 含 #f#）三星通关（completeState>=3）各计 1
   * @param param[1] 关卡列表（分支 0）或通关状态阈值（分支 2）或目标值（分支 3/4）
   * @param param[2] 目标通关次数（分支 0/2 用）
   */
  CompleteStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData) => {
        if (args.completeState >= parseInt(mission.param[1])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "3": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData & { isPractice: number }) => {
        if (!args.isPractice) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
    "4": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (!args.stageId.includes("#f#")) {
          return;
        }
        if (args.completeState >= 3) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 通关任一指定关卡
   *
   * 指定关卡列表（param[1] 以 ^ 分隔）中命中一关、且通关状态达 param[2] 各计 1。
   * 文件主线章节任务（如 main_83=[0,main_15-04^main_15-04#s,2]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 关卡列表（^ 分隔，可含 #s 变体）
   * @param param[2] 通关状态阈值
   */
  CompleteAnyStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 指定关卡内击杀敌人（单场阈值式）
   *
   * 指定关卡（param[1] ^ 分隔）单场击杀 killCnt 取较大值作为进度上限，达 param[2]
   * 完成。用于「在 XX 关卡单场击杀 N」（如 sub_69 param=[0,camp_01,350]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 关卡列表（^ 分隔）
   * @param param[2] 单场目标击杀数
   */
  BattleWithEnemyKill: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.killCnt >= mission.progress[0].value) {
          mission.progress[0].value = args.killCnt;
        }
      },
    },
  },

  /**
   * 通关时使用代理/再现（代理作战）
   *
   * 每次代理作战通关（isReplay 非空）+1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标代理作战次数
   */
  StageWithReplay: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { isReplay: number }) => {
        if (args.isReplay) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 接管/中断代理作战（手动接管）
   *
   * 战斗中产生自动代理取消（autoReplayCancelled）各计 1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标接管次数
   */
  TakeOverReplay: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        if (args.battleData.stats.autoReplayCancelled) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 通关剿灭作战
   *
   * 三星通关（completeState>=2）且关卡类型为 CAMPAIGN（剿灭）：各计 1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标剿灭通关次数
   */
  CompleteCampaign: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stageType = excel.StageTable.stages[args.stageId].stageType;
        if (args.completeState < 2) {
          return;
        }
        if (stageType == "CAMPAIGN") {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 通关指定主线关卡
   *
   * 指定主线关卡（param[1] stageId）三星通关（completeState>=2）各计 1，目标恒为 1。
   * 用于主线章节任务（如 main_28 param=[1,main_02-03,1]）。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 指定主线关卡 id
   */
  CompleteMainStage: {
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId != mission.param[1]) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 消耗理智
   *
   * 每次战斗消耗理智按 ap 累加，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标消耗理智值
   */
  CostAp: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      // 修复：原 update 为空操作（事件即使 emit 也不累计）→ 消耗理智类任务永不推进；
      // 改为按实际消耗 AP 累计（emit 参数 {ap}）
      update: (mission, args: { ap: number }) => {
        mission.progress[0].value += args.ap;
      },
    },
  },
  /**
   * 通关活动关卡累计（53sideActivity_37..39）
   *
   * param[1]=活动关卡列表（^ 分隔，含 #f# 突袭变体），param[2]=目标累计通关次数
   * （15/45/85）。事件 CompleteStageAct 由 battle 结算 emit，满足 completeState>=2
   * 且关卡命中列表时累计 +1。
   */
  CompleteStageAct: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) return;
        if (args.completeState < 2) return;
        mission.progress[0].value += 1;
      },
    },
    // 型1：通关指定单关 n 次（param[1]=关卡，param[2]=目标次数，param[3]=星级门槛）。
    // 大量别传 EX/普通关单关任务（917 个 missionData 用此型）；对齐 DoctoratePy
    // CompleteStageAct type1：命中 param[1] 且 completeState>=param[3] 每次 +1
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2] ?? "1"),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[1]) return;
        const gate = parseInt(mission.param[3] ?? "2");
        if (args.completeState < gate) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 指定关卡内累计杀敌 / 用技能 / 部署（StageWithCondition）
   * type0：param[1]=关卡列表(^)，param[2]=enemyId，param[3]=目标击杀数
   * type1：param[1]=关卡列表，param[2]=目标技能施放次数
   * type2：param[1]=关卡列表，param[2]=目标干员部署次数
   */
  StageWithCondition: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const stats = args.battleData?.stats;
        let sum = 0;
        for (const n of stats?.enemyStats ?? []) {
          if (n.Key.enemyId === mission.param[2] && n.Key.counterType === "HP_ZERO") {
            sum += n.Value;
          }
        }
        mission.progress[0].value += sum;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const stats = args.battleData?.stats;
        let sum = 0;
        for (const n of stats?.skillTrigStats ?? []) {
          sum += n.Value;
        }
        mission.progress[0].value += sum;
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const stats = args.battleData?.stats;
        let sum = 0;
        for (const n of stats?.charStats ?? []) {
          if (n.Key.counterType === "SPAWN") {
            sum += n.Value;
          }
        }
        mission.progress[0].value += sum;
      },
    },
    // 型3：关卡三星且 extraBattleInfo 同时命中 param[2]**param[3] 累计达 param[4]
    //（act50side 载具骑乘 trap_* , ride / enemy killed_no_eat）
    "3": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4] ?? "1"),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let cnt = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[2]) && k.includes(mission.param[3])) {
            cnt += v;
          }
        }
        mission.progress[0].value += cnt;
      },
    },
    // 型4：关卡三星且 extraBattleInfo 命中 param[2] 累计达 param[3]
    //（如 flashstun / criticaldamage）
    "4": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let cnt = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[2])) {
            cnt += v;
          }
        }
        mission.progress[0].value += cnt;
      },
    },
  },

  /**
   * 活动关卡累计击杀敌人（EnemyKill，type0）
   * param[1]=关卡列表(^)，param[2]=目标累计击杀数；命中关卡三星后按 killCnt 累加
   */
  EnemyKill: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        mission.progress[0].value += args.killCnt;
      },
    },
  },

  /**
   * 通关任意关卡（CompleteStageOrCampaign，type0）
   * param[1]=目标累计通关次数
   */
  CompleteStageOrCampaign: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (!args.stageId || args.completeState < 2) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 通关物资筹备关卡（CompleteDailyStage，type1）
   * param[1]=物资类型（如 MATERIAL），param[2]=目标累计通关次数；stageType==DAILY 才计入
   */
  CompleteDailyStage: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (!args.stageId || args.completeState < 2) return;
        const stageType = excel.StageTable.stages[args.stageId]?.stageType;
        if (stageType !== "DAILY") return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 通关多维合作（CompleteAnyMulStage，type0）
   * param[1]=关卡，param[2]=星级门槛（completeState）
   */
  CompleteAnyMulStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[1]) return;
        if (args.completeState < parseInt(mission.param[2])) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 自走车发射计数（CompleteStageSimpleAtLeastId，type0）
   * param[1]=星级门槛，param[2]=关卡，param[3]=enemyId，param[4]=counterType(born)，
   * param[5]=目标次数；extraBattleInfo 中 key 同时含 enemy+counterType 之和达标即 +1
   */
  CompleteStageSimpleAtLeastId: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && k.includes(mission.param[4])) {
            count += v;
          }
        }
        if (count >= parseInt(mission.param[5])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 阻止/避免指定事件（CompleteStageSimpleAtMostId，type0）
   * param[1]=星级门槛，param[2]=关卡，param[3]=enemyId，param[4]=counterType(take)，
   * param[5]=上限次数；extraBattleInfo 中命中项计数不超上限即通关计 1 次
   */
  CompleteStageSimpleAtMostId: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && k.includes(mission.param[4])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[5])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 通关且满足战斗统计条件（CompleteStageCondition）
   * 覆盖 DoctoratePy 最常用的细分型（读 battleData.stats 统计，不依赖 ownSlots）：
   *  type0：param[1]=星级门槛，param[2]=关卡，param[3]=技能 id 列表(^)，param[4]=目标施放次数
   *  type3：param[1]=门槛，param[2]=关卡，param[3]=装置 key，param[4]=上限——命中装置不超上限
   *  type4：param[1]=门槛，param[2]=关卡，param[3]=装置 key，param[4]=上限——累计不超上限
   *  type8：param[1]=门槛，param[2]=关卡，param[3]=enemyId，param[4]=counterType(killed)，param[5]=目标击杀
   *  type10：param[1]=门槛，param[2]=关卡，param[3]=teamKey，param[4]=目标计数
   *  type11：param[1]=门槛，param[2]=关卡，param[3]=key，param[4]=上限（潮汐撤退/击倒）
   *  type12：param[1]=门槛，param[2]=关卡，param[3]=干员列表(^)——指定干员无 DEAD 即 +1
   *  type15：param[1]=门槛，param[2]=关卡，param[3]=上限，param[4]=key（受影响干员数上限）
   */
  CompleteStageCondition: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const skills = mission.param[3].split("^");
        const stats = args.battleData?.stats;
        let count = 0;
        for (const n of stats?.skillTrigStats ?? []) {
          if (skills.includes(n.Key.skillId)) {
            count += n.Value;
          }
        }
        if (count >= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "3": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && v <= parseInt(mission.param[4])) {
            mission.progress[0].value += 1;
            return;
          }
        }
      },
    },
    "4": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "8": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && k.includes(mission.param[4]) && v >= parseInt(mission.param[5])) {
            mission.progress[0].value += 1;
            return;
          }
        }
      },
    },
    "10": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count >= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "11": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "12": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const chars = mission.param[3].split("^");
        const stats = args.battleData?.stats;
        for (const n of stats?.charStats ?? []) {
          if (n.Key.counterType === "DEAD" && chars.includes(n.Key.charId)) {
            return;
          }
        }
        mission.progress[0].value += 1;
      },
    },
    "15": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[4])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count >= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "9": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && k.includes(mission.param[4])) {
            count += v;
          }
        }
        if (count >= parseInt(mission.param[5])) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型13：N 星通关且部署非助战的指定干员（param[3]=charId，param[4]=推进数）。
    // 需 ownSlots（battleInfo），事件暂不带 → 占位防崩（对齐 DoctoratePy TODO）
    "13": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      // 近似实现：N 星通关该关且上场干员 charId==param[3] 且非助战（未在 stats.idList）即推进。
      // 较 DoctoratePy ownSlots 的「编入非助战」判定更宽松（按实际上场判定）
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const stats = args.battleData?.stats;
        const rawIdList = stats?.idList;
        const idList: string[] = isStringArray(rawIdList) ? rawIdList : [];
        for (const n of stats?.charStats ?? []) {
          if (
            n.Key.charId === mission.param[3] &&
            n.Key.counterType === "SPAWN" &&
            !idList.includes(n.Key.charId)
          ) {
            mission.progress[0].value += parseInt(mission.param[4] ?? "1");
            return;
          }
        }
      },
    },
    // 型14：N 星通关且额外进化 buff 达到 param[3]（param[4]=buff key；extraBattleInfo 命中 key 数）
    "14": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k] of info) {
          if (k.includes(mission.param[4])) {
            count += 1;
          }
        }
        if (count >= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型5：N 星通关且场上干员数不超过 param[3]（charList 规模判定）
    "5": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const cl = args.battleData?.stats?.charList ?? {};
        if (Object.keys(cl).length <= parseInt(mission.param[3] ?? "0")) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型6/7：N 星通关且 extraBattleInfo 命中 param[3] 累计不超 param[4]（如不使用的装置）
    "6": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "7": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型16：N 星通关且部署 param[3] 势力的干员累计 param[4]（charStats SPAWN + nationId）
    "16": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const stats = args.battleData?.stats;
        let count = 0;
        for (const n of stats?.charStats ?? []) {
          if (n.Key.counterType === "SPAWN") {
            const national = excel.charData(n.Key.charId)?.nationId;
            if (national === mission.param[3]) {
              count += n.Value;
            }
          }
        }
        if (count >= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型17：N 星通关且上场干员中至少 param[3] 位含 tag=param[4]（近似 ownSlots 编队 tag 判定）
    "17": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const stats = args.battleData?.stats;
        const seen = new Set<string>();
        let count = 0;
        for (const n of stats?.charStats ?? []) {
          if (seen.has(n.Key.charId)) continue;
          seen.add(n.Key.charId);
          const tags = excel.charData(n.Key.charId)?.tagList;
          const hit = Array.isArray(tags)
            ? (tags as string[]).some((t) => String(t).includes(mission.param[4]))
            : String(tags ?? "").includes(mission.param[4]);
          if (hit) {
            count += 1;
            if (count >= parseInt(mission.param[3] ?? "1")) break;
          }
        }
        if (count >= parseInt(mission.param[3] ?? "1")) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 携带遗物通关（CompleteStageWithRelic，type0）
   * param[1]=关卡列表(^)，param[2]=遗物 id，param[3]=目标部署次数；
   * packedRuneDataList 命中遗物且部署达标即 +1
   */
  CompleteStageWithRelic: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const stats: BattleStatsView | undefined = args.battleData?.stats;
        const runes: string[] = stats?.packedRuneDataList ?? [];
        if (!runes.some((r: string) => String(r).includes(mission.param[2]))) return;
        let deploy = 0;
        for (const n of stats?.charStats ?? []) {
          if (n.Key.counterType === "SPAWN") {
            deploy += n.Value;
          }
        }
        if (deploy >= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 携带小帮手组件通关（CompleteStageWithTechTree，type0）
   * param[1]=星级门槛，param[2]=关卡，param[3]=组件 id 列表(^)，param[4]=携带上限；
   * packedRuneDataList 中命中组件数不超上限即 +1
   */
  CompleteStageWithTechTree: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const techs = mission.param[3].split(";");
        const stats: BattleStatsView | undefined = args.battleData?.stats;
        const runes: string[] = stats?.packedRuneDataList ?? [];
        let count = 0;
        for (const r of runes) {
          if (techs.includes(String(r))) {
            count += 1;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 驻守关卡通关（CompleteInterlockStage，type0，参照 DoctoratePy 占位实现）
   * 锁活动（act1lock）专属；当前不推进进度（完整判定需链路关卡状态）
   */
  CompleteInterlockStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: () => {},
    },
  },

  /**
   * 携带标志物通关（CompleteStageWithCharm，type0，参照 DoctoratePy 占位）
   * act12side 专属（玄铁/旗舰标志物判定）；完整判定需玩法状态，暂不推进防崩
   */
  CompleteStageWithCharm: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: () => {},
    },
  },
};
