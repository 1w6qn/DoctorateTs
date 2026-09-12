/**
 * 基建服务端扩展字段形状（生成模型缺口的本地补丁）
 *
 * `app/game/excel/types-playerdata.ts` 由「客户端闭包 + 服务端协议适配」生成，只覆盖
 * 线格式已声明的字段。基建 logic 子树另有一批**服务端自建**的存档扩展字段（旧存档惰性
 * 初始化、客户端忽略）以及两处**生成模型形状偏差**（见下）。本次收敛类型债不动生成器
 * 输入表（`scripts/playerdata-server-adapt.ts`），缺口统一在本文件就地声明，待主线把这些
 * 字段登记进 `SERVER_ADD_FIELDS` / `SERVER_OVERRIDE_FIELDS` 并重生成后即可删除本文件。
 *
 * 声明约定：
 * - **新增字段**用交叉类型（`A & {...}`），全部可选；
 * - **修改既有字段类型**（如 `dailyReward` 允许 `null`、`trading.stock` 元素带 `special`）
 *   必须先 `Omit` 再交叉——直接交叉会把 `A` 与 `A | null` 求交回 `A`，nullable 静默失效。
 *
 * 偏差清单（这些字段应由生成器登记，本文件只是过渡）：
 * 1. `PlayerBuildingMeeting.dailyReward`：生成模型为必填线索对象，服务端以 `null` 表示
 *    「今日未领」（见 accrue.ts#dailyRefresh）；
 * 2. `PlayerBuilding.diyPresetSolutions`：生成模型声明为 `PlayerBuildingDIYPreset`，但
 *    服务端按 CS `BuildingDIYSavePresetSolutionRequest.solution`（`PlayerBuildingDIYSolution`）
 *    原样写入（见 misc.ts#saveDiyPresetSolution）。
 * 其余类型仅补「服务端自建扩展字段」，与生成模型不冲突。
 */
import type {
  PlayerBuilding,
  PlayerBuildingChar,
  PlayerBuildingHire,
  PlayerBuildingMeeting,
  PlayerBuildingMeetingClue,
  PlayerBuildingTrainee,
  PlayerBuildingTrading,
  PlayerBuildingTradingOrder,
  PlayerBuildingTraining,
} from "../../../kernel/playerdata";

/** 干员暖机扩展字段（在岗累积秒 / 上次推进秒 / 累积中的房间槽位；见 accrue.ts#_accrueWarmup） */
export type CharWithWarmup = PlayerBuildingChar & {
  warmupSec?: number;
  warmupTs?: number;
  warmupSlot?: string;
};

/** 干员信赖结算基准（浮点秒；见 accrue.ts#_accrueFavor） */
export type CharWithFavor = PlayerBuildingChar & { lastFavorAddTime?: number };

/**
 * 会客室房间（服务端扩展）
 * - `dailyReward = null` 表示「今日免费线索未领」（生成模型为必填线索对象）
 * - `clueReceiveCount` 为接收好友线索的信用计次（每日刷新归零）
 */
export type MeetingRoom = Omit<PlayerBuildingMeeting, "dailyReward"> & {
  dailyReward?: PlayerBuildingMeetingClue | null;
  clueReceiveCount?: number;
};

/** 贸易订单（服务端扩展 `special`：独占/违约订单来源标记，见 trading.ts#_genTradingOrder） */
export type TradingOrder = PlayerBuildingTradingOrder & { special?: string };

/**
 * 贸易站房间（服务端扩展）
 * - `_lastOrderFillTs` 补单守卫时刻（防交付后 sync 立即回满订单）
 * - `_lastOrderSpanSec` 上一笔订单的整周期秒数（补单节流按官方节奏）
 */
export type TradingRoom = Omit<PlayerBuildingTrading, "stock"> & {
  stock: TradingOrder[];
  _lastOrderFillTs?: number;
  _lastOrderSpanSec?: number;
};

/** 人力办公室房间（服务端扩展：`contactSec` 人脉进度；`refreshStock` 旧存档回退字段，官方字段为 `refreshCount`） */
export type HireRoom = PlayerBuildingHire & {
  contactSec?: number;
  refreshStock?: number;
};

/** 受训干员（服务端扩展 `maxPoint` = 训练时长阈值 lvlUpTime） */
export type TraineeWithMaxPoint = PlayerBuildingTrainee & { maxPoint?: number };

/** 训练室房间（trainee 带 `maxPoint` 扩展） */
export type TrainingRoom = Omit<PlayerBuildingTraining, "trainee"> & {
  trainee: TraineeWithMaxPoint;
};

/** 预设队列元数据（名称/锁定；服务端自建，官方线格式 room.presetQueue 无名称） */
export interface PresetQueueMeta {
  name?: string;
  locked?: boolean;
}

/** 预设队列元数据字典（`building.presetQueues`） */
export type PresetQueueMetaDict = Record<string, PresetQueueMeta>;

/** 基建顶层扩展字段（`maxLevelReached` 曾达等级；`presetQueues` 预设队列元数据） */
export type BuildingWithExt = PlayerBuilding & {
  maxLevelReached?: Record<string, number>;
  presetQueues?: PresetQueueMetaDict;
};

/** 玩家状态扩展字段（访问好友基建的信用每日计次，见 misc.ts#visitBuilding） */
export interface StatusExt {
  visitCreditDay?: number;
  visitCreditCount?: number;
  visitCreditIds?: string[];
}

/**
 * 房间时间戳最小形状
 * 跨房间类型遍历时使用（PRIVATE 等房间类型没有 `state`/`lastUpdateTime`/`completeWorkTime`，
 * 直接取并集成员会报「属性不存在」，故收敛为可选字段结构）。
 */
export interface RoomTimestamp {
  state?: number;
  lastUpdateTime?: number;
  completeWorkTime?: number;
}
