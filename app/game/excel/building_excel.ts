/**
 * 基建 Excel 查询工具
 *
 * 从 excel.BuildingData 查表（制造/加工配方、房间相位、汇率、常量），
 * 供 BuildingManager 复用——替代硬编码区间/常量。
 *
 * 返回类型一律取自官方表类型的索引访问（`BuildingData["manufactFormulas"][string]` 等），
 * 表结构随 `types_excel_gen` 重生成自动跟随，不再需要 any 或调用侧补类型。
 */
import excel, { type ClueData } from "./excel";
import type { BuildingData } from "./types_excel_gen";

/** 制造配方（building_data.manufactFormulas[...]） */
type ManufactFormula = BuildingData["manufactFormulas"][string];
/** 加工配方（building_data.workshopFormulas[...]） */
type WorkshopFormula = BuildingData["workshopFormulas"][string];
/** 房间相位（building_data.rooms[roomId].phases[...]） */
type RoomPhase = BuildingData["rooms"][string]["phases"][number];
/** 制造站相位（building_data.manufactData.phases[...]） */
type ManufactPhase = BuildingData["manufactData"]["phases"][number];
/** 宿舍相位（building_data.dormData.phases[...]） */
type DormPhase = BuildingData["dormData"]["phases"][number];
/** 会客室相位（building_data.meetingData.phases[...]） */
type MeetingPhase = BuildingData["meetingData"]["phases"][number];
/** 人力办公室相位（building_data.hireData.phases[...]） */
type HirePhase = BuildingData["hireData"]["phases"][number];
/** 家具（building_data.customData.furnitures[...]） */
type FurnitureInfo = BuildingData["customData"]["furnitures"][string];

/** 制造配方（formulaId 字符串/数字兼容；未知返回 undefined） */
export function getManufactFormula(
  formulaId: string | number | undefined | null,
): ManufactFormula | undefined {
  if (formulaId == null) return undefined;
  return excel.BuildingData?.manufactFormulas?.[String(formulaId)];
}

/** 加工配方（未知返回 undefined） */
export function getWorkshopFormula(
  formulaId: string | number | undefined | null,
): WorkshopFormula | undefined {
  if (formulaId == null) return undefined;
  return excel.BuildingData?.workshopFormulas?.[String(formulaId)];
}

/** 房间相位（level 从 1 起；越界返回 undefined） */
export function getRoomPhase(
  roomId: string,
  level: number,
): RoomPhase | undefined {
  return excel.BuildingData?.rooms?.[roomId]?.phases?.[level - 1];
}

/** 贸易凭证汇率（goldItems 3003 → 金币；缺省 500） */
export function getGoldRate(): number {
  return excel.BuildingData?.goldItems?.["3003"] ?? 500;
}

/** 制造站相位（level 从 1 起；outputCapacity = 基础容量） */
export function getManufactPhase(
  level: number,
): ManufactPhase | undefined {
  return excel.BuildingData?.manufactData?.phases?.[level - 1];
}

/** 宿舍相位（level 从 1 起；manpowerRecover 为心情恢复数值——注意个别相位是占位字符串） */
export function getDormPhase(
  level: number,
): DormPhase | undefined {
  return excel.BuildingData?.dormData?.phases?.[level - 1];
}

/** 读取 BuildingData 顶层常量（laborRecoverTime/basicFavorPerDay/apToLaborRatio 等） */
export function getBuildingConstant<K extends keyof BuildingData>(
  key: K,
): BuildingData[K] | undefined {
  return excel.BuildingData?.[key];
}

/**
 * 家具信息（BuildingData.customData.furnitures[家具id]——舒适度/主题/分解产物等）
 * 未知家具返回 undefined（数据版本错位时容错跳过）
 */
export function getFurnitureInfo(
  furnitureId: string | undefined | null,
): FurnitureInfo | undefined {
  if (furnitureId == null) return undefined;
  return excel.BuildingData?.customData?.furnitures?.[furnitureId];
}

/**
 * 家具主题 ID（themeId，如 furni_set_warehouse）——勋章 BuildingGotFurnitureThemeCount
 * 按主题去重计数；未知家具返回 undefined
 */
export function getFurnitureThemeId(furnitureId: string | undefined | null): string | undefined {
  return getFurnitureInfo(furnitureId)?.themeId;
}

/**
 * 房间最大等级（phases 数组长度；未知房间返回 0）
 * 用于 upgradeRoom/degradeRoom 的等级边界校验
 */
export function getRoomMaxLevel(roomId: string | undefined | null): number {
  return excel.BuildingData?.rooms?.[roomId ?? ""]?.phases?.length ?? 0;
}

/**
 * 房间相位解锁条件 id（`rooms[roomId].phases[level-1].unlockCondId`，如 MANUFACTURE#2）
 *
 * 官方：每个房间等级都有解锁条件，指向 `roomUnlockConds[condId].number[*]`
 * （`{ type, level, count }` —— 需要指定类型房间达到指定等级、数量 ≥ count；
 * type = FUNCTIONAL 时为「功能房间数」）。修复前全模块无该字段引用，升级可绕过中枢等级门槛。
 * @param roomId - 房间类型
 * @param level - 目标等级（1 起）
 * @returns 条件 id；无配置返回 undefined
 */
export function getRoomUnlockCondId(
  roomId: string | undefined | null,
  level: number,
): string | undefined {
  const phase = getRoomPhase(roomId ?? "", level);
  return phase?.unlockCondId;
}

/**
 * 房间是否允许降级（`rooms[roomId].canLevelDown`；未知房间按 true）
 *
 * 官方数据中 CONTROL / WORKSHOP / HIRE / TRAINING / MEETING 为 false（不可降级）。
 * @param roomId - 房间类型
 * @returns 是否可降级
 */
export function canRoomLevelDown(roomId: string | undefined | null): boolean {
  const v = excel.BuildingData?.rooms?.[roomId ?? ""]?.canLevelDown;
  return v === undefined ? true : Boolean(v);
}

/**
 * 线索/信用常量（`clue_data.json`）
 *
 * 实测：`outputBasicBonus 20`（每产出 1 张线索的信用）/ `outputOperatorsBonus 20` /
 * `transferBonus 20`（转赠线索）/ `recycleBonus 5`（回收自有线索）/ `expiredBonus 25` /
 * `receiveTimeBonus [{1:15},{2:10},{3:5}]`（接收好友线索第 1/2/3 张）/ `initiatorBonus 210`（自己开启线索交流）/
 * `participantsBonus 30`（参与他人交流）/ `messageLeaveBoardConstData.visitorBonus 30`（访客信用）等。
 * @param key - clue_data 顶层键
 * @returns 常量值；缺表返回 undefined
 */
export function getClueConstant<K extends keyof ClueData>(
  key: K,
): ClueData[K] | undefined {
  return excel.ClueData?.[key];
}

/**
 * 接收好友线索的第 n 张信用（clue_data.receiveTimeBonus：第 1/2/3 张 = 15/10/5，第 4 张起 0）
 * @param index - 本日已接收张数（0 起）
 * @returns 信用值
 */
export function getClueReceiveBonus(index: number): number {
  const table = getClueConstant("receiveTimeBonus");
  const row = Array.isArray(table)
    ? table.find((r) => Number(r?.receiveTimes) === index + 1)
    : undefined;
  // 缺表/越界回退官方默认（第 1/2/3 张 = 15/10/5，第 4 张起 0）
  return Number(row?.receiveBonus ?? [15, 10, 5][index] ?? 0);
}

/**
 * 制造站单次排产份数上限（`building_data.manufactInputCapacity`，实测 99）
 *
 * 官服语义：选定制造方案时按份数一次性划拨原料，份数上限即该常量；
 * 官服存档佐证——制造站 `remainSolutionCnt + outputSolutionCnt = 99`。
 * @returns 上限（缺表回退 99）
 */
export function getManufactureInputCapacity(): number {
  const v = getBuildingConstant("manufactInputCapacity");
  return typeof v === "number" && v > 0 ? v : 99;
}

/**
 * 房间基础效率加成（每名在岗干员）——manufactData / tradingData / meetingData.basicSpeedBuff
 *
 * 官方：制造站与贸易站每进驻 1 名干员提供 +1% 基础效率（会客室为 +5%）。
 * 修复前该字段仅出现在生成类型里、运行期从未被读。
 * @param roomType - 房间类型（MANUFACTURE / TRADING / MEETING / HIRE）
 * @returns 每名在岗干员的加成（无配置返回 0）
 */
export function getRoomBasicSpeedBuff(roomType: string): number {
  // 各房间类型的 basicSpeedBuff（控制中枢为 basicCostBuff，无该字段 → 缺省 0）
  const map: { [roomType: string]: number | undefined } = {
    MANUFACTURE: excel.BuildingData?.manufactData?.basicSpeedBuff,
    TRADING: excel.BuildingData?.tradingData?.basicSpeedBuff,
    MEETING: excel.BuildingData?.meetingData?.basicSpeedBuff,
    HIRE: excel.BuildingData?.hireData?.basicSpeedBuff,
  };
  const v = map[roomType];
  return typeof v === "number" ? v : 0;
}

/** 加工配方类型（formulaType，如 F_BUILDING/F_EVOLVE）——勋章 BuildingWorkshopSynthesisGroupByID 按组过滤 */
export function getWorkshopFormulaType(
  formulaId: string | number | undefined | null,
): string | undefined {
  return getWorkshopFormula(formulaId)?.formulaType;
}

/** 制造配方类型（formulaType，如 F_EXP/F_GOLD）——贸易站订单按制造产出类型匹配 */
export function getManufactFormulaType(
  formulaId: string | number | undefined | null,
): string | undefined {
  return getManufactFormula(formulaId)?.formulaType;
}

/**
 * 房间电力（相位 electricity：POWER 正向发电、其余负向消耗；未知房间/相位返回 0）。
 * 电力系统：全部房间按当前等级求和，发电站（POWER）供给其余房间消耗。
 */
export function getRoomElectricity(
  roomId: string | undefined | null,
  level: number,
): number {
  const phase = getRoomPhase(roomId ?? "", Math.max(1, level || 1));
  return typeof phase?.electricity === "number" ? phase.electricity : 0;
}

/**
 * 会客室线索过期天数（官方 clue_data.json expiredDays，缺省 10 天）
 *
 * 好友赠送的线索进入 receiveStock 后，在过期时间（now + expiredDays×86400s）
 * 之后由 BuildingManager 自动移除；缺表/字段时回退官方默认值 10。
 */
export function getClueExpiredDays(): number {
  const days = excel.ClueData?.expiredDays;
  return typeof days === "number" && days > 0 ? days : 10;
}

/**
 * 会客室留言板常量（官方 clue_data.json messageLeaveBoardConstData）
 *
 * - visitorBonus：每位访客留言（好友访问）获得的社交点
 * - visitorBonusLimit：每周留言板社交点上限（封顶值）
 * 缺表/字段时回退官方默认（30 / 300）。
 */
export function getMessageLeaveBoardConst(): {
  visitorBonus: number;
  visitorBonusLimit: number;
} {
  const c = excel.ClueData?.messageLeaveBoardConstData;
  const visitorBonus = typeof c?.visitorBonus === "number" ? c.visitorBonus : 30;
  const visitorBonusLimit =
    typeof c?.visitorBonusLimit === "number" ? c.visitorBonusLimit : 300;
  return { visitorBonus, visitorBonusLimit };
}

/**
 * 会客室相位（level 从 1 起；friendSlotInc = 每次好友访问/情报分享的信用量）
 * 信用经济：socialReward.daily/search 按 friendSlotInc 累积（封顶 creditPassiveLimit/
 * creditInitiativeLimit），getMeetingroomReward 领取后清零重新累积。
 */
export function getMeetingPhase(
  level: number,
): MeetingPhase | undefined {
  return excel.BuildingData?.meetingData?.phases?.[level - 1];
}

/**
 * 人力办公室相位（level 从 1 起；resSpeed = 基础人脉搜集速度、refreshTimes = 每日招募刷新次数）
 * 时间推进：HIRE 房间 processPoint += 流逝时间 × 有效速度（resSpeed × (1 + hire_* buff)）。
 */
export function getHirePhase(
  level: number,
): HirePhase | undefined {
  return excel.BuildingData?.hireData?.phases?.[level - 1];
}
