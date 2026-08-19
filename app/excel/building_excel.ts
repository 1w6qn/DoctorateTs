/**
 * 基建 Excel 查询工具
 *
 * 从 excel.BuildingData 查表（制造/加工配方、房间相位、汇率、常量），
 * 供 BuildingManager 复用——替代硬编码区间/常量。
 */
import excel from "./excel";

/** 制造配方（formulaId 字符串/数字兼容；未知返回 undefined） */
export function getManufactFormula(
  formulaId: string | number | undefined | null,
): any {
  if (formulaId == null) return undefined;
  return excel.BuildingData?.manufactFormulas?.[String(formulaId)];
}

/** 加工配方（未知返回 undefined） */
export function getWorkshopFormula(
  formulaId: string | number | undefined | null,
): any {
  if (formulaId == null) return undefined;
  return excel.BuildingData?.workshopFormulas?.[String(formulaId)];
}

/** 房间相位（level 从 1 起；越界返回 undefined） */
export function getRoomPhase(
  roomId: string,
  level: number,
): { buildCost?: { items?: { id: string; count: number; type: string }[]; time?: number; labor?: number }; maxStationedNum?: number; electricity?: number } | undefined {
  return excel.BuildingData?.rooms?.[roomId]?.phases?.[level - 1];
}

/** 贸易凭证汇率（goldItems 3003 → 金币；缺省 500） */
export function getGoldRate(): number {
  return excel.BuildingData?.goldItems?.["3003"] ?? 500;
}

/** 制造站相位（level 从 1 起；outputCapacity = 基础容量） */
export function getManufactPhase(
  level: number,
): { speed?: number; outputCapacity?: number } | undefined {
  return excel.BuildingData?.manufactData?.phases?.[level - 1];
}

/** 宿舍相位（level 从 1 起；manpowerRecover 为心情恢复数值——注意个别相位是占位字符串） */
export function getDormPhase(
  level: number,
): { manpowerRecover?: number | string } | undefined {
  return excel.BuildingData?.dormData?.phases?.[level - 1];
}

/** 读取 BuildingData 顶层常量（laborRecoverTime/basicFavorPerDay/apToLaborRatio 等） */
export function getBuildingConstant<T = number>(key: string): T | undefined {
  return (excel.BuildingData as any)?.[key] as T | undefined;
}

/**
 * 家具信息（BuildingData.customData.furnitures[家具id]——舒适度/主题/分解产物等）
 * 未知家具返回 undefined（数据版本错位时容错跳过）
 */
export function getFurnitureInfo(
  furnitureId: string | undefined | null,
): { comfort?: number; themeId?: string; processedProductId?: string; processedProductCount?: number; name?: string } | undefined {
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

/** 加工配方类型（formulaType，如 F_BUILDING/F_EVOLVE）——勋章 BuildingWorkshopSynthesisGroupByID 按组过滤 */
export function getWorkshopFormulaType(
  formulaId: string | number | undefined | null,
): string | undefined {
  return getWorkshopFormula(formulaId)?.formulaType as string | undefined;
}

/** 制造配方类型（formulaType，如 F_EXP/F_GOLD）——贸易站订单按制造产出类型匹配 */
export function getManufactFormulaType(
  formulaId: string | number | undefined | null,
): string | undefined {
  return getManufactFormula(formulaId)?.formulaType as string | undefined;
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
 * 会客室相位（level 从 1 起；friendSlotInc = 每次好友访问/情报分享的信用量）
 * 信用经济：socialReward.daily/search 按 friendSlotInc 累积（封顶 creditPassiveLimit/
 * creditInitiativeLimit），getMeetingroomReward 领取后清零重新累积。
 */
export function getMeetingPhase(
  level: number,
): { friendSlotInc?: number; maxVisitorNum?: number; gatheringSpeed?: number } | undefined {
  return excel.BuildingData?.meetingData?.phases?.[level - 1];
}

/**
 * 人力办公室相位（level 从 1 起；resSpeed = 基础人脉搜集速度、refreshTimes = 每日招募刷新次数）
 * 时间推进：HIRE 房间 processPoint += 流逝时间 × 有效速度（resSpeed × (1 + hire_* buff)）。
 */
export function getHirePhase(
  level: number,
): { economizeRate?: number; resSpeed?: number; refreshTimes?: number } | undefined {
  return excel.BuildingData?.hireData?.phases?.[level - 1];
}
