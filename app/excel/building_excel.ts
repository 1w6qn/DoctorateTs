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
): { buildCost?: { items?: { id: string; count: number; type: string }[]; time?: number; labor?: number }; maxStationedNum?: number } | undefined {
  return excel.BuildingData?.rooms?.[roomId]?.phases?.[level - 1];
}

/** 贸易凭证汇率（goldItems 3003 → 金币；缺省 500） */
export function getGoldRate(): number {
  return excel.BuildingData?.goldItems?.["3003"] ?? 500;
}

/** 读取 BuildingData 顶层常量（laborRecoverTime/basicFavorPerDay/apToLaborRatio 等） */
export function getBuildingConstant<T = number>(key: string): T | undefined {
  return (excel.BuildingData as any)?.[key] as T | undefined;
}
