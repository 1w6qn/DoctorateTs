/**
 * 基建配方/策略解锁判定引擎（纯函数，无 IO）
 *
 * 官方机制（prts.wiki 制造站/加工站页，2026-08-25 全量对齐）：
 * - 制造/加工配方按 requireRooms（"曾达到"等级 + 当前房间数）与
 *   requireStages（关卡 rank 星）解锁；解锁后任意等级房间可用
 * - 贸易站"开采协力"策略需站级达到 tradingStrategyUnlockLevel（excel 常量 = 3）
 *
 * "曾达等级"（maxLevelReached）为服务端扩展字段（官方存档无此字段——官方由
 * 客户端本地配方表判定；服务端校验需持久化历史等级），降级不回退。
 */
import { getBuildingConstant } from "@excel/building_excel";

/** 配方解锁判定上下文（由 BuildingManager 从存档构造） */
export interface FormulaUnlockCtx {
  /** roomId → 曾达最高等级（buildRoom/upgradeRoom 取 max 更新，降级不回退） */
  maxLevelReached: Record<string, number>;
  /** roomId → 当前已建造房间数（roomSlots 按类型计数） */
  roomCountByType: Record<string, number>;
  /** stageId → 通关星数（dungeon.stages[].state；1=失败，2=胜利，3=三星，4=突袭三星） */
  stageState: Record<string, number>;
}

/**
 * 配方是否解锁：
 * - requireRooms[]：曾达等级 ≥ roomLevel 且当前该类型房间数 ≥ roomCount
 * - requireStages[]：关卡通关星数 ≥ rank（rank=2 即二星通关）
 * 无条件配方（缺省/空数组）视为解锁。
 */
export function isFormulaUnlocked(formula: any, ctx: FormulaUnlockCtx): boolean {
  if (!formula) return false;
  for (const req of formula.requireRooms ?? []) {
    const reached = ctx.maxLevelReached[req?.roomId] ?? 0;
    if (reached < (req?.roomLevel ?? 1)) return false;
    const count = ctx.roomCountByType[req?.roomId] ?? 0;
    if (count < (req?.roomCount ?? 1)) return false;
  }
  for (const req of formula.requireStages ?? []) {
    const state = ctx.stageState[req?.stageId] ?? 0;
    if (state < (req?.rank ?? 2)) return false;
  }
  return true;
}

/**
 * 开采协力（O_DIAMOND）策略是否解锁：贸易站等级 ≥ tradingStrategyUnlockLevel。
 * @param roomLevel - 贸易站当前等级
 */
export function isDiamondStrategyUnlocked(roomLevel: number): boolean {
  const need = getBuildingConstant<number>("tradingStrategyUnlockLevel") ?? 3;
  return (roomLevel ?? 0) >= need;
}
