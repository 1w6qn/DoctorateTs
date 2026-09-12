/**
 * 限定寻访（LIMITED）免费次数与 300 抽赠送账本
 *
 * 数据源：excel `GachaTable.freeGacha`（`[{ poolId, openTime, endTime, freeCount }]`）——
 * 限定池活动期内的**每日免费寻访次数**（实测 `LIMITED_9_0_3` 等 24 期 `freeCount = 1`）。
 * 玩家侧字段见 `types-playerdata` 的 `PlayerGacha_PlayerFreeLimitGacha`：
 * `{ leastFree, poolCnt, recruitedFreeChar }`（`gacha.limit[poolId]`）。
 *
 * 修复背景（§5.2-3）：原实现这三字段**全仓无写入点** —— 300 抽赠送拿不到、
 * 免费寻访无任何计数（可无限免费抽）。
 */
import excel from "@excel/excel";
import type { Draft } from "mutative";
import type {
  PlayerDataModel,
  PlayerGacha_PlayerFreeLimitGacha,
} from "../../kernel/playerdata";

/** 限定寻访赠送当期 UP 六星所需的抽数（官方 300 抽） */
export const LIMIT_FREE_GACHA_THRESHOLD = 300;

/** freeGacha 条目 */
export interface FreeGachaEntry {
  poolId: string;
  openTime: number;
  endTime: number;
  freeCount: number;
}

/** 限定池免费账本视图（服务端扩展：`freeDay` 日序私服字段） */
type LimitGachaView = PlayerGacha_PlayerFreeLimitGacha & { freeDay?: number };

/**
 * 抽卡账本写入视图
 *
 * 生成类型把 gacha/limit 声明为必填，但旧存档/测试夹具可能整体缺失这些子表，
 * 旧实现用 `any` 逐层兜底；此处保留同一行为（可选 + `??=`）。
 */
interface GachaLimitView {
  gacha?: { limit?: { [poolId: string]: LimitGachaView } };
}

/**
 * 取某限定池的免费寻访配置
 * @param poolId - 卡池 id
 * @returns freeGacha 条目；未收录返回 undefined
 */
export function freeGachaEntry(poolId: string): FreeGachaEntry | undefined {
  const list = excel.GachaTable?.freeGacha ?? [];
  return list.find((e) => e?.poolId === poolId);
}

/**
 * 某池在指定时刻可用的每日免费寻访次数（窗口外为 0）
 * @param poolId - 卡池 id
 * @param nowTs - 当前时间（秒）
 * @returns 免费次数
 */
export function freeCountFor(poolId: string, nowTs: number): number {
  const e = freeGachaEntry(poolId);
  if (!e) return 0;
  if (nowTs < Number(e.openTime ?? 0) || nowTs > Number(e.endTime ?? 0)) return 0;
  return Math.max(0, Number(e.freeCount ?? 0));
}

/**
 * 取（必要时创建）`gacha.limit[poolId]` 账本
 * @param draft - 玩家数据草稿
 * @param poolId - 卡池 id
 * @returns 账本记录
 */
export function ensureLimitGacha(draft: Draft<PlayerDataModel>, poolId: string): LimitGachaView {
  const view = draft as GachaLimitView;
  const gacha = (view.gacha ??= {});
  const limit = (gacha.limit ??= {});
  if (!limit[poolId]) {
    limit[poolId] = { leastFree: 0, poolCnt: 0, recruitedFreeChar: false };
  }
  const rec = limit[poolId];
  if (rec.leastFree == null) rec.leastFree = 0;
  if (rec.poolCnt == null) rec.poolCnt = 0;
  if (rec.recruitedFreeChar == null) rec.recruitedFreeChar = false;
  return rec;
}

/**
 * 每日免费寻访刷新
 *
 * 官方为「活动期内每日 N 次」（不累计），故按自然日重置 `leastFree`。
 * 日序记录在私有扩展字段 `freeDay`（官服字段仅 leastFree/poolCnt/recruitedFreeChar，
 * 客户端忽略未知字段；与其它模块的私服扩展字段同例）。
 * @param draft - 玩家数据草稿
 * @param poolId - 卡池 id
 * @param nowTs - 当前时间（秒）
 */
export function refreshLimitFree(draft: Draft<PlayerDataModel>, poolId: string, nowTs: number): void {
  const day = Math.floor(nowTs / 86400);
  const rec = ensureLimitGacha(draft, poolId);
  if (Number(rec.freeDay ?? -1) === day) return;
  rec.freeDay = day;
  rec.leastFree = freeCountFor(poolId, nowTs);
}
