/**
 * 统一物品变更管道（GainItemPipeline）
 *
 * 对齐 OBS `player_data.gainItem.setTarget(...).handle(player_data)` 的 fluent 形式：
 * 物品增减统一经管道入队、一次执行，替代散落的 `_trigger.emit("items:get"/"items:use")`
 * 直发（建议 4）。执行语义与既有事件完全一致：
 * - `handle()` → emit "items:get"（InventoryManager 串行 gainItem：入账 + 活动币跟踪 +
 *   勋章/任务事件，逐物品）
 * - `use()`   → emit "items:use"（InventoryManager 串行消耗，含 AP 补给等复合行为）
 *
 * 用法：
 * ```ts
 * await player.gainItem
 *   .setTarget("TKT_GACHA", "TKT_GACHA", 1)
 *   .setTarget("4003", "DIAMOND_SHD", 600)
 *   .use();                       // 一次请求内消耗多类物品
 * await player.gainItem.add({ id: "4002", type: "DIAMOND", count: 1 }).handle(); // 发放
 * ```
 */
import type { PlayerDataManager } from "./PlayerDataManager";
import type { TypedEventEmitter } from "./events";
import { ItemBundle } from "@excel/character_table";

export class GainItemPipeline {
  private _targets: ItemBundle[] = [];

  constructor(
    private _player: PlayerDataManager,
    private _trigger: TypedEventEmitter,
  ) {}

  /** 已入队的目标（只读，供断言/审计） */
  get targets(): readonly ItemBundle[] {
    return this._targets;
  }

  /**
   * 追加一个发放/消耗目标（fluent）
   * @param itemId - 物品 id（如 "TKT_GACHA" / "4003"）
   * @param itemType - 物品类型（如 "TKT_GACHA" / "DIAMOND_SHD"；缺省由 ItemTable 推断）
   * @param itemCount - 数量（正=获得，负=消耗）
   * @param itemInstId - consumable 实例 id（可选）
   */
  setTarget(
    itemId: string,
    itemType?: string,
    itemCount?: number,
    itemInstId?: number,
  ): this {
    this._targets.push({
      id: itemId,
      type: itemType as never,
      count: itemCount ?? 1,
      instId: itemInstId,
    });
    return this;
  }

  /**
   * 追加一个已组装的物品（fluent）
   * @param bundle - 物品（ItemBundle 形状）
   */
  add(bundle: ItemBundle): this {
    this._targets.push(bundle);
    return this;
  }

  /** 队列长度（0 时不执行） */
  get size(): number {
    return this._targets.length;
  }

  /** 清空队列（失败重试/复用场景） */
  clear(): this {
    this._targets = [];
    return this;
  }

  /**
   * 执行发放：emit "items:get"（经 InventoryManager 串行 gainItem 全链路）
   */
  async handle(): Promise<void> {
    if (this._targets.length === 0) return;
    await this._trigger.emit("items:get", [this._targets]);
    this._targets = [];
  }

  /**
   * 执行消耗：emit "items:use"（经 InventoryManager 串行消耗）
   */
  async use(): Promise<void> {
    if (this._targets.length === 0) return;
    await this._trigger.emit("items:use", [this._targets]);
    this._targets = [];
  }
}
