/**
 * 保险库（reslock）请求体 zod schema
 *
 * 协议类字段取自反编译 CS（reference/arknights-2.7.71-csharp，Torappu 命名空间）：
 * - ItemRepoReslockInventoryRequest   { itemId, count }        → /reslock/lockInventory
 * - ItemRepoResUnlockInventoryRequest { itemId, count }        → /reslock/unlockInventory
 * - ItemRepoReslockConsumableRequest  { instId, itemId, count }→ /reslock/lockConsumable
 * - ItemRepoResUnlockConsumableRequest{ instId, itemId, count }→ /reslock/unlockConsumable
 *
 * count 统一约束为**正整数**：锁定/解锁方向由路由决定，负数或 0 会翻转语义
 * （如锁定 -5 变成从保险库取出 5），必须在入口拦掉。
 */
import { z } from "zod";

/** 库存物品锁定/移出（CS: ItemRepoReslockInventoryRequest / ItemRepoResUnlockInventoryRequest） */
export const reslockInventorySchema = z.object({
  itemId: z.string().min(1),
  count: z.number().int().positive(),
});

/**
 * 消耗品实例锁定/移出（CS: ItemRepoReslockConsumableRequest / ItemRepoResUnlockConsumableRequest）
 *
 * instId 客户端可能以字符串或数字下发（consumable 键为数字），统一 union 后在业务层归一化。
 */
export const reslockConsumableSchema = z.object({
  instId: z.union([z.string(), z.number()]),
  itemId: z.string().min(1),
  count: z.number().int().positive(),
});
