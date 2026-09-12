/**
 * 保险库（reslock）单元测试
 *
 * 覆盖四类存取的状态迁移、增量下发与边界：资格校验、余额校验、计数归零摘除、
 * 消耗品实例时间戳保留、以及请求 schema 对负数/0 的拦截（方向翻转防护）。
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

// excel 门面打桩：reslock 仅依赖 getItem（canReslock 资格判定）
vi.mock("@excel/excel", () => ({
  default: {
    ItemTable: {
      items: {
        randomMaterialRune_0: {
          itemId: "randomMaterialRune_0",
          name: "荒芜行动物资补给",
          itemType: "VOUCHER_MGACHA",
          canReslock: true,
        },
        "3251": {
          itemId: "3251",
          name: "术师芯片",
          itemType: "MATERIAL",
          canReslock: true,
        },
        "3003": {
          itemId: "3003",
          name: "赤金",
          itemType: "MATERIAL",
          canReslock: false,
        },
      },
    },
    getItem(id: string) {
      return (this as any).ItemTable?.items?.[id];
    },
  },
}));

import { PlayerDataManager } from "@game/kernel/PlayerDataManager";
import { mockPlayerData } from "../../../helpers/mockPlayerData";
import {
  lockConsumable,
  lockInventory,
  unlockConsumable,
  unlockInventory,
} from "@game/modules/reslock/reslock";
import {
  reslockConsumableSchema,
  reslockInventorySchema,
} from "@game/modules/reslock/reslock.schema";

/** 构造带库存/消耗品的玩家（reslock 缺省不存在，模拟老存档） */
function makePlayer(): PlayerDataManager {
  const pd: any = mockPlayerData({
    mission: { missions: {} },
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } },
    rlv2: { outer: {}, current: {}, pinned: {} },
    inventory: { "3251": 10, "3003": 5 },
    consumable: {
      randomMaterialRune_0: { 0: { count: 5, ts: 1695000000 } },
    },
  } as any);
  return new PlayerDataManager(pd._playerdata as any);
}

describe("reslock 保险库（库存物品）", () => {
  let player: PlayerDataManager;

  beforeEach(() => {
    player = makePlayer();
  });

  it("存入：库存减少、reslock 增加，且两者同批下发 delta", async () => {
    await lockInventory(player, { itemId: "3251", count: 6 });
    const data = player._playerdata as any;
    expect(data.inventory["3251"]).toBe(4);
    expect(data.reslock.inventory["3251"]).toBe(6);

    const delta = player.delta.playerDataDelta as any;
    expect(delta.modified.inventory["3251"]).toBe(4);
    expect(delta.modified.reslock.inventory["3251"]).toBe(6);
  });

  it("存入：老存档缺 reslock 时自动初始化", async () => {
    const data = player._playerdata as any;
    expect(data.reslock).toBeUndefined();
    await lockInventory(player, { itemId: "3251", count: 1 });
    expect((player._playerdata as any).reslock.inventory["3251"]).toBe(1);
  });

  it("存入：item_table 标记不可存入的物品被拒且不改数据", async () => {
    await expect(lockInventory(player, { itemId: "3003", count: 1 })).rejects.toThrow(
      /不可存入保险库/,
    );
    expect((player._playerdata as any).inventory["3003"]).toBe(5);
    expect((player._playerdata as any).reslock?.inventory?.["3003"]).toBeUndefined();
  });

  it("存入：不在 item_table 的物品被拒", async () => {
    await expect(
      lockInventory(player, { itemId: "not_exist", count: 1 }),
    ).rejects.toThrow(/物品不存在/);
  });

  it("存入：持有不足被拒且不改数据（防负库存）", async () => {
    await expect(lockInventory(player, { itemId: "3251", count: 11 })).rejects.toThrow(
      /物品不足/,
    );
    expect((player._playerdata as any).inventory["3251"]).toBe(10);
    expect((player._playerdata as any).reslock?.inventory?.["3251"]).toBeUndefined();
  });

  it("移出：库存回补、保险库计数归零即摘除条目", async () => {
    await lockInventory(player, { itemId: "3251", count: 10 });
    expect((player._playerdata as any).reslock.inventory["3251"]).toBe(10);
    expect((player._playerdata as any).inventory["3251"]).toBe(0);

    await unlockInventory(player, { itemId: "3251", count: 10 });
    expect((player._playerdata as any).inventory["3251"]).toBe(10);
    expect((player._playerdata as any).reslock.inventory["3251"]).toBeUndefined();
  });

  it("移出：部分移出保留剩余计数", async () => {
    await lockInventory(player, { itemId: "3251", count: 8 });
    await unlockInventory(player, { itemId: "3251", count: 3 });
    expect((player._playerdata as any).inventory["3251"]).toBe(5);
    expect((player._playerdata as any).reslock.inventory["3251"]).toBe(5);
  });

  it("移出：保险库存量不足被拒（不做 canReslock 复核）", async () => {
    await expect(
      unlockInventory(player, { itemId: "3003", count: 1 }),
    ).rejects.toThrow(/保险库内物品不足/);
  });
});

describe("reslock 保险库（消耗品实例）", () => {
  let player: PlayerDataManager;

  beforeEach(() => {
    player = makePlayer();
  });

  it("存入：实例计数扣减、保险库按实例记录并保留 ts", async () => {
    await lockConsumable(player, {
      instId: "0",
      itemId: "randomMaterialRune_0",
      count: 2,
    });
    const data = player._playerdata as any;
    expect(data.consumable.randomMaterialRune_0["0"].count).toBe(3);
    expect(data.reslock.consumable.randomMaterialRune_0["0"]).toEqual({
      count: 2,
      ts: 1695000000,
    });
  });

  it("存入：全部存入时实例从 consumable 摘除（物品整体搬入保险库）", async () => {
    await lockConsumable(player, {
      instId: 0,
      itemId: "randomMaterialRune_0",
      count: 5,
    });
    const data = player._playerdata as any;
    expect(data.consumable.randomMaterialRune_0).toBeUndefined();
    expect(data.reslock.consumable.randomMaterialRune_0["0"].count).toBe(5);
  });

  it("移出：实例按保险库保留的 ts 重建", async () => {
    await lockConsumable(player, {
      instId: 0,
      itemId: "randomMaterialRune_0",
      count: 5,
    });
    await unlockConsumable(player, {
      instId: 0,
      itemId: "randomMaterialRune_0",
      count: 5,
    });
    const data = player._playerdata as any;
    expect(data.consumable.randomMaterialRune_0["0"]).toEqual({
      count: 5,
      ts: 1695000000,
    });
    expect(data.reslock.consumable.randomMaterialRune_0).toBeUndefined();
  });

  it("移出：实例已存在于 consumable 时累加计数（不覆盖 ts）", async () => {
    await lockConsumable(player, {
      instId: 0,
      itemId: "randomMaterialRune_0",
      count: 2,
    });
    await unlockConsumable(player, {
      instId: 0,
      itemId: "randomMaterialRune_0",
      count: 2,
    });
    const data = player._playerdata as any;
    expect(data.consumable.randomMaterialRune_0["0"].count).toBe(5);
    expect(data.reslock.consumable?.randomMaterialRune_0).toBeUndefined();
  });

  it("存入：实例不存在 / 持有不足 / 不可存入 均被拒", async () => {
    await expect(
      lockConsumable(player, { instId: "9", itemId: "randomMaterialRune_0", count: 1 }),
    ).rejects.toThrow(/实例不存在/);
    await expect(
      lockConsumable(player, { instId: "0", itemId: "randomMaterialRune_0", count: 6 }),
    ).rejects.toThrow(/物品不足/);
    await expect(
      lockConsumable(player, { instId: "0", itemId: "3003", count: 1 }),
    ).rejects.toThrow(/不可存入保险库/);
    // 失败请求不得留下任何痕迹（配方抛错 → mutative 草稿丢弃）
    expect((player._playerdata as any).reslock).toBeUndefined();
  });

  it("移出：保险库无该实例被拒", async () => {
    await expect(
      unlockConsumable(player, { instId: "0", itemId: "randomMaterialRune_0", count: 1 }),
    ).rejects.toThrow(/保险库内无该实例/);
  });
});

describe("reslock 请求 schema", () => {
  it("count 必须为正整数（方向由路由决定，负数会翻转语义）", () => {
    expect(reslockInventorySchema.safeParse({ itemId: "3251", count: 1 }).success).toBe(true);
    expect(reslockInventorySchema.safeParse({ itemId: "3251", count: 0 }).success).toBe(false);
    expect(reslockInventorySchema.safeParse({ itemId: "3251", count: -5 }).success).toBe(false);
    expect(reslockInventorySchema.safeParse({ itemId: "3251", count: 1.5 }).success).toBe(false);
    expect(reslockInventorySchema.safeParse({ count: 1 }).success).toBe(false);
  });

  it("消耗品 instId 允许字符串或数字（实例键为数字）", () => {
    expect(
      reslockConsumableSchema.safeParse({
        instId: "0",
        itemId: "randomMaterialRune_0",
        count: 1,
      }).success,
    ).toBe(true);
    expect(
      reslockConsumableSchema.safeParse({
        instId: 0,
        itemId: "randomMaterialRune_0",
        count: 1,
      }).success,
    ).toBe(true);
    expect(
      reslockConsumableSchema.safeParse({ itemId: "randomMaterialRune_0", count: 1 }).success,
    ).toBe(false);
  });
});
