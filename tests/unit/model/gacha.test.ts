import { describe, it, expect } from 'vitest';
import { GachaType } from '@game/modules/gacha/gacha';
import type { GachaResult } from '@game/modules/gacha/gacha';
import type { ItemBundle } from '@excel/excel';

/**
 * 掉落物组合夹具视图
 *
 * `ItemBundle.type` 真实为枚举 `ItemType`（大写，如 `MATERIAL`/`CHAR`），本用例沿用早期
 * 小写字面量夹具（仅形状冒烟，断言比较的也是小写值）。为不改夹具数据，仅就地放宽 `type`；
 * 其余字段仍受真实模型约束。
 */
type ItemBundleFixture = Omit<ItemBundle, 'type'> & { type: string; instId?: number };

/** 抽卡结果夹具视图：仅 `itemGet` 放宽（见 {@link ItemBundleFixture}） */
type GachaResultFixture = Omit<GachaResult, 'itemGet'> & { itemGet: ItemBundleFixture[] };

describe('Gacha 模型', () => {
  describe('GachaType 枚举', () => {
    it('应包含所有抽卡类型', () => {
      expect(GachaType.None).toBe(4294967295);
      expect(GachaType.Diamond).toBe(0);
      expect(GachaType.SingleTicket).toBe(1);
      expect(GachaType.TenTicket).toBe(2);
      expect(GachaType.LimitSingle).toBe(3);
      expect(GachaType.UseItem).toBe(4);
      expect(GachaType.TenSingleTkt).toBe(5);
      expect(GachaType.ClassicSingleTicket).toBe(6);
      expect(GachaType.ClassicTenTicket).toBe(7);
      expect(GachaType.classicTenSingleTicket).toBe(8);
      expect(GachaType.CombineTenTicket).toBe(9);
    });

    it('None 应使用最大 32 位无符号整数值', () => {
      expect(GachaType.None).toBe(4294967295);
      expect(GachaType.None).toBe(0xFFFFFFFF);
    });

    it('Diamond 应为默认的钻石抽卡类型', () => {
      expect(GachaType.Diamond).toBe(0);
    });

    it('SingleTicket 和 TenTicket 应有不同值', () => {
      expect(GachaType.SingleTicket).not.toBe(GachaType.TenTicket);
      expect(GachaType.SingleTicket).toBeLessThan(GachaType.TenTicket);
    });

    it('经典系列应有独立的枚举值', () => {
      expect(GachaType.ClassicSingleTicket).toBe(6);
      expect(GachaType.ClassicTenTicket).toBe(7);
      expect(GachaType.classicTenSingleTicket).toBe(8);
    });

    it('枚举值应全部唯一', () => {
      const values = Object.values(GachaType).filter(
        (v) => typeof v === 'number'
      ) as number[];
      const uniqueValues = new Set(values);
      expect(uniqueValues.size).toBe(values.length);
    });

    it('CombineTenTicket 应为最新类型', () => {
      expect(GachaType.CombineTenTicket).toBe(9);
    });
  });

  describe('GachaResult', () => {
    it('应包含抽卡结果的所有字段', () => {
      const itemGet: ItemBundleFixture[] = [
        { id: 'item_001', count: 10, type: 'material' },
        { id: 'item_002', count: 1, type: 'char', instId: 2001 },
      ];

      const result: GachaResultFixture = {
        charInstId: 2001,
        charId: 'char_001',
        isNew: 1,
        itemGet: itemGet,
        potent: {
          delta: 1,
          now: 5,
        },
      };

      expect(result.charInstId).toBe(2001);
      expect(result.charId).toBe('char_001');
      expect(result.isNew).toBe(1);
      expect(result.itemGet).toHaveLength(2);
      expect(result.itemGet[0].id).toBe('item_001');
      expect(result.potent).toBeDefined();
      expect(result.potent!.delta).toBe(1);
      expect(result.potent!.now).toBe(5);
    });

    it('isNew 为 0 时表示非新干员', () => {
      const result: GachaResultFixture = {
        charInstId: 1001,
        charId: 'char_existing',
        isNew: 0,
        itemGet: [],
      };

      expect(result.isNew).toBe(0);
      expect(result.itemGet).toHaveLength(0);
    });

    it('potent 字段可选，未设置时应为 undefined', () => {
      const result: GachaResultFixture = {
        charInstId: 3001,
        charId: 'char_no_potent',
        isNew: 1,
        itemGet: [{ id: 'item_001', count: 5, type: 'material' }],
      };

      expect(result.potent).toBeUndefined();
    });

    it('多个 itemGet 应正确记录', () => {
      const result: GachaResultFixture = {
        charInstId: 4001,
        charId: 'char_multi_drop',
        isNew: 1,
        itemGet: [
          { id: 'char_001', count: 1, type: 'char', instId: 4001 },
          { id: 'item_001', count: 5000, type: 'gold' },
          { id: 'item_002', count: 10, type: 'material' },
          { id: 'item_003', count: 1, type: 'card_exp' },
        ],
      };

      expect(result.itemGet).toHaveLength(4);
      expect(result.itemGet[0].type).toBe('char');
      expect(result.itemGet[1].count).toBe(5000);
    });

    it('potent 应正确记录潜能变化', () => {
      const result: GachaResultFixture = {
        charInstId: 5001,
        charId: 'char_potent_up',
        isNew: 0,
        itemGet: [],
        potent: {
          delta: 2,
          now: 7,
        },
      };

      expect(result.potent!.delta).toBe(2);
      expect(result.potent!.now).toBe(7);
      expect(result.isNew).toBe(0);
    });
  });
});