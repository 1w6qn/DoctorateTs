import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    GachaTable: {
      gachaPoolClient: [
        { gachaPoolId: "p_normal_1", gachaRuleType: "NORMAL" },
        { gachaPoolId: "p_double_1", gachaRuleType: "DOUBLE" },
      ],
    },
    GachaDetailTable: {
      details: {
        p_normal_1: {
          upCharInfo: { perCharList: [] },
          availCharInfo: {
            perAvailList: [
              { rarityRank: 5, totalPercent: 2, charIdList: ["char_001"] },
              { rarityRank: 4, totalPercent: 50, charIdList: ["char_002"] },
              { rarityRank: 3, totalPercent: 48, charIdList: ["char_003"] },
            ],
          },
        },
      },
    },
  },
}));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/gacha_detail_table", () => ({}));
vi.mock("@excel/types_auto_gen", () => ({}));
vi.mock("@game/manager/AccountManger", () => ({
  accountManager: {
    getBeforeNonHitCnt: vi.fn().mockResolvedValue(0),
    saveBeforeNonHitCnt: vi.fn().mockResolvedValue(undefined),
  },
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { GachaController } from "@game/controller/gacha";
import { GachaType } from "@game/model/gacha";

describe("GachaController 抽卡扣费 costs 构造", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      gacha: {
        normal: {},
        single: {},
      } as any,
    });
    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  it("Diamond 单抽应只扣 600 合成玉（id=4003 带 type，且无 fallthrough）", async () => {
    const controller = new GachaController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    // 阻断后续抽卡流程，只验证 costs 构造
    vi.spyOn(controller, "doAdvancedGacha").mockResolvedValue({
      charInstId: 1,
      charId: "char_001",
      isNew: 0,
      itemGet: [],
      logInfo: { beforeNonHitCnt: 0 },
    } as any);
    await controller.advancedGacha({ poolId: "p_normal_1", useTkt: GachaType.Diamond, itemId: "" });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "4003", type: "DIAMOND_SHD", count: 600 }],
    ]);
  });

  it("SingleTicket 单抽应只扣 1 张寻访凭证（无 fallthrough）", async () => {
    const controller = new GachaController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    vi.spyOn(controller, "doAdvancedGacha").mockResolvedValue({
      charInstId: 1,
      charId: "char_001",
      isNew: 0,
      itemGet: [],
      logInfo: { beforeNonHitCnt: 0 },
    } as any);
    await controller.advancedGacha({ poolId: "p_normal_1", useTkt: GachaType.SingleTicket, itemId: "" });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "TKT_GACHA", type: "TKT_GACHA", count: 1 }],
    ]);
  });

  it("UseItem 单抽应扣客户端指定物品", async () => {
    const controller = new GachaController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    vi.spyOn(controller, "doAdvancedGacha").mockResolvedValue({
      charInstId: 1,
      charId: "char_001",
      isNew: 0,
      itemGet: [],
      logInfo: { beforeNonHitCnt: 0 },
    } as any);
    await controller.advancedGacha({ poolId: "p_normal_1", useTkt: GachaType.UseItem, itemId: "4005" });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "4005", count: 1 }]]);
  });

  it("BOOT 池 Diamond 单抽应扣 380 合成玉", async () => {
    const controller = new GachaController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    vi.spyOn(controller, "doAdvancedGacha").mockResolvedValue({
      charInstId: 1,
      charId: "char_001",
      isNew: 0,
      itemGet: [],
      logInfo: { beforeNonHitCnt: 0 },
    } as any);
    await controller.advancedGacha({ poolId: "BOOT_1", useTkt: GachaType.Diamond, itemId: "" });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "4003", type: "DIAMOND_SHD", count: 380 }],
    ]);
  });

  it("Diamond 十连应只扣 6000 合成玉", async () => {
    const controller = new GachaController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    vi.spyOn(controller, "doAdvancedGacha").mockResolvedValue({
      charInstId: 1,
      charId: "char_001",
      isNew: 0,
      itemGet: [],
      logInfo: { beforeNonHitCnt: 0 },
    } as any);
    await controller.tenAdvancedGacha({ poolId: "p_normal_1", useTkt: GachaType.Diamond, itemList: [] });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "4003", type: "DIAMOND_SHD", count: 6000 }],
    ]);
  });

  it("CombineTenTicket 十连应消耗客户端 itemList 且不叠加其他费用", async () => {
    const controller = new GachaController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    vi.spyOn(controller, "doAdvancedGacha").mockResolvedValue({
      charInstId: 1,
      charId: "char_001",
      isNew: 0,
      itemGet: [],
      logInfo: { beforeNonHitCnt: 0 },
    } as any);
    await controller.tenAdvancedGacha({
      poolId: "p_normal_1",
      useTkt: GachaType.CombineTenTicket,
      itemList: [{ id: "4005", count: 10 }],
    });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "4005", count: 10 }]]);
  });

  describe("缺详情卡池回退（2026-08-09 修复）", () => {
    it("_poolDetail 对 gacha_detail_table 缺失的卡池应回退而非抛错", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      // p_normal_1 在表内直接返回；LIMITED_76_0_1 缺失 → 回退（不抛错）
      expect(controller._poolDetail("p_normal_1")).toBeDefined();
      const fallback = controller._poolDetail("LIMITED_76_0_1");
      expect(fallback).toBeDefined();
      expect(fallback.availCharInfo).toBeDefined();
    });

    it("doAdvancedGacha 对缺失详情卡池应正常返回（不 500）", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      // char:get 事件 emit 会调用 mockTrigger.emit（测试环境无订阅），
      // 只验证不抛错——真实行为由实机冒烟覆盖
      await expect(
        controller.doAdvancedGacha({ poolId: "LIMITED_76_0_1", useTkt: 0, itemId: "" }),
      ).resolves.toBeDefined();
    });
  });

  describe("ruleType 缺失处理（2026-08-09 修复）", () => {
    it("DOUBLE/CLASSIC_DOUBLE/BACKFLOW/SPECIAL 池应走通用 _handleGacha 不 500", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      // p_double_1 是 DOUBLE ruleType（此前 funcs 缺该键 → 500）
      await expect(
        controller.doAdvancedGacha({ poolId: "p_double_1", useTkt: 0, itemId: "" }),
      ).resolves.toBeDefined();
    });
  });
});
