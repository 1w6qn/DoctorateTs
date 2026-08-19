import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    GachaTable: {
      gachaPoolClient: [
        { gachaPoolId: "p_normal_1", gachaRuleType: "NORMAL" },
        { gachaPoolId: "p_double_1", gachaRuleType: "DOUBLE" },
        { gachaPoolId: "p_limited_1", gachaRuleType: "LIMITED", lMTGSID: "LMTGS_COIN_TEST" },
        // 无 lMTGSID 的限定池 → 凭证回退 "LMTGS_COIN"
        { gachaPoolId: "p_limited_2", gachaRuleType: "LIMITED" },
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
    // 抽卡 UseItem/CombineTenTicket 消耗走 ItemTable 解析类型（余额校验依赖）
    ItemTable: {
      items: {
        "4005": { itemType: "LGG_SHD" },
      },
    },
  },
}));
vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/gacha_detail_table", () => ({}));

vi.mock("@game/manager/AccountManager", () => ({
  accountManager: {
    getBeforeNonHitCnt: vi.fn().mockResolvedValue(0),
    saveBeforeNonHitCnt: vi.fn().mockResolvedValue(undefined),
  },
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { GachaController } from "@game/controller/gacha";
import { GachaType } from "@game/model/gacha";
import { accountManager } from "@game/manager/AccountManager";
import excelData from "@excel/excel";

/** accountManager 模块 mock 的 saveBeforeNonHitCnt（vi.fn()，调用历史跨测试保留需手动 clear） */
const saveSpy = vi.mocked(accountManager.saveBeforeNonHitCnt);

describe("GachaController 抽卡扣费 costs 构造", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    saveSpy.mockClear();
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

  it("合成玉（DIAMOND_SHD）单抽余额按 diamondShard 校验，不误用源石 androidDiamond", async () => {
    const controller = new GachaController(mockPlayer as any, mockTrigger as any);
    vi.spyOn(controller, "doAdvancedGacha").mockResolvedValue({
      charInstId: 1,
      charId: "char_001",
      isNew: 0,
      itemGet: [],
      logInfo: { beforeNonHitCnt: 0 },
    } as any);
    const st = (mockPlayer._playerdata.status as any);
    // 合成玉充足（1000 ≥ 600）、源石为 0 —— 修复前按 androidDiamond 判档会误拒
    st.diamondShard = 1000;
    st.androidDiamond = 0;
    await expect(
      controller.advancedGacha({ poolId: "p_normal_1", useTkt: GachaType.Diamond, itemId: "" }),
    ).resolves.toBeDefined();

    // 反例：合成玉不足（0）、源石充足（9999）—— 必须拒绝（合成玉消费≠源石）
    st.diamondShard = 0;
    st.androidDiamond = 9999;
    await expect(
      controller.advancedGacha({ poolId: "p_normal_1", useTkt: GachaType.Diamond, itemId: "" }),
    ).rejects.toThrow("资源不足");
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
    vi.spyOn(controller, "_pullOnce").mockResolvedValue({
      charId: "char_001",
      beforeNonHitCnt: 1,
      extras: { from: "NORMAL" },
    } as any);
    await controller.tenAdvancedGacha({ poolId: "p_normal_1", useTkt: GachaType.Diamond, itemList: [] });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [
      [{ id: "4003", type: "DIAMOND_SHD", count: 6000 }],
    ]);
  });

  it("CombineTenTicket 十连应消耗客户端 itemList 且不叠加其他费用", async () => {
    const controller = new GachaController(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    vi.spyOn(controller, "_pullOnce").mockResolvedValue({
      charId: "char_001",
      beforeNonHitCnt: 1,
      extras: { from: "NORMAL" },
    } as any);
    await controller.tenAdvancedGacha({
      poolId: "p_normal_1",
      useTkt: GachaType.CombineTenTicket,
      itemList: [{ id: "4005", count: 10 }],
    });
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "4005", count: 10 }]]);
  });

  describe("保底计数批量落盘（2026-08-10 速度优化）", () => {
    it("十连应只调用 saveBeforeNonHitCnt 一次（原每抽一次 SQLite 全表重写）", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      vi.spyOn(controller, "_pullOnce").mockImplementation(async ({ beforeNonHitCnt }) => ({
        charId: "char_001",
        beforeNonHitCnt: beforeNonHitCnt + 1,
        extras: { from: "NORMAL" },
      }) as any);
      await controller.tenAdvancedGacha({
        poolId: "p_normal_1",
        useTkt: GachaType.Diamond,
        itemList: [],
      });
      expect(saveSpy).toHaveBeenCalledTimes(1);
      // 10 抽全部未中六星 → 最终计数 = 10
      expect(saveSpy).toHaveBeenCalledWith(10000, "NORMAL", 10);
    });

    it("单抽 doAdvancedGacha 仍按次落盘且计数 +1", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      // 强制稀有度 4（非六星）→ 保底计数 +1
      vi.spyOn(controller, "_getRarityRank").mockResolvedValue(4);
      await controller.doAdvancedGacha({ poolId: "p_normal_1", useTkt: 0, itemId: "" });
      expect(saveSpy).toHaveBeenCalledWith(10000, "NORMAL", 1);
    });

    it("六星命中（rank 5）应重置保底计数为 0（修复 rank 恒 0 死值）", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      vi.spyOn(controller, "_getRarityRank").mockResolvedValue(5);
      await controller.doAdvancedGacha({ poolId: "p_normal_1", useTkt: 0, itemId: "" });
      expect(saveSpy).toHaveBeenCalledWith(10000, "NORMAL", 0);
    });

    it("十连中途中六星应重置计数后继续累积（rank 4,4,5 后清零，7 次未中 → 7）", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      const ranks = [4, 4, 5, 4, 4, 4, 4, 4, 4, 4];
      vi.spyOn(controller, "_getRarityRank").mockImplementation(
        () => Promise.resolve(ranks.shift()!),
      );
      await controller.tenAdvancedGacha({
        poolId: "p_normal_1",
        useTkt: GachaType.Diamond,
        itemList: [],
      });
      expect(saveSpy).toHaveBeenCalledTimes(1);
      expect(saveSpy).toHaveBeenCalledWith(10000, "NORMAL", 7);
    });
  });

  describe("五星保底：一次性事件（2026-08-19 修复：原 cnt 少一 → 前 10 抽可能无五星）", () => {
    it("前 10 抽若无五星，第 10 抽强制五星；此后不再触发（一次性）且计数器不回绕", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      // 屏蔽六星（totalPercent 置 0）——否则 per6 恒命中六星，保底分支不可达
      (excelData as any).GachaDetailTable.details["p_normal_1"].availCharInfo.perAvailList[0].totalPercent = 0;
      // 初始化保底：累计抽数从 0 开始（cnt 只增不减，不回绕）
      await mockPlayer.update((draft: any) => {
        draft.gacha.normal["p_normal_1"] = { cnt: 0, maxCnt: 10, rarity: 4, avail: true };
      });
      // 六星判定 Math.random<=per6(0) 恒不命中；randomChoices 加权恒取最末 rank 3
      const rnd = vi.spyOn(Math, "random").mockReturnValue(0.9);
      const ranks: number[] = [];
      for (let i = 0; i < 10; i++) {
        ranks.push(await controller._getRarityRank("p_normal_1", { beforeNonHitCnt: 0 }));
      }
      // 前 9 抽全为低稀有度（<4，非五星），第 10 抽触发一次性保底强制 4（五星）
      expect(ranks.slice(0, 9).every((r) => r < 4)).toBe(true);
      expect(ranks[9]).toBe(4);
      // 计数器只增不减（禁止回绕）：10 抽后 cnt=10
      expect(mockPlayer._playerdata.gacha!.normal["p_normal_1"].cnt).toBe(10);
      // 一次性事件：第 11、第 20 抽（cnt 不再等于 maxCnt）均不再强制五星
      for (let i = 0; i < 10; i++) {
        expect(await controller._getRarityRank("p_normal_1", { beforeNonHitCnt: 0 })).toBe(3);
      }
      expect(mockPlayer._playerdata.gacha!.normal["p_normal_1"].cnt).toBe(20);
      rnd.mockRestore();
    });
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

  describe("LIMITED 池 extraItem 接线（2026-08-10 修复：原 extras 死代码）", () => {
    it("LIMITED 池应透传 { from: LIMITED, extraItem: LMTGS 凭证 } 到 char:get", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await controller.doAdvancedGacha({ poolId: "p_limited_1", useTkt: 0, itemId: "" });
      // emit 调用形如 emit("char:get", [charId, extras, callback])——extras 含 from/extraItem
      const charGetCall = emitSpy.mock.calls.find((c) => c[0] === "char:get");
      expect(charGetCall).toBeDefined();
      // 修复：extraItem 带 type=LMTGS_COIN（消费型入账 consumable）——旧实现缺 type
      // + LMTGSID 缺失时空 id → gainItem 查 ItemTable[""] 警告跳过（凭证从未入账）
      expect(charGetCall![1][1]).toEqual({
        from: "LIMITED",
        extraItem: { id: "LMTGS_COIN_TEST", count: 1, type: "LMTGS_COIN" },
      });
    });

    it("LIMITED 池缺 LMTGSID 时应回退 LMTGS_COIN 凭证（不再空 id 警告跳过）", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      const emitSpy = vi.spyOn(mockTrigger, "emit");
      // p_limited_2 无 LMTGSID → 回退 "LMTGS_COIN"
      await controller.doAdvancedGacha({ poolId: "p_limited_2", useTkt: 0, itemId: "" });
      const charGetCall = emitSpy.mock.calls.find((c) => c[0] === "char:get");
      expect(charGetCall![1][1]).toEqual({
        from: "LIMITED",
        extraItem: { id: "LMTGS_COIN", count: 1, type: "LMTGS_COIN" },
      });
    });

    it("普通池不携带 extraItem", async () => {
      const controller = new GachaController(mockPlayer as any, mockTrigger as any);
      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await controller.doAdvancedGacha({ poolId: "p_normal_1", useTkt: 0, itemId: "" });
      const charGetCall = emitSpy.mock.calls.find((c) => c[0] === "char:get");
      expect(charGetCall![1][1]).toEqual({ from: "NORMAL" });
    });
  });
});
