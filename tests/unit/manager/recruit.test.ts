import { describe, it, expect, vi, beforeEach } from "vitest";

// 公招数据 mock（参考 data/excel/gacha_table.json 结构）
const excelMock = vi.hoisted(() => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    GachaTable: {
      gachaTags: [
        { tagGroup: 1, tagId: 1, tagName: "近卫干员" },
        { tagGroup: 2, tagId: 2, tagName: "狙击干员" },
        { tagGroup: 3, tagId: 3, tagName: "重装干员" },
        { tagGroup: 4, tagId: 4, tagName: "医疗干员" },
        { tagGroup: 5, tagId: 5, tagName: "辅助干员" },
        { tagGroup: 6, tagId: 6, tagName: "术师干员" },
        { tagGroup: 7, tagId: 7, tagName: "特种干员" },
        { tagGroup: 8, tagId: 8, tagName: "先锋干员" },
        { tagGroup: 9, tagId: 9, tagName: "近战位" },
        { tagGroup: 10, tagId: 10, tagName: "远程位" },
        { tagGroup: 11, tagId: 11, tagName: "高级资深干员" },
        { tagGroup: 12, tagId: 12, tagName: "资深干员" },
        { tagGroup: 13, tagId: 13, tagName: "控场" },
        { tagGroup: 14, tagId: 14, tagName: "爆发" },
        { tagGroup: 15, tagId: 15, tagName: "输出" },
        { tagGroup: 16, tagId: 16, tagName: "治疗" },
        { tagGroup: 17, tagId: 17, tagName: "支援" },
        { tagGroup: 18, tagId: 18, tagName: "费用回复" },
        { tagGroup: 19, tagId: 19, tagName: "生存" },
        { tagGroup: 20, tagId: 20, tagName: "防护" },
        { tagGroup: 21, tagId: 21, tagName: "减速" },
        { tagGroup: 22, tagId: 22, tagName: "削弱" },
        { tagGroup: 23, tagId: 23, tagName: "位移" },
        { tagGroup: 24, tagId: 24, tagName: "召唤" },
        { tagGroup: 25, tagId: 25, tagName: "快速复活" },
        { tagGroup: 26, tagId: 26, tagName: "新手" },
        { tagGroup: 27, tagId: 27, tagName: "输出干员" },
        { tagGroup: 28, tagId: 28, tagName: "元素" },
        { tagGroup: 29, tagId: 29, tagName: "支援机械" },
        { tagGroup: 1012, tagId: 1012, tagName: "男性干员" },
        { tagGroup: 1013, tagId: 1013, tagName: "女性干员" },
      ],
      recruitRarityTable: {
        "230": { rarityStart: 0, rarityEnd: 3 },
        "460": { rarityStart: 2, rarityEnd: 4 },
        "540": { rarityStart: 2, rarityEnd: 4 },
      },
      specialTagRarityTable: [
        { key: 11, value: [5] },
        { key: 14, value: [4] },
      ],
      recruitDetail:
        "★\\n1星A/1星B\n-★★\\n2星A\n-★★★\\n3星A\n-★★★★\\n4星A\n-★★★★★\\n5星A\n-★★★★★★\\n6星A",
    },
    CharacterTable: {
      char_001: { name: "1星A", rarity: "TIER_1", position: "MELEE", profession: "PIONEER", tagList: ["近战位", "费用回复"] },
      char_002: { name: "1星B", rarity: "TIER_1", position: "MELEE", profession: "PIONEER", tagList: ["近战位"] },
      char_003: { name: "2星A", rarity: "TIER_2", position: "MELEE", profession: "PIONEER", tagList: ["近战位"] },
      char_004: { name: "3星A", rarity: "TIER_3", position: "MELEE", profession: "WARRIOR", tagList: ["近卫干员", "输出"] },
      char_005: { name: "4星A", rarity: "TIER_4", position: "RANGED", profession: "SNIPER", tagList: ["狙击干员", "输出"] },
      char_006: { name: "5星A", rarity: "TIER_5", position: "RANGED", profession: "SUPPORT", tagList: ["辅助干员"] },
      char_007: { name: "6星A", rarity: "TIER_6", position: "MELEE", profession: "WARRIOR", tagList: ["近卫干员", "输出"] },
      // tagList 缺失（undefined）——修复前 generateRecruitableData 崩溃 500 的干员
      char_008: { name: "无标签干员", rarity: "TIER_6", position: "MELEE", profession: "WARRIOR" },
    },
  },
}));

vi.mock("@excel/excel", () => excelMock);

// 控制随机性：randomInt=1（选 1 个标签）、randomSample 取前 n 个、randomChoice 取第一个
vi.mock("@utils/random", () => ({
  randomInt: vi.fn(() => 1),
  randomSample: vi.fn((arr: any[], n: number) => arr.slice(0, n)),
  randomChoice: vi.fn((arr: any[]) => arr[0]),
  randomChoices: vi.fn((a: any[], _w: any[], n: number) => Array(n).fill(a[0])),
}));

vi.mock("@utils/time", () => ({
  now: () => 1234567890,
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { RecruitManager } from "@game/service/player/recruit";

describe("RecruitManager sync", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      recruit: {
        normal: {
          slots: {
            "0": { state: 2, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: 1000, durationInSec: 32400, maxFinishTs: 2000, realFinishTs: 1000 },
            "1": { state: 2, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: 2000, durationInSec: 32400, maxFinishTs: 1234568000, realFinishTs: 1234568000 },
            "2": { state: 1, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: -1, durationInSec: -1, maxFinishTs: -1, realFinishTs: -1 },
          },
        },
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

  it("sync 应将已到期的招募槽位标记为可领取（state=3）", async () => {
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    await manager.sync();
    const slots = mockPlayer._playerdata.recruit!.normal.slots;
    // 槽位 0：realFinishTs=1000 <= now，应变为 3
    expect(slots["0"].state).toBe(3);
    // 槽位 1：realFinishTs 未到期，保持 2
    expect(slots["1"].state).toBe(2);
    // 槽位 2：空闲，保持 1
    expect(slots["2"].state).toBe(1);
  });
});

describe("RecruitManager 核心方法", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockPlayer = mockPlayerData({
      recruit: {
        normal: {
          slots: {
            "0": { state: 1, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: -1, durationInSec: -1, maxFinishTs: -1, realFinishTs: -1 },
          },
        },
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

  it("refreshTags 应刷新槽位标签", async () => {
    const { RecruitTools } = await import("@game/service/player/recruit");
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([2, 4, 6, 8, 10] as any);
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    await manager.refreshTags({ slotId: 0 });
    expect(mockPlayer._playerdata.recruit!.normal.slots["0"].tags).toEqual([2, 4, 6, 8, 10]);
  });

  it("cancel 应重置槽位状态", async () => {
    const { RecruitTools } = await import("@game/service/player/recruit");
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([9, 9, 9, 9, 9] as any);
    mockPlayer._playerdata.recruit!.normal.slots["0"] = {
      state: 2, tags: [], selectTags: [{ tagId: 1, pick: 1 }], startTs: 100, durationInSec: 32400, maxFinishTs: 200, realFinishTs: 200,
    } as any;
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    await manager.cancel({ slotId: 0 });
    const slot = mockPlayer._playerdata.recruit!.normal.slots["0"];
    expect(slot.state).toBe(1);
    expect(slot.selectTags).toEqual([]);
    expect(slot.realFinishTs).toBe(-1);
    expect(slot.tags).toEqual([9, 9, 9, 9, 9]);
  });

  it("normalGacha 应开始招募并消耗招募券", async () => {
    const { RecruitTools } = await import("@game/service/player/recruit");
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([1, 2, 3, 4, 5] as any);
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    await manager.normalGacha({ slotId: 0, tagList: [1, 3], specialTagId: 0, duration: 32400 });
    const slot = mockPlayer._playerdata.recruit!.normal.slots["0"];
    expect(slot.state).toBe(2);
    expect(slot.selectTags).toEqual([{ tagId: 1, pick: 1 }, { tagId: 3, pick: 1 }]);
    expect(slot.maxFinishTs).toBe(1234567890 + 32400);
    expect(emitSpy).toHaveBeenCalledWith("items:use", [[{ id: "7001", count: 1, type: "TKT_RECRUIT" }]]);
  });

  it("finish 应结算招募并出干员", async () => {
    const { RecruitTools } = await import("@game/service/player/recruit");
    vi.spyOn(RecruitTools, "generateValidTags").mockResolvedValue(["char_001", [1]] as any);
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([1, 2, 3, 4, 5] as any);
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    // 准备进行中槽位
    mockPlayer._playerdata.recruit!.normal.slots["0"] = {
      state: 2, tags: [1, 2, 3, 4, 5], selectTags: [{ tagId: 1, pick: 1 }], startTs: 100, durationInSec: 32400, maxFinishTs: 200, realFinishTs: 200,
    } as any;
    let captured: any;
    mockTrigger.on("char:get", (([charId, from, cb]: any) => { captured = { charId, from }; cb?.({ charId }); }) as any);
    const result = await manager.finish({ slotId: 0 });
    expect(captured.charId).toBe("char_001");
    expect(result).toBeDefined();
  });

  it("boost 应立即完成招募", async () => {
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    mockPlayer._playerdata.recruit!.normal.slots["0"] = {
      state: 2, tags: [1, 2, 3, 4, 5], selectTags: [], startTs: 100, durationInSec: 32400, maxFinishTs: 9999999999, realFinishTs: 9999999999,
    } as any;
    const emitSpy = vi.spyOn(mockTrigger, "emit");
    await manager.boost({ slotId: 0, buy: 0 });
    expect(mockPlayer._playerdata.recruit!.normal.slots["0"].realFinishTs).toBe(1234567890);
    expect(emitSpy).toHaveBeenCalledWith("BoostNormalGacha", []);
  });
});

describe("RecruitTools 数据驱动公招逻辑（参考 ArkGachaService gacha_table.json）", () => {
  it("generateRecruitableData 不应因 tagList undefined 崩溃（修复 500）", async () => {
    const { RecruitTools } = await import("@game/service/player/recruit");
    // char_008 的 tagList 为 undefined——修复前 line 331 value.tagList.map 崩溃
    const [charsList, charData] = await RecruitTools.generateRecruitableData();
    expect(Object.keys(charData).length).toBeGreaterThan(0);
    // 6 星干员带高级资深标签(11)、5 星带资深(14)
    expect(charData["char_007"].tags).toContain(11);
    expect(charData["char_006"].tags).toContain(14);
    // 稀有度为数字索引（修复前存字符串导致与 charRange 比较恒 false）
    expect(charData["char_007"].rarity).toBe(5);
    expect(charData["char_005"].rarity).toBe(3);
    // 按稀有度分组
    expect(charsList[5]).toContain("char_007");
  });

  it("9 小时 + 高级资深干员(11) 必出 6 星（specialTagRarityTable 强制稀有度）", async () => {
    const { RecruitTools } = await import("@game/service/player/recruit");
    const [charId, filterTags] = await RecruitTools.generateValidTags(32400, [11, 1]);
    // selectedTags = [11]（randomSample 取前 1）；charRange=[5,5] → 只有 6 星匹配
    expect(charId).toBe("char_007");
    // 标签 11 命中干员 → 不进入 filterTags（pick=1）
    expect(filterTags).not.toContain(11);
  });

  it("3:50 短时招募稀有度范围由 recruitRarityTable[230] 决定（1-4 星）", async () => {
    const { RecruitTools } = await import("@game/service/player/recruit");
    const [charId] = await RecruitTools.generateValidTags(13800, [1, 2, 3]);
    // selectedTags = [1]；charRange=[0,3] → 结果干员稀有度索引 ≤ 3
    const charData = (await RecruitTools.generateRecruitableData())[1];
    expect(charData[charId].rarity).toBeLessThanOrEqual(3);
  });

  it("9 小时无特殊标签 → 基础范围 [2,4]（3-5 星）", async () => {
    const { RecruitTools } = await import("@game/service/player/recruit");
    const [charId] = await RecruitTools.generateValidTags(32400, [1]);
    const charData = (await RecruitTools.generateRecruitableData())[1];
    const r = charData[charId].rarity;
    expect(r).toBeGreaterThanOrEqual(2);
    expect(r).toBeLessThanOrEqual(4);
  });
});
