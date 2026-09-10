import { describe, it, expect, vi } from "vitest";

/**
 * 肉鸽局外收藏 → 勋章事件（Round 33）
 *
 * 官服勋章 unlockParam = [主题, 目标数]：
 * - Rlv2CollectRelic「拟造物质编目已持有 N 个收藏品」← collect.relic 中 state ≥ 2 的条目数
 * - Rlv2UnlockBand「解锁 N 个分队」← collect.band 中 state ≥ 1 的条目数
 * 载荷为当前累计值（非增量），模板取 max —— 幂等。
 */
vi.mock("@excel/excel", () => ({
  default: {
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
    RoguelikeTopicTable: { details: {}, modules: {}, consts: {} },
    CharacterTable: {},
    RoguelikeConsts: {},
  },
}));

import excel from "@excel/excel";
import { PlayerDataManager } from "@game/kernel/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";

function makePlayer(collect: any) {
  const pd: any = mockPlayerData({
    pushFlags: { status: 0 } as any,
    rlv2: { outer: { rogue_4: { collect } }, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2.current as any).game = {
    theme: "rogue_4", mode: "NORMAL", modeGrade: 0, predefined: null, start: 1,
  };
  return player;
}

describe("RoguelikeV2Manager.emitOuterProgressionMedals（局外进度 → 勋章）", () => {
  it("按 collect.relic(state≥2) / collect.band(state≥1) 计数并派发（含主题）", async () => {
    const player = makePlayer({
      relic: {
        r1: { state: 2 }, r2: { state: 2 }, r3: { state: 1 }, // state 1 未获得 → 不计
      },
      band: { band_1: { state: 1 }, band_2: { state: 1 }, band_3: { state: 0 } },
      endBook: { ro4_ending_1: { state: 2 }, ro4_ending_2: { state: 2 } },
    });
    const emit = vi.spyOn(player._trigger as any, "emit");
    await (player.rlv2 as any).emitOuterProgressionMedals("rogue_4");
    const relicCall = emit.mock.calls.find((c: any[]) => c[0] === "Rlv2CollectRelic")!;
    const bandCall = emit.mock.calls.find((c: any[]) => c[0] === "Rlv2UnlockBand")!;
    const endingCall = emit.mock.calls.find((c: any[]) => c[0] === "Rlv2EndingCollect")!;
    expect(relicCall[1][0]).toEqual({ theme: "rogue_4", count: 2 });
    expect(bandCall[1][0]).toEqual({ theme: "rogue_4", count: 2 });
    // 结局图鉴条目数（「达成 N 种结局」）
    expect(endingCall[1][0]).toEqual({ theme: "rogue_4", count: 2 });
  });

  it("resolveBpLevel：按官方 milestones 门槛换算源流堆栈等级", () => {
    const player = makePlayer({ relic: {}, band: {} });
    (excel as any).RoguelikeTopicTable.details.rogue_4 = {
      milestones: [
        { level: 1, tokenNum: 0 },
        { level: 2, tokenNum: 100 },
        { level: 65, tokenNum: 19000 },
      ],
    };
    const rlv2 = player.rlv2 as any;
    expect(rlv2.resolveBpLevel("rogue_4", 0)).toBe(1);
    expect(rlv2.resolveBpLevel("rogue_4", 99)).toBe(1);
    expect(rlv2.resolveBpLevel("rogue_4", 100)).toBe(2);
    expect(rlv2.resolveBpLevel("rogue_4", 99999)).toBe(65);
    expect(rlv2.resolveBpLevel("rogue_9", 99999)).toBe(0); // 无该主题 → 0
    delete (excel as any).RoguelikeTopicTable.details.rogue_4;
  });

  it("源流样本累计时派发 Rlv2BpLevel（等级来自 bp.point 换算）", async () => {
    const player = makePlayer({ relic: {}, band: {} });
    (excel as any).RoguelikeTopicTable.details.rogue_4 = {
      milestones: [
        { level: 1, tokenNum: 0 },
        { level: 7, tokenNum: 500 },
      ],
    };
    (player._playerdata.rlv2 as any).outer.rogue_4.bp = { point: 600, reward: {} };
    const emit = vi.spyOn(player._trigger as any, "emit");
    await (player.rlv2 as any).emitOuterProgressionMedals("rogue_4");
    const call = emit.mock.calls.find((c: any[]) => c[0] === "Rlv2BpLevel")!;
    expect(call[1][0]).toEqual({ theme: "rogue_4", level: 7 });
    delete (excel as any).RoguelikeTopicTable.details.rogue_4;
  });

  it("空收藏 / 无该主题 时派发 0（不抛错）", async () => {
    const player = makePlayer({ relic: {}, band: {} });
    const emit = vi.spyOn(player._trigger as any, "emit");
    await (player.rlv2 as any).emitOuterProgressionMedals("rogue_4");
    expect(emit.mock.calls.find((c: any[]) => c[0] === "Rlv2CollectRelic")![1][0].count).toBe(0);
    emit.mockClear();
    await (player.rlv2 as any).emitOuterProgressionMedals("rogue_9");
    expect(emit).not.toHaveBeenCalled();
  });
});
