import { describe, it, expect, vi, beforeEach } from "vitest";

const excelMock = vi.hoisted(() => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    CharacterTable: {
      char_001_test1: {
        profession: "CASTER",
        skills: [
          { skillId: "skchr_test1_1", overridePrefabKey: null, overrideTokenKey: null },
          { skillId: null, overridePrefabKey: null, overrideTokenKey: null },
        ],
        phases: [{ maxLevel: 30 }, { maxLevel: 55 }, { maxLevel: 90 }],
      },
      char_002_test2: { profession: "WARRIOR" },
      token_100_test: { profession: "TOKEN" },
    },
    UniequipTable: {
      charEquip: {
        char_001_test1: ["uniequip_001_test1", "uniequip_002_test1"],
      },
    },
    ItemTable: {
      items: {
        "2001": { classifyType: "MATERIAL", sortId: 1 },
        "2002": { classifyType: "NORMAL", sortId: 2 },
        "3001": { classifyType: "CONSUME", sortId: 1 },
        "4001": { classifyType: "FURN", sortId: 1 },
        "5001": { classifyType: "MATERIAL", sortId: 0 },
      },
    },
  },
}));
vi.mock("@excel/excel", () => excelMock);
vi.mock("@core/config/index", () => ({
  default: { version: { resVersion: "26-08-03-23-34-20_test", clientVersion: "2.7.61" } },
}));
vi.mock("@utils/file", () => ({
  readJson: vi.fn(),
}));

import { generateMaxedAccount } from "../../../scripts/generate-max-account";
import { readJson } from "@utils/file";
import { mockPlayerData } from "../../helpers/mockPlayerData";

/** player_data.json 基底样例（官服满级号结构——结构完整，直接覆盖） */
const basePlayerData = {
  troop: {
    chars: {
      "1": {
        instId: 1,
        charId: "char_001_test1",
        favorPoint: 25570,
        potentialRank: 5,
        mainSkillLvl: 7,
        skin: null,
        level: 120,
        exp: 0,
        evolvePhase: 2,
        defaultSkillIndex: -1,
        gainTime: 1700000000,
        skills: [],
        voiceLan: "CN_MANDARIN",
        currentEquip: null,
        equip: {},
        starMark: 0,
      },
    },
  },
  inventory: { "2001": 999 },
  consumable: { "3001": { "0": { ts: -1, count: 999 } } },
  status: { uid: 1, level: 120, gold: 0 },
};

describe("generateMaxedAccount 满配账号生成（single 唯一实例）", () => {
  let player: any;

  beforeEach(() => {
    vi.clearAllMocks();
    (vi.mocked(readJson) as any).mockResolvedValue(JSON.parse(JSON.stringify(basePlayerData)));
    player = mockPlayerData({
      status: { uid: 1, maxAp: 135, ap: 10, gold: 100 } as any,
      troop: { chars: {} },
      inventory: {},
      consumable: {},
    });
  });

  it("应以 player_data.json 刷新内容字段并保留进度字段（合并式刷新，不覆盖进度）", async () => {
    player = mockPlayerData({
      status: { uid: 1, maxAp: 135, ap: 10, gold: 100, level: 100 } as any,
      troop: { chars: { "1": { charId: "char_OLD", instId: 1 } } },
      inventory: { "9001": 5 },
      consumable: {},
      mission: { missions: { DAILY: { "1": { state: 2 } } } }, // 进度字段
      building: { roomSlots: { "1": { charInstId: 1 } } }, // 进度字段
    });
    await generateMaxedAccount(player);
    const data = player._playerdata;
    expect(readJson).toHaveBeenCalledWith("./player_data.json");
    // 内容字段以 base 刷新（新版本干员/物品——官服结构直接生效）
    expect(data.troop.chars["1"].charId).toBe("char_001_test1");
    expect(data.troop.chars["1"].voiceLan).toBe("CN_MANDARIN");
    expect(data.troop.chars["1"].starMark).toBe(0);
    expect(data.inventory["2001"]).toBe(999);
    // 进度字段保留（版本更新不再清空任务/基建等玩家进度）
    expect(data.mission).toEqual({ missions: { DAILY: { "1": { state: 2 } } } });
    expect(data.building).toEqual({ roomSlots: { "1": { charInstId: 1 } } });
    // 保持 uid + 版本标记 + 满配资源（独立于保留的进度字段）
    expect(data.status.uid).toBe(1);
    expect(data.status.maxAccountResVersion).toBe("26-08-03-23-34-20_test");
    expect(data.status.gold).toBe(99999999);
    expect(data.status.level).toBe(120);
    expect(data.status.ap).toBe(135);
  });

  it("player_data.json 缺失时回退 excel 逐干员生成（buildMaxedChar 结构）", async () => {
    (vi.mocked(readJson) as any).mockResolvedValue(null);
    await generateMaxedAccount(player);
    const chars = player._playerdata.troop.chars;
    expect(Object.keys(chars).length).toBe(2); // 只含 char_ 前缀干员
    const c = chars["1"];
    expect(c.charId).toBe("char_001_test1");
    expect(c.potentialRank).toBe(5);
    expect(c.level).toBe(90); // phases[2].maxLevel
    expect(c.skills).toEqual([
      { skillId: "skchr_test1_1", unlock: 1, state: 0, specializeLevel: 3, completeUpgradeTime: -1 },
    ]);
    expect(c.currentEquip).toBe("uniequip_001_test1");
    expect(c.starMark).toBe(0);
    expect(c.currentTmpl).toBeUndefined();
    expect(player._playerdata.status.maxAccountResVersion).toBe("26-08-03-23-34-20_test");
  });

  it("回退生成应全物品（CONSUME→consumable / NORMAL+MATERIAL→inventory 999）", async () => {
    (vi.mocked(readJson) as any).mockResolvedValue(null);
    await generateMaxedAccount(player);
    expect(player._playerdata.consumable["3001"]).toEqual({ "0": { ts: -1, count: 999 } });
    expect(player._playerdata.inventory["2001"]).toBe(999);
    expect(player._playerdata.inventory["4001"]).toBeUndefined();
  });
});
