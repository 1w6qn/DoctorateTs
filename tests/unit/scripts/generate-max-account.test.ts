import { describe, it, expect, vi, beforeEach } from "vitest";

const excelMock = vi.hoisted(() => ({
  default: {
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
vi.mock("../../../app/config", () => ({
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

  it("应以 player_data.json 为基底覆盖玩家数据并标记版本（不逐字段 excel 生成）", async () => {
    await generateMaxedAccount(player);
    const data = player._playerdata;
    expect(readJson).toHaveBeenCalledWith("./player_data.json");
    // 基底数据直接生效（官服结构）
    expect(data.troop.chars["1"].charId).toBe("char_001_test1");
    expect(data.troop.chars["1"].voiceLan).toBe("CN_MANDARIN");
    expect(data.troop.chars["1"].starMark).toBe(0);
    expect(data.inventory["2001"]).toBe(999);
    // 保持 uid + 版本标记
    expect(data.status.uid).toBe(1);
    expect(data.status.maxAccountResVersion).toBe("26-08-03-23-34-20_test");
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
