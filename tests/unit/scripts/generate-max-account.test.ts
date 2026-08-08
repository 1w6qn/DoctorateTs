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

import { generateMaxedAccount } from "../../../scripts/generate-max-account";
import { mockPlayerData } from "../../helpers/mockPlayerData";

describe("generateMaxedAccount 满配账号生成", () => {
  let player: any;

  beforeEach(() => {
    player = mockPlayerData({
      status: { uid: 1, maxAp: 135, ap: 10, gold: 100 } as any,
      troop: { chars: {} },
      inventory: {},
      consumable: {},
    });
  });

  it("应生成全干员（char_ 前缀）满配结构（参考 player_data.json：skills/equip/voiceLan/starMark 齐全，无 tmpl）", async () => {
    await generateMaxedAccount(player);
    const chars = player._playerdata.troop.chars;
    const ids = Object.keys(chars);
    expect(ids.length).toBe(2); // 只含 char_ 前缀干员
    const c = chars["1"];
    expect(c.charId).toBe("char_001_test1");
    expect(c.potentialRank).toBe(5);
    expect(c.evolvePhase).toBe(2);
    expect(c.level).toBe(90); // phases[2].maxLevel
    expect(c.favorPoint).toBe(25570);
    // 技能：excel skills 满解锁满专精（skillId 为 null 的过滤掉）
    expect(c.skills).toEqual([
      {
        skillId: "skchr_test1_1",
        unlock: 1,
        state: 0,
        specializeLevel: 3,
        completeUpgradeTime: -1,
      },
    ]);
    // 装备：charEquip 全解锁满级
    expect(c.equip["uniequip_001_test1"]).toEqual({ hide: 0, locked: 0, level: 3 });
    expect(c.equip["uniequip_002_test1"]).toEqual({ hide: 0, locked: 0, level: 3 });
    expect(c.currentEquip).toBe("uniequip_001_test1");
    expect(c.voiceLan).toBe("CN_MANDARIN");
    expect(c.starMark).toBe(0); // player_data.json 官服结构必有字段
    // 无 tmpl/currentTmpl 字段（客户端干员列表按此判断，null 会导致渲染卡死）
    expect(c.currentTmpl).toBeUndefined();
    expect(c.tmpl).toBeUndefined();
    // 无技能/装备干员：skills 空、currentEquip null
    const c2 = chars["2"];
    expect(c2.skills).toEqual([]);
    expect(c2.equip).toEqual({});
    expect(c2.currentEquip).toBeNull();
    expect(c2.starMark).toBe(0);
    expect(c2.level).toBe(90); // 无 phases 回退
  });

  it("阿米娅（char_002_amiya）应生成三形态 tmpl（对齐 player_data.json 唯一带 tmpl 干员）", async () => {
    // 覆盖 excel mock：加入阿米娅本体 + 两个异格形态
    const ct = excelMock.default.CharacterTable as any;
    ct.char_002_amiya = {
      profession: "CASTER",
      skills: [{ skillId: "skchr_amiya_1", overridePrefabKey: null, overrideTokenKey: null }],
      phases: [{ maxLevel: 30 }, { maxLevel: 55 }, { maxLevel: 90 }],
    };
    ct.char_1001_amiya2 = {
      skills: [{ skillId: "skchr_amiya2_1", overridePrefabKey: null, overrideTokenKey: null }],
    };
    ct.char_1037_amiya3 = {
      skills: [{ skillId: "skchr_amiya3_1", overridePrefabKey: null, overrideTokenKey: null }],
    };
    const ce = excelMock.default.UniequipTable.charEquip as any;
    ce.char_002_amiya = ["uniequip_001_amiya"];
    ce.char_1001_amiya2 = [];
    ce.char_1037_amiya3 = [];

    const { buildMaxedChar } = await import("../../../scripts/generate-max-account");
    const ami = buildMaxedChar(1, "char_002_amiya") as any;
    expect(ami.currentTmpl).toBe("char_002_amiya");
    expect(Object.keys(ami.tmpl)).toEqual(["char_002_amiya", "char_1001_amiya2", "char_1037_amiya3"]);
    expect(ami.tmpl["char_002_amiya"].skills[0].skillId).toBe("skchr_amiya_1");
    expect(ami.tmpl["char_002_amiya"].skills[0].specializeLevel).toBe(3);
    expect(ami.tmpl["char_002_amiya"].currentEquip).toBe("uniequip_001_amiya");
    expect(ami.tmpl["char_1001_amiya2"].skills[0].skillId).toBe("skchr_amiya2_1");
  });

  it("应生成全物品（CONSUME→consumable / NORMAL+MATERIAL→inventory 999）", async () => {
    await generateMaxedAccount(player);
    expect(player._playerdata.consumable["3001"]).toEqual({ "0": { ts: -1, count: 999 } });
    expect(player._playerdata.inventory["2001"]).toBe(999);
    expect(player._playerdata.inventory["2002"]).toBe(999);
    // FURN 与 sortId=0 的物品不处理
    expect(player._playerdata.inventory["4001"]).toBeUndefined();
    expect(player._playerdata.inventory["5001"]).toBeUndefined();
  });

  it("应设置大额资源并标记当前版本（随版本刷新）", async () => {
    await generateMaxedAccount(player);
    expect(player._playerdata.status.gold).toBe(99999999);
    expect(player._playerdata.status.androidDiamond).toBe(99999);
    expect(player._playerdata.status.ap).toBe(135); // maxAp
    expect(player._playerdata.status.maxAccountResVersion).toBe("26-08-03-23-34-20_test");
  });
});
