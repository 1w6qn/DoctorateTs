import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    CharacterTable: {
      char_001_test1: { profession: "CASTER" },
      char_002_test2: { profession: "WARRIOR" },
      token_100_test: { profession: "TOKEN" },
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

  it("应生成全干员（char_ 前缀）满配结构", async () => {
    await generateMaxedAccount(player);
    const chars = player._playerdata.troop.chars;
    const ids = Object.keys(chars);
    expect(ids.length).toBe(2); // 只含 char_ 前缀干员
    const c = chars["1"];
    expect(c.charId).toBe("char_001_test1");
    expect(c.potentialRank).toBe(5);
    expect(c.evolvePhase).toBe(2);
    expect(c.level).toBe(90);
    expect(c.favorPoint).toBe(25570);
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
