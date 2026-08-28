import { describe, it, expect, vi } from "vitest";
import {
  itemName,
  charName,
  charRarity,
  skinName,
  resolveItemRef,
  resolveCharRef,
  COMMON_ITEMS,
} from "@ops/admin/admin-names";

vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    ItemTable: {
      items: {
        "4001": { name: "龙门币" },
        "4003": { name: "合成玉" },
      },
    },
    CharacterTable: {
      char_002_amiya: { name: "阿米娅", rarity: "TIER_5" },
      char_285_medic2: { name: "Lancet-2", rarity: "TIER_1" },
      char_100_akafuyu: { name: "赤冬", rarity: 3 },
    },
    SkinTable: {
      charSkins: {
        "char_002_amiya#2": { charId: "char_002_amiya", displaySkin: { skinName: "开初" } },
      },
    },
  },
}));

describe("admin-names 名称解析", () => {
  it("itemName 应返回物品中文名，未知原样返回 ID", () => {
    expect(itemName("4001")).toBe("龙门币");
    expect(itemName("no_such")).toBe("no_such");
  });

  it("charName 应返回干员中文名，未知原样返回 ID", () => {
    expect(charName("char_002_amiya")).toBe("阿米娅");
    expect(charName("char_999")).toBe("char_999");
  });

  it("skinName 应返回皮肤名，无 displaySkin 返回 null", () => {
    expect(skinName("char_002_amiya#2")).toBe("开初");
    expect(skinName("char_999#1")).toBeNull();
  });
});

describe("admin-names resolveItemRef", () => {
  it("纯数字应原样返回", () => {
    expect(resolveItemRef("4001")).toBe("4001");
    expect(resolveItemRef(" 4001 ")).toBe("4001");
  });

  it("别名应解析为物品 ID", () => {
    expect(resolveItemRef("合成玉")).toBe("4003");
  });

  it("常用物品别名表应包含核心资源", () => {
    expect(COMMON_ITEMS["龙门币"]).toBe("4001");
    expect(COMMON_ITEMS["合成玉"]).toBe("4003");
    expect(COMMON_ITEMS["至纯源石"]).toBe("4002");
    expect(COMMON_ITEMS["寻访凭证"]).toBe("7003");
  });

  it("未知输入应返回 null", () => {
    expect(resolveItemRef("不存在的东西")).toBeNull();
  });
});

describe("admin-names charRarity", () => {
  it("TIER_5 字符串应归一为 5", () => {
    expect(charRarity("char_002_amiya")).toBe(5);
  });

  it("TIER_1 应归一为 1", () => {
    expect(charRarity("char_285_medic2")).toBe(1);
  });

  it("数字 rarity 应原样返回", () => {
    expect(charRarity("char_100_akafuyu")).toBe(3);
  });

  it("未知干员应返回 0", () => {
    expect(charRarity("char_999")).toBe(0);
  });
});

describe("admin-names resolveCharRef", () => {
  it("干员 ID 应原样返回", () => {
    expect(resolveCharRef("char_002_amiya")).toBe("char_002_amiya");
  });

  it("中文名应解析为干员 ID", () => {
    expect(resolveCharRef("阿米娅")).toBe("char_002_amiya");
  });

  it("未知输入应原样返回", () => {
    expect(resolveCharRef("不存在的人")).toBe("不存在的人");
  });
});
