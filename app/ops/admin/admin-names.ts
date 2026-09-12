/**
 * 管理后台名称解析工具
 *
 * 把裸 ID（物品/干员/皮肤）解析为中文名称用于 CLI/Dashboard 展示；
 * 支持按中文名反查物品 ID（resolveItemRef），并维护常用物品别名表。
 * 纯函数、无副作用（仅依赖 excel 只读表），便于单测；excel 未初始化时优雅降级原样返回。
 */
import excel from "@excel/excel";

/**
 * 常用物品别名表（中文名 → 物品 ID）
 * ID 经 data/excel/item_table.json 逐项核对（注意：合成玉是 4003，5001 是声望）。
 */
export const COMMON_ITEMS: { [key: string]: string } = {
  龙门币: "4001",
  至纯源石: "4002",
  合成玉: "4003",
  高级凭证: "4004",
  资质凭证: "4005",
  采购凭证: "4006",
  演习券: "6001",
  招聘许可: "7001",
  加急许可: "7002",
  寻访凭证: "7003",
  十连寻访凭证: "7004",
  家具零件: "3401",
};

/** 物品 ID → 中文名（未知原样返回 ID） */
export function itemName(id: string): string {
  const def = excel.getItem(id);
  return def?.name || id;
}

/** 干员 ID → 中文名（未知原样返回 ID） */
export function charName(charId: string): string {
  const def = excel.charData(charId);
  return def?.name || charId;
}

/** 皮肤 ID → 皮肤名（无 displaySkin 返回 null，由调用方回退 charId#N） */
export function skinName(skinId: string): string | null {
  return excel.SkinTable?.charSkins?.[skinId]?.displaySkin?.skinName ?? null;
}

/**
 * 把用户输入解析为物品 ID：
 * - 纯数字 → 原样返回
 * - 命中 COMMON_ITEMS 别名 → 对应 ID
 * - ItemTable 中精确匹配中文名 → 该 ID
 * - 其余 → null（调用方据此报错）
 */
export function resolveItemRef(ref: string): string | null {
  const id = ref.trim();
  if (/^\d+$/.test(id)) return id;
  if (COMMON_ITEMS[id]) return COMMON_ITEMS[id];
  const items = excel.ItemTable?.items ?? {};
  for (const [itemId, info] of Object.entries(items)) {
    if (info?.name === id) return itemId;
  }
  return null;
}

/**
 * 把干员 ID/中文名解析为干员 ID：
 * - 已存在于 CharacterTable → 原样返回
 * - 精确匹配干员中文名 → 该 charId
 * - 其余 → 原样返回（由调用方校验/展示错误）
 */
export function resolveCharRef(ref: string): string {
  const id = ref.trim();
  if (excel.charData(id)) return id;
  const table = excel.CharacterTable;
  if (table) {
    for (const [charId, info] of Object.entries(table)) {
      if (info?.name === id) return charId;
    }
  }
  return id;
}

/**
 * 干员星级（0-5）：character_table 的 rarity 为 "TIER_5" 字符串（部分版本数字），统一归一为数字
 */
export function charRarity(charId: string): number {
  const info = excel.charData(charId);
  const r = info?.rarity;
  if (typeof r === "number") return r;
  if (typeof r === "string") {
    const m = /(\d+)$/.exec(r);
    if (m) return Number(m[1]);
  }
  return 0;
}
