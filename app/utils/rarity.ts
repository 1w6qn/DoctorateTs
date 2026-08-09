/**
 * 干员稀有度工具
 *
 * CharacterTable.rarity 为字符串枚举 RarityRank（"TIER_1".."TIER_6"），
 * 而 GameDataConst.maxLevel / evolveGoldCost 等表以数值下标索引
 * （TIER_1→0 ... TIER_6→5，即星级-1），公共招募/肉鸽招募也按数值分组。
 * 此前多处直接用 rarity 做数值比较/下标导致 500 与招募失效，统一走此工具。
 */

/**
 * RarityRank 字符串枚举转数值索引（TIER_1→0 ... TIER_6→5）
 * @param rarity - CharacterTable.rarity（"TIER_N"）或已是数值
 * @returns 0~5 的稀有度索引
 */
export function rarityToIndex(rarity: string | number | undefined): number {
  if (typeof rarity === "number") return rarity;
  const m = /^TIER_(\d)$/.exec(String(rarity ?? ""));
  return m ? parseInt(m[1], 10) - 1 : 0;
}

/**
 * 数值稀有度索引转 RarityRank 字符串（0→"TIER_1" ... 5→"TIER_6"）
 * @param index - 0~5 的稀有度索引
 * @returns RarityRank 字符串
 */
export function rarityIndexToString(index: number): string {
  const tier = Math.min(6, Math.max(1, index + 1));
  return `TIER_${tier}`;
}
