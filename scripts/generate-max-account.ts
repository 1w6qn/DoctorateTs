/**
 * 满配账号生成器（单例模式）
 *
 * 基于当前 excel 数据生成满配账号：全干员（char_ 前缀）+ 全物品 + 大额资源。
 * "随版本更新"：生成时标记 resVersion，启动时版本变化则重新生成（新干员/新物品加入）。
 *
 * 参考：opendoctoratepy tools/生成背包物品.py（物品分类处理）
 */
import excel from "@excel/excel";
import config from "../app/config";
import { PlayerDataManager } from "../app/game/manager/PlayerDataManager";

/** 满配干员结构（满潜/满级/精二/满信赖/满技能） */
export function buildMaxedChar(instId: number, charId: string): Record<string, unknown> {
  return {
    instId,
    charId,
    favorPoint: 25570,
    potentialRank: 5,
    mainSkillLvl: 10,
    skin: null,
    level: 90,
    exp: 0,
    evolvePhase: 2,
    defaultSkillIndex: -1,
    gainTime: Math.floor(Date.now() / 1000),
    skills: [],
    currentTmpl: null,
    tmpl: {},
  };
}

/**
 * 生成满配账号（覆盖玩家数据——全干员/全物品/大额资源）
 * @param player - 目标玩家（单例模式为 uid=1）
 */
export async function generateMaxedAccount(player: PlayerDataManager): Promise<void> {
  const data = player._playerdata as any;

  // 1. 全干员（char_ 前缀——玩家可用干员）
  const charIds = Object.keys(excel.CharacterTable).filter((k) =>
    k.startsWith("char_"),
  );
  data.troop = data.troop || {};
  data.troop.chars = {};
  charIds.forEach((charId, i) => {
    data.troop.chars[String(i + 1)] = buildMaxedChar(i + 1, charId);
  });

  // 2. 全物品（参考 opendoctoratepy 生成背包物品.py）
  data.inventory = {};
  data.consumable = {};
  const items = (excel.ItemTable as any)?.items || {};
  for (const [itemId, info] of Object.entries<any>(items)) {
    const classify = info?.classifyType;
    const sortId = info?.sortId ?? 0;
    if (sortId <= 0) continue;
    if (classify === "CONSUME") {
      data.consumable[itemId] = { "0": { ts: -1, count: 999 } };
    } else if (classify === "NORMAL" || classify === "MATERIAL") {
      data.inventory[itemId] = 999;
    }
  }

  // 3. 大额资源/状态
  data.status = data.status || {};
  data.status.gold = 99999999;
  data.status.androidDiamond = 99999;
  data.status.iosDiamond = 99999;
  data.status.level = 120;
  data.status.exp = 0;
  if (data.status.maxAp) data.status.ap = data.status.maxAp;

  // 4. 版本标记（启动时比较——版本变化重新生成）
  data.status.maxAccountResVersion = config.version.resVersion;
}
