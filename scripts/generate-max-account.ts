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

/** 从 excel 干员数据生成满配技能列表（满解锁 + 满专精） */
export function buildMaxedSkills(charData: any): { skillId: string; unlock: number; state: number; specializeLevel: number; completeUpgradeTime: number }[] {
  return ((charData?.skills as any[]) || [])
    .filter((s) => s?.skillId)
    .map((s) => ({
      skillId: s.skillId,
      unlock: 1,
      state: 0,
      specializeLevel: 3,
      completeUpgradeTime: -1,
    }));
}

/** 从 excel 装备表生成满配装备字典（满级满解锁） */
export function buildMaxedEquip(charId: string): { ids: string[]; equip: Record<string, unknown> } {
  const ids: string[] = (excel as any).UniequipTable?.charEquip?.[charId] || [];
  const equip: Record<string, unknown> = {};
  for (const id of ids) equip[id] = { hide: 0, locked: 0, level: 3 };
  return { ids, equip };
}

/**
 * 满配干员结构（满潜/满级/精二/满信赖/满技能）
 * 参考 data：player_data.json（官服 453 干员抓包——通用结构含 skills/equip/voiceLan/starMark，无 tmpl；
 * 唯一例外 char_002_amiya 带 currentTmpl/tmpl 三形态）。
 */
export function buildMaxedChar(instId: number, charId: string): Record<string, unknown> {
  const charData = (excel.CharacterTable as any)[charId];
  const skills = buildMaxedSkills(charData);
  const { ids: equipIds, equip } = buildMaxedEquip(charId);
  // 精二满级：最高阶段 maxLevel（无 phases 数据回退 90）
  const phases = charData?.phases as any[] | undefined;
  const maxEvolve = phases && phases.length > 0 ? phases.length - 1 : 2;
  const maxLevel = phases?.[maxEvolve]?.maxLevel ?? 90;
  const base = {
    instId,
    charId,
    favorPoint: 25570,
    potentialRank: 5,
    mainSkillLvl: 7, // 技能 7 级满（专精等级在 skills[].specializeLevel）
    skin: null,
    level: maxLevel,
    exp: 0,
    evolvePhase: maxEvolve,
    defaultSkillIndex: -1,
    gainTime: Math.floor(Date.now() / 1000),
    skills,
    currentEquip: equipIds[0] || null,
    equip,
    voiceLan: "CN_MANDARIN",
    starMark: 0,
  };
  // 阿米娅特殊：多形态模板（升变——客户端按 tmpl 渲染形态，缺字段会异常）
  if (charId === "char_002_amiya") {
    const tmpl: Record<string, unknown> = {};
    for (const form of ["char_002_amiya", "char_1001_amiya2", "char_1037_amiya3"]) {
      const tChar = (excel.CharacterTable as any)[form];
      const tSkills = buildMaxedSkills(tChar);
      const { ids: tEquipIds, equip: tEquip } = buildMaxedEquip(form);
      tmpl[form] = {
        skinId: null,
        defaultSkillIndex: tSkills.length > 0 ? 0 : -1,
        skills: tSkills,
        currentEquip: tEquipIds[0] || null,
        equip: tEquip,
      };
    }
    return { ...base, currentTmpl: "char_002_amiya", tmpl };
  }
  return base;
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
