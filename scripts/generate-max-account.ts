/**
 * 满配账号生成器（单例模式）
 *
 * 基于当前 excel 数据生成满配账号：全干员（char_ 前缀）+ 全物品 + 大额资源。
 * "随版本更新"：生成时标记 resVersion，启动时版本变化则重新生成（新干员/新物品加入）。
 *
 * 参考：opendoctoratepy tools/生成背包物品.py（物品分类处理）
 *
 * 注意：buildMaxedSkills / buildMaxedEquip 已迁至 app/game/maxout.ts（供管理后台复用），
 * 此处 re-export 保持公共 API 不变。
 */
import excel from "@excel/excel";
import config from "@core/config/index";
import { readJson } from "@utils/file";
import { PlayerDataManager } from "../app/game/service/PlayerDataManager";
import {
  buildMaxedSkills,
  buildMaxedEquip,
} from "../app/game/domain/util/maxout";

export { buildMaxedSkills, buildMaxedEquip } from "../app/game/domain/util/maxout";

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
 * 生成满配账号（合并式刷新——保留玩家进度）
 *
 * single 模式唯一实例：以 player_data.json（官服满级号抓包——uid=1/453 干员/完整模块结构）为基底，
 * 不再逐字段 excel 生成（旧生成器 currentTmpl:null 结构是干员列表卡死根因）。
 * player_data.json 缺失时回退旧 excel 生成逻辑。
 *
 * 合并语义：内容类字段（troop/inventory/consumable/skin——干员与物品随版本新增）以 base 刷新，
 * 其余字段（任务/剧情/基建/勋章/社交/推图等玩家进度）保留当前账号——版本更新不再清空进度。
 *
 * @param player - 目标玩家（单例模式为 uid=1）
 */
export async function generateMaxedAccount(player: PlayerDataManager): Promise<void> {
  const data = player._playerdata as any;

  // 以 player_data.json 为基底（官服满级号——结构完整，直接作为账号数据）
  const base = await readJson<any>("./player_data.json").catch(() => null);
  if (base && base.troop?.chars) {
    const uid = data.status?.uid;
    // 合并式刷新：仅内容类字段以 base 覆盖；玩家进度字段保留
    // （troop 假定 instId 映射与 base 一致——同一 player_data.json 基底派生的账号）
    const REFRESH_KEYS = ["troop", "inventory", "consumable", "skin"];
    const preserved: Record<string, unknown> = {};
    for (const k of Object.keys(data)) {
      if (!REFRESH_KEYS.includes(k)) preserved[k] = data[k];
    }
    for (const k of Object.keys(data)) delete data[k];
    Object.assign(data, base);
    for (const k of Object.keys(preserved)) data[k] = preserved[k];
    // 保持当前账号 uid；版本标记（启动时比较——版本变化重新生成）
    data.status.uid = uid;
    data.status.maxAccountResVersion = config.version.resVersion;
    // 满配资源（独立于保留的进度字段——每次刷新保持大额资源与满级）
    data.status.gold = 99999999;
    data.status.androidDiamond = 99999;
    data.status.iosDiamond = 99999;
    data.status.level = 120;
    data.status.exp = 0;
    if (data.status.maxAp) data.status.ap = data.status.maxAp;
    return;
  }

  // 回退：player_data.json 缺失——excel 逐干员生成（旧逻辑，结构见 buildMaxedChar）
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
