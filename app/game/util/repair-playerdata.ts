/**
 * 玩家数据结构修复工具
 *
 * 修复旧版本满配生成器遗留的坏干员结构（currentTmpl:null + tmpl:{} + 缺字段）——
 * 客户端干员列表按 tmpl[currentTmpl] 取技能/装备，null 会导致渲染卡死。
 * 参考数据：player_data.json（官服 453 干员抓包——通用结构含 skills/equip/voiceLan/starMark，无 tmpl；
 * 唯一例外 char_002_amiya 带 currentTmpl/tmpl 三形态）。
 */
import excel from "@excel/excel";
import { buildMaxedEquip, buildMaxedSkills } from "../../../scripts/generate-max-account";

/** 阿米娅三形态（升变——tmpl key 固定） */
const AMIYA_FORMS = ["char_002_amiya", "char_1001_amiya2", "char_1037_amiya3"];

/**
 * 修复玩家数据的干员结构（幂等——对已合规结构无副作用）
 * @param chars - troop.chars（按 instId 索引的干员字典）
 */
export function repairCharStructure(chars: Record<string, any>): void {
  if (!chars || typeof chars !== "object") return;
  for (const c of Object.values(chars)) {
    if (!c || typeof c !== "object" || !c.charId) continue;
    const charData = (excel.CharacterTable as any)?.[c.charId];
    // 旧生成器：所有干员带 currentTmpl:null/tmpl:{}——非阿米娅删除（客户端按 tmpl[currentTmpl] 崩溃）
    if (c.currentTmpl !== undefined && c.charId !== "char_002_amiya") {
      delete c.currentTmpl;
      delete c.tmpl;
    }
    // 缺失字段补齐（参考 player_data.json 官服结构）
    if (c.voiceLan === undefined) c.voiceLan = "CN_MANDARIN";
    if (c.starMark === undefined) c.starMark = 0;
    if (c.skills === undefined || !Array.isArray(c.skills)) c.skills = [];
    if (c.equip === undefined) c.equip = {};
    if (c.currentEquip === undefined) c.currentEquip = null;
    // 旧生成器 skills 全空：按 excel 补齐（满解锁满专精）
    if (Array.isArray(c.skills) && c.skills.length === 0 && charData?.skills) {
      c.skills = buildMaxedSkills(charData);
    }
    // 旧生成器 equip 空：按 excel 补齐
    if (c.equip && typeof c.equip === "object" && Object.keys(c.equip).length === 0) {
      const { ids, equip } = buildMaxedEquip(c.charId);
      c.equip = equip;
      if (c.currentEquip === null && ids.length > 0) c.currentEquip = ids[0];
    }
    // 阿米娅：tmpl 为空（旧生成器 tmpl:{}）→ 重建三形态（对齐 player_data.json）
    if (c.charId === "char_002_amiya") {
      if (!c.tmpl || Object.keys(c.tmpl).length === 0) {
        const tmpl: Record<string, unknown> = {};
        for (const form of AMIYA_FORMS) {
          const tChar = (excel.CharacterTable as any)?.[form];
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
        c.tmpl = tmpl;
        c.currentTmpl = "char_002_amiya";
      }
    }
  }
}

/**
 * 修复玩家数据入口（_loadPlayer 调用）
 * @param data - 从文件读取的 PlayerDataModel
 */
export function repairPlayerData(data: any): void {
  repairCharStructure(data?.troop?.chars);
}
