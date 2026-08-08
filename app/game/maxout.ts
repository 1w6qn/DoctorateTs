/**
 * 满配账号共享构建器
 *
 * 从 excel 干员数据生成满配技能/装备结构，供 generate-max-account（single 模式）
 * 与 AdminService.maxOutAccount（管理后台一键满配）复用。
 * 原实现位于 scripts/generate-max-account.ts，为让 app/ 可安全引用（tsc include 仅 app/**）迁入本文件。
 */
import excel from "@excel/excel";

/** 从 excel 干员数据生成满配技能列表（满解锁 + 满专精） */
export function buildMaxedSkills(charData: any): {
  skillId: string;
  unlock: number;
  state: number;
  specializeLevel: number;
  completeUpgradeTime: number;
}[] {
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
export function buildMaxedEquip(charId: string): {
  ids: string[];
  equip: Record<string, unknown>;
} {
  const ids: string[] = (excel as any).UniequipTable?.charEquip?.[charId] || [];
  const equip: Record<string, unknown> = {};
  for (const id of ids) equip[id] = { hide: 0, locked: 0, level: 3 };
  return { ids, equip };
}
