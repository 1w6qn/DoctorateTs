/**
 * 干员「势力」全员收集判定（任务模板 GainTeamChar / guide_43、guide_48 的数据源）
 *
 * 势力成员定义：`character_table[charId].mainPower` 的 nationId / groupId / teamId
 * 命中 `handbook_team_table` 中的 powerId —— 与游戏内「档案 → 势力」展示口径一致
 * （实测：罗德岛 92、哥伦比亚 49、S.W.E.E.P. 3、贾维团伙 3、使徒 3，共 46 个势力，
 * 2 个无成员：none / dublinn）。
 *
 * 修复（2026-09-09，S2）：guide_43「获得1个势力的全部成员」与 guide_48「获得3个势力
 * 的全部成员」此前永久卡死——GainTeamChar 事件全仓无 emit 站点，且模板把目标硬编码为 1。
 */
import excel from "@excel/excel";

/** powerId → 成员干员 id 列表（惰性构建并缓存；数据热更后进程重启即刷新） */
let _powerMembers: Map<string, string[]> | null = null;

/**
 * 构建势力成员表（按 mainPower 归属；无成员的势力不参与判定）
 * @returns powerId → 干员 id 列表
 */
export function powerMembers(): Map<string, string[]> {
  if (_powerMembers) return _powerMembers;
  const table = (excel as { HandbookTeamTable?: Record<string, unknown> })
    .HandbookTeamTable ?? {};
  const map = new Map<string, string[]>();
  for (const id of Object.keys(table)) map.set(id, []);
  const chars =
    (excel as { CharacterTable?: Record<string, { mainPower?: {
      nationId?: string | null;
      groupId?: string | null;
      teamId?: string | null;
    } }> }).CharacterTable ?? {};
  for (const charId of Object.keys(chars)) {
    const power = chars[charId]?.mainPower ?? {};
    for (const powerId of [power.nationId, power.groupId, power.teamId]) {
      if (powerId && map.has(powerId)) map.get(powerId)!.push(charId);
    }
  }
  for (const [id, list] of [...map]) {
    if (list.length === 0) map.delete(id);
  }
  _powerMembers = map;
  return map;
}

/**
 * 计算本次获得干员后「新达成全员收集」的势力
 * @param ownedCharIds - 玩家当前拥有的干员 id 集合（应已包含本次新干员）
 * @param newCharId - 本次获得的干员 id
 * @returns 新完成的 powerId 列表
 */
export function newlyCompletedPowers(
  ownedCharIds: ReadonlySet<string>,
  newCharId: string,
): string[] {
  const out: string[] = [];
  for (const [powerId, members] of powerMembers()) {
    if (!members.includes(newCharId)) continue;
    if (members.every((id) => ownedCharIds.has(id))) out.push(powerId);
  }
  return out;
}

/** 清空势力成员缓存（数据热更/测试用） */
export function resetPowerMembersCache(): void {
  _powerMembers = null;
}
