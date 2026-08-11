/**
 * 存档健康检查与自动修复
 *
 * 自动检测玩家存档（data/user/databases/{uid}.json）的常见损坏并尝试修复：
 * 1. 必填顶层结构缺失（status/troop/dungeon/activity/building）
 * 2. troop.chars 内非法干员（非对象/缺 charId）
 * 3. building.rooms.PRIVATE[].owners 含 null 条目（setPrivateDormOwner 字段名 bug 残留）
 * 4. status.uid 类型错误
 * 5. dexNav.character[].charInstId 与 troop.chars 一致性（roster 重建后悬空重指向）
 * 6. troop.chars 干员模板字段归一化（自引用空 currentTmpl/旧 null 结构 → 移除）
 * 7. troop.chars 技能回填（按等级/精英化解锁——历史新干员建档空 skills）
 *
 * 修复为幂等（对合规结构无副作用）且保守（不做破坏性重建）——结构性损坏可安全修复，
 * 非法 JSON 无法自动修复（由加载层记录并备份）。
 */
import { logger } from "@utils/logger";
import { reconcileCharSkills, unlockedSkillIds } from "@game/util/char-skills";

/** 存档问题记录 */
export interface SaveIssue {
  /** 问题路径（如 building.rooms.PRIVATE.slot_47.owners） */
  path: string;
  message: string;
  /** 是否已修复 */
  fixed: boolean;
}

/** 必填顶层结构（缺失时重建空对象） */
const REQUIRED_TOP_LEVEL = ["status", "troop", "dungeon", "activity", "building"];

/**
 * 校验并修复玩家存档（幂等）
 * @param data - 从文件读取的存档对象（原地修改）
 * @returns 发现的问题列表（含是否已修复）
 */
export function checkAndRepairSave(data: any): SaveIssue[] {
  const issues: SaveIssue[] = [];
  if (!data || typeof data !== "object") {
    issues.push({ path: "(root)", message: "存档根节点非对象，无法自动修复", fixed: false });
    return issues;
  }

  // 1. status 基础结构（缺失时重建）
  if (!data.status || typeof data.status !== "object") {
    data.status = {
      uid: String(data?.status?.uid ?? "1"),
      nickName: "博士",
      nickNumber: "1",
      level: 1,
      exp: 0,
    };
    issues.push({ path: "status", message: "status 缺失/非对象，重建基础结构", fixed: true });
  }

  // 2. 必填顶层结构
  for (const key of REQUIRED_TOP_LEVEL) {
    if (!data[key] || typeof data[key] !== "object") {
      data[key] = {};
      issues.push({ path: key, message: `${key} 缺失/非对象，重置为空结构`, fixed: true });
    }
  }

  // 3. troop.chars：过滤非法干员
  const chars = data.troop?.chars;
  if (chars && typeof chars === "object") {
    for (const [instId, c] of Object.entries(chars)) {
      if (!c || typeof c !== "object" || !(c as any).charId) {
        delete chars[instId];
        issues.push({ path: `troop.chars[${instId}]`, message: "非法干员（非对象/缺 charId），移除", fixed: true });
      }
    }
  }

  // 4. building.rooms.PRIVATE[].owners 含 null 条目（setPrivateDormOwner 字段名 bug 残留）
  const privateRooms = data.building?.rooms?.PRIVATE;
  if (privateRooms && typeof privateRooms === "object") {
    for (const [slotId, room] of Object.entries(privateRooms)) {
      const owners = (room as any)?.owners;
      if (Array.isArray(owners) && owners.some((o) => o == null)) {
        (room as any).owners = owners.filter((o) => o != null);
        issues.push({
          path: `building.rooms.PRIVATE[${slotId}].owners`,
          message: "含 null 条目（损坏残留），已过滤",
          fixed: true,
        });
      }
    }
  }

  // 5. status.uid 类型
  if (typeof data.status.uid !== "string") {
    data.status.uid = String(data.status.uid ?? "1");
    issues.push({ path: "status.uid", message: "uid 非字符串，转字符串", fixed: true });
  }

  // 6. dexNav.character[charId].charInstId 与 troop.chars 一致性。
  //    干员发放/满配重建 roster（instId 按 charId 编号）后，旧 dexNav 的 charInstId
  //    悬空或错指其他干员 → 客户端按 charInstId 查 troop.chars 失败 → 抽卡/招募结果
  //    "获取干员信息" 报错。修复：按 charId 在 roster 找回正确 instId 重指向；
  //    charId 不在 roster（孤儿条目）则移除，使下次获得时按新干员正确建档。
  const dexChars = data.dexNav?.character as
    | Record<string, { charInstId?: number } | null>
    | undefined;
  const troopChars = data.troop?.chars as
    | Record<string, { charId?: string }>
    | undefined;
  if (dexChars && troopChars) {
    for (const [charId, entry] of Object.entries(dexChars)) {
      const e = entry;
      if (!e || typeof e !== "object") continue;
      const cur = e.charInstId != null ? troopChars[e.charInstId] : undefined;
      if (cur && cur.charId === charId) continue; // 指向正确
      const found = Object.entries(troopChars).find(
        ([, c]) => c && c.charId === charId,
      );
      if (found) {
        const old = e.charInstId;
        e.charInstId = Number(found[0]);
        issues.push({
          path: `dexNav.character[${charId}].charInstId`,
          message: `悬空/错指（原 ${old ?? "无"}，roster[${old ?? "?"}]${cur ? ` 实为 ${cur.charId}` : " 不存在"}），重指向 ${found[0]}`,
          fixed: true,
        });
      } else {
        delete dexChars[charId];
        issues.push({
          path: `dexNav.character[${charId}]`,
          message: "干员不在 troop.chars（孤儿条目），移除",
          fixed: true,
        });
      }
    }
  }

  // 7. troop.chars 干员模板字段（currentTmpl/tmpl）归一化。
  //    官方参考（test.json 379 干员仅 char_002_amiya 带 currentTmpl/tmpl，且
  //    currentTmpl 指向 tmpl 内异格形态）——普通干员不应有模板字段。历史 onCharGet
  //    发放 `currentTmpl:charId + tmpl:{}` 自引用空模板（客户端干员详情按 currentTmpl
  //    查 tmpl 得 undefined → 结构破坏/卡死）；旧生成器 currentTmpl:null 同样卡死。
  //    修复：currentTmpl 无有效模板映射即移除；阿米娅合法多形态模板保留。
  if (chars && typeof chars === "object") {
    for (const [instId, ch] of Object.entries(chars)) {
      const c = ch as any;
      if (!c || typeof c !== "object") continue;
      const tmpl = c.tmpl;
      const hasFilledTmpl =
        tmpl && typeof tmpl === "object" && Object.keys(tmpl).length > 0;
      const cur = c.currentTmpl; // undefined / null / string
      if (cur !== undefined && cur !== null && !hasFilledTmpl) {
        delete c.currentTmpl;
        delete c.tmpl;
        issues.push({
          path: `troop.chars[${instId}]`,
          message: "currentTmpl 无有效模板映射（自引用空模板/旧结构），移除模板字段",
          fixed: true,
        });
      } else if (cur === null) {
        // 旧生成器 currentTmpl:null → 客户端干员列表卡死根因；移除（tmpl 若有填充保留）
        delete c.currentTmpl;
        if (!hasFilledTmpl) delete c.tmpl;
        issues.push({
          path: `troop.chars[${instId}]`,
          message: "currentTmpl 为 null（旧生成器结构），移除模板字段",
          fixed: true,
        });
      } else if (cur !== undefined && hasFilledTmpl && !tmpl[cur]) {
        delete c.currentTmpl;
        issues.push({
          path: `troop.chars[${instId}]`,
          message: "currentTmpl 指向 tmpl 中不存在的形态，移除 currentTmpl",
          fixed: true,
        });
      }
    }
  }

  // 8. troop.chars 技能回填：按等级/精英化解锁相应技能。
  //    历史 onCharGet 建档 skills 恒为空 → 客户端干员详情无技能可看（新干员/发放）。
  //    官方规则 allSkillLvlup[i].unlockCond（test.json 378/378 验证）；幂等回填，
  //    阿米娅（技能在 tmpl）/无技能干员自动跳过。
  if (chars && typeof chars === "object") {
    for (const [instId, ch] of Object.entries(chars)) {
      const c = ch as any;
      if (!c || typeof c !== "object" || !c.charId) continue;
      if (reconcileCharSkills(c)) {
        const unlocked = unlockedSkillIds(
          c.charId,
          c.evolvePhase,
          c.level,
        );
        issues.push({
          path: `troop.chars[${instId}].skills`,
          message: `技能按等级/精英化回填（解锁 ${unlocked.join(",") || "(无)"}）`,
          fixed: true,
        });
      }
    }
  }

  return issues;
}

/**
 * 校验存档并输出健康报告（不修改数据）
 * @param data - 存档对象
 * @returns 是否存在可修复的问题
 */
export function hasRepairableIssues(data: any): boolean {
  return checkAndRepairSave(structuredClone ? structuredClone(data) : JSON.parse(JSON.stringify(data))).some(
    (i) => i.fixed,
  );
}

/**
 * 记录修复结果（供加载/保存层调用）
 */
export function logSaveRepair(uid: string, issues: SaveIssue[]): void {
  for (const issue of issues) {
    if (issue.fixed) {
      logger.warn("save-health", `存档 ${uid} ${issue.path}: ${issue.message}`);
    } else {
      logger.error("save-health", `存档 ${uid} ${issue.path}: ${issue.message}`);
    }
  }
}
