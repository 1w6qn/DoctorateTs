/**
 * 存档健康检查与自动修复
 *
 * 自动检测玩家存档（data/user/databases/{uid}.json）的常见损坏并尝试修复：
 * 1. 必填顶层结构缺失（status/troop/dungeon/activity/building）
 * 2. troop.chars 内非法干员（非对象/缺 charId）
 * 3. building.rooms.PRIVATE[].owners 含 null 条目（setPrivateDormOwner 字段名 bug 残留）
 * 4. status.uid 类型错误
 *
 * 修复为幂等（对合规结构无副作用）且保守（不做破坏性重建）——结构性损坏可安全修复，
 * 非法 JSON 无法自动修复（由加载层记录并备份）。
 */
import { logger } from "@utils/logger";

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
