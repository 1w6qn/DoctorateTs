/**
 * 管理服务层
 *
 * 供 CLI 与 HTTP 管理接口共用的纯逻辑层：
 * 用户管理、物品/干员/皮肤发放、干员属性编辑、一键满配、基建满级、
 * 备份/回滚、邮件（单发/群发/查看/删除）、每日刷新、原始 JSON、统计与审计日志。
 * 所有数据操作均基于本地 JSON（AccountManager / mailManager），离线可用。
 */
import { appendFile, copyFile, mkdir, readFile, readdir, rm, stat, writeFile } from "fs/promises";
import * as path from "path";
import excel from "@excel/excel";
import { getRoomPhase } from "@excel/building_excel";
import { buildMaxedSkills, buildMaxedEquip } from "@game/maxout";
import { GACHA_RULE_TYPE } from "@game/model/gacha";
import { accountManager } from "@game/manager/AccountManger";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { PlayerDataModel } from "@game/model/playerdata";
import { mailManager } from "@game/manager/mail";
import { runMigration } from "../../scripts/migrate-official";
import { buildMaxedChar } from "../../scripts/generate-max-account";
import { GAME_API, ACCOUNT_API, CONF_API } from "../../scripts/official-api";
import {
  runOfficialAction,
  runOfficialCall,
  runGachaSync,
  OfficialAction,
} from "./official-ops";
import { MAIL_TEMPLATES } from "./mail-templates";
import { exists, size, readJson, writeJson } from "@utils/file";
import { now } from "@utils/time";
import { logger } from "@utils/logger";
import {
  itemName,
  charName,
  charRarity,
  skinName,
  resolveItemRef,
  resolveCharRef,
  COMMON_ITEMS,
} from "./admin-names";
import config from "../config";

/** 审计日志文件（JSONL：一行一条 {ts, action, uid, detail}） */
const ADMIN_LOG_PATH = "./data/admin/logs.jsonl";
/** 用户存档备份目录 */
const BACKUP_DIR = "./data/user/backups";

/** 用户列表摘要 */
export interface UserSummary {
  uid: string;
  nickName: string;
  nickNumber: string;
  level: number;
  phone: string;
  lastOnlineTs: number;
}

/** 用户详情（列表摘要 + 资源/道具摘要） */
export interface UserDetail extends UserSummary {
  gold: number;
  androidDiamond: number;
  gachaTicket: number;
  recruitLicense: number;
  practiceTicket: number;
  exp: number;
  charCnt: number;
  registerTs: number;
  inventory: { [key: string]: number };
  /** 带中文名的背包道具（按数量降序；Dashboard 展示用） */
  inventoryInfo: { id: string; name: string; count: number }[];
  /** 更多资源（理智/凭证/信用等） */
  ap: number;
  maxAp: number;
  hggShard: number;
  lggShard: number;
  socialPoint: number;
  diamondShard: number;
  instantFinishTicket: number;
  tenGachaTicket: number;
}

/** 干员摘要 */
export interface CharSummary {
  instId: number;
  charId: string;
  name: string;
  rarity: number;
  level: number;
  maxLevel: number;
  evolvePhase: number;
  potentialRank: number;
  mainSkillLvl: number;
  skin: string | null;
  skinName: string | null;
}

/** 干员详情（含技能/专精/装备/语音） */
export interface CharDetail extends CharSummary {
  favorPoint: number;
  voiceLan: string;
  skills: { skillId: string; unlock: number; specializeLevel: number }[];
  currentEquip: string | null;
  equip: { [key: string]: unknown };
}

/** 干员属性修改参数（均可选，未传不修改） */
export interface CharAttrs {
  level?: number;
  evolvePhase?: number;
  potentialRank?: number;
  mainSkillLvl?: number;
}

/** 备份文件摘要 */
export interface BackupInfo {
  name: string;
  size: number;
  ts: number;
}

/** 邮件摘要 */
export interface MailSummary {
  mailId: number;
  subject: string;
  content: string;
  createAt: number;
  expireAt: number;
  receiveAt: number;
  state: number;
  hasItem: number;
  items: { id: string; name: string; count: number }[];
}

/** 服务器状态 */
export interface ServerStatus {
  port: number;
  offline: boolean;
  clientVersion: string;
  resVersion: string;
  uptime: number;
  userCount: number;
  dataFiles: { path: string; exists: boolean; size: number }[];
  /** 数据总量（用户存档 + 数据文件，KB） */
  totalDataKB: number;
  /** 进程内存（Node RSS，MB） */
  memoryMB: number;
}

/** 统计聚合 */
export interface AdminStats {
  userCount: number;
  totalChars: number;
  totalGold: number;
  totalDiamond: number;
  avgLevel: number;
  levelDist: { [bucket: string]: number };
  registerDist: { [month: string]: number };
}

/** 审计日志条目 */
export interface AuditLogEntry {
  ts: number;
  action: string;
  uid: string;
  detail: string;
}

/** 卡池摘要 */
export interface PoolSummary {
  poolId: string;
  name: string;
  ruleType: string;
  gachaType: string;
  openTime: number;
  endTime: number;
  guarantee5Count: number;
  guarantee5Avail: number;
  summary: string;
}

/** 卡池干员（UP/可用） */
export interface PoolCharInfo {
  charId: string;
  name: string;
  percent?: number;
  count?: number;
  rarityRank?: number;
}

/** 卡池详情 */
export interface PoolDetail extends PoolSummary {
  upChars: PoolCharInfo[];
  availChars: PoolCharInfo[];
  limitedChars: string[];
}

/** 玩家卡池状态（UP 选择 + 保底计数） */
export interface PlayerPoolState {
  poolId: string;
  name: string;
  ruleType: string;
  gachaType: string;
  upCharIds: string[];
  upChars: { charId: string; name: string }[];
  beforeNonHitCnt: number;
  guarantee5Count: number;
}

/** 玩家签到状态 */
export interface CheckInState {
  groupId: string;
  groupTitle: string;
  canCheckIn: number;
  rewardIndex: number;
  historyCount: number;
  total: number;
}

/** 从玩家数据提取列表摘要 */
export function toUserSummary(uid: string, pd: PlayerDataManager): UserSummary {
  const status = pd._playerdata.status;
  return {
    uid,
    nickName: status.nickName,
    nickNumber: status.nickNumber,
    level: status.level,
    phone: accountManager.configs[uid]?.auth.phone ?? "",
    lastOnlineTs: status.lastOnlineTs,
  };
}

/** 格式化时间戳为 YYYYMMDD-HHmmss（备份文件名用） */
function formatTs(ts: number): string {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}` +
    `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
  );
}

export class AdminService {
  /** 玩家数据快照（grant 等写操作后的落盘：存档 + 账号配置，并清 debounce） */
  private async savePlayer(uid: string): Promise<void> {
    await accountManager.flushSave(uid);
  }

  /** 取玩家（已加载直接返回；未加载走懒加载；不存在/读取失败统一报"用户不存在"） */
  private async getPlayer(uid: string): Promise<PlayerDataManager> {
    if (accountManager.data[uid]) return accountManager.data[uid];
    try {
      return await accountManager.getPlayerData(uid);
    } catch {
      throw new Error(`用户不存在: ${uid}`);
    }
  }

  /** 审计日志：追加一行 JSONL（失败不阻断业务操作）；每 200 条检查一次大小，超 1MB 自动轮转保留最近 3000 行 */
  private _auditCount = 0;
  private async _audit(action: string, uid: string, detail: string): Promise<void> {
    try {
      await mkdir("./data/admin", { recursive: true });
      await appendFile(
        ADMIN_LOG_PATH,
        JSON.stringify({ ts: now(), action, uid, detail }) + "\n",
        "utf8",
      );
      this._auditCount++;
      if (this._auditCount % 200 === 0) {
        const st = await stat(ADMIN_LOG_PATH).catch(() => null);
        if (st && st.size > 1024 * 1024) {
          const entries = await this.logs(3000); // 最新在前
          const kept = entries.reverse().map((e) => JSON.stringify(e)).join("\n") + "\n";
          await writeFile(ADMIN_LOG_PATH, kept, "utf8");
        }
      }
    } catch (e) {
      logger.warn("AdminService", `审计日志写入失败: ${(e as Error).message}`);
    }
  }

  /** 用户列表（按 uid 排序；filter 匹配 uid/昵称/手机号，空返回全部） */
  async listUsers(filter = ""): Promise<UserSummary[]> {
    const kw = String(filter ?? "").trim().toLowerCase();
    return Object.keys(accountManager.data)
      .sort((a, b) => Number(a) - Number(b))
      .map((uid) => toUserSummary(uid, accountManager.data[uid]))
      .filter(
        (u) =>
          !kw ||
          u.uid.includes(kw) ||
          u.nickName.toLowerCase().includes(kw) ||
          u.phone.toLowerCase().includes(kw),
      );
  }

  /** 用户详情 */
  async getUserInfo(uid: string): Promise<UserDetail | null> {
    const pd = accountManager.data[uid];
    if (!pd) return null;
    const status = pd._playerdata.status;
    const inventory = pd._playerdata.inventory ?? {};
    const inventoryInfo = Object.entries(inventory)
      .map(([id, count]) => ({ id, name: itemName(id), count }))
      .sort((a, b) => b.count - a.count);
    return {
      ...toUserSummary(uid, pd),
      gold: status.gold,
      androidDiamond: status.androidDiamond,
      gachaTicket: status.gachaTicket,
      recruitLicense: status.recruitLicense,
      practiceTicket: status.practiceTicket,
      exp: status.exp,
      charCnt: pd._playerdata.troop.curCharInstId - 1,
      registerTs: status.registerTs,
      inventory,
      inventoryInfo,
      ap: status.ap,
      maxAp: status.maxAp,
      hggShard: status.hggShard,
      lggShard: status.lggShard,
      socialPoint: status.socialPoint,
      diamondShard: status.diamondShard,
      instantFinishTicket: status.instantFinishTicket,
      tenGachaTicket: status.tenGachaTicket,
    };
  }

  /**
   * 发放物品/资源
   * @param uid - 目标用户ID
   * @param itemId - 物品ID（如 4001=龙门币、4003=合成玉）或中文名/别名（如 "合成玉"）
   * @param count - 数量（正整数）
   */
  async grantItem(uid: string, itemId: string, count: number): Promise<void> {
    if (!Number.isInteger(count) || count <= 0) {
      throw new Error(`数量必须为正整数，收到: ${count}`);
    }
    const resolved = resolveItemRef(itemId);
    if (!resolved) {
      throw new Error(`未知物品: ${itemId}（可先 users config 或用 item_table.json 核对 ID）`);
    }
    if (!excel.ItemTable?.items?.[resolved]) {
      throw new Error(`物品 ${resolved} 不在 ItemTable，无法发放`);
    }
    const pd = await this.getPlayer(uid);
    await pd.inventory.gainItem({ id: resolved, count });
    await this.savePlayer(uid);
    await this._audit("grantItem", uid, `${resolved}(${itemName(resolved)}) x${count}`);
  }

  /**
   * 发放干员（新干员建档；重复干员按稀有度折算信物/凭证）
   * @param uid - 目标用户ID
   * @param charId - 干员ID（如 char_002_amiya）或中文名
   */
  async grantChar(uid: string, charId: string): Promise<{ isNew: number; name: string }> {
    const resolved = resolveCharRef(charId);
    if (!(excel.CharacterTable as Record<string, any>)?.[resolved]) {
      throw new Error(`未知干员: ${charId}`);
    }
    const pd = await this.getPlayer(uid);
    // 直接调用 onCharGet（char:get 事件监听为无操作，见 char.ts 构造器）
    const res = await pd.char.onCharGet([resolved, { from: "ADMIN" }]);
    await this.savePlayer(uid);
    await this._audit("grantChar", uid, `${resolved}(${charName(resolved)})`);
    return { isNew: res?.isNew ?? 0, name: charName(resolved) };
  }

  /**
   * 解锁皮肤
   * @param uid - 目标用户ID
   * @param skinId - 皮肤ID（如 char_002_amiya#2）
   */
  async grantSkin(uid: string, skinId: string): Promise<void> {
    if (!excel.SkinTable?.charSkins?.[skinId]) {
      throw new Error(`未知皮肤: ${skinId}`);
    }
    const pd = await this.getPlayer(uid);
    await pd.inventory.gainItem({ id: skinId, count: 1, type: "CHAR_SKIN" });
    await this.savePlayer(uid);
    await this._audit("grantSkin", uid, `${skinId}(${skinName(skinId) ?? ""})`);
  }

  /** 干员列表 */
  async listChars(uid: string): Promise<CharSummary[]> {
    const pd = await this.getPlayer(uid);
    const chars = pd._playerdata.troop?.chars ?? {};
    return Object.values(chars)
      .sort((a, b) => a.instId - b.instId)
      .map((ch) => {
        const info = (excel.CharacterTable as Record<string, any>)?.[ch.charId];
        const phases = info?.phases as any[] | undefined;
        const maxLevel = phases?.[ch.evolvePhase ?? 0]?.maxLevel ?? 90;
        return {
          instId: ch.instId,
          charId: ch.charId,
          name: charName(ch.charId),
          rarity: charRarity(ch.charId),
          level: ch.level,
          maxLevel,
          evolvePhase: ch.evolvePhase,
          potentialRank: ch.potentialRank,
          mainSkillLvl: ch.mainSkillLvl,
          skin: ch.skin ?? null,
          skinName: ch.skin ? skinName(ch.skin) : null,
        };
      });
  }

  /** 单个干员详情（技能/专精/装备/信赖/语音等；不存在返回 null） */
  async getCharDetail(
    uid: string,
    instId: number,
  ): Promise<CharDetail | null> {
    const pd = await this.getPlayer(uid);
    const ch = pd._playerdata.troop?.chars?.[String(instId)];
    if (!ch) return null;
    const info = (excel.CharacterTable as Record<string, any>)?.[ch.charId];
    return {
      instId,
      charId: ch.charId,
      name: charName(ch.charId),
      rarity: charRarity(ch.charId),
      level: ch.level,
      maxLevel: info?.phases?.[ch.evolvePhase]?.maxLevel ?? 90,
      evolvePhase: ch.evolvePhase,
      potentialRank: ch.potentialRank,
      mainSkillLvl: ch.mainSkillLvl,
      favorPoint: ch.favorPoint,
      skin: ch.skin ?? null,
      skinName: ch.skin ? skinName(ch.skin) : null,
      voiceLan: ch.voiceLan,
      skills: (ch.skills ?? []).map((s) => ({
        skillId: s.skillId,
        unlock: s.unlock,
        specializeLevel: s.specializeLevel,
      })),
      currentEquip: ch.currentEquip ?? null,
      equip: ch.equip ?? {},
    };
  }

  /** 商店数据汇总（只读：各商店类型购买记录数） */
  async getShopSummary(
    uid: string,
  ): Promise<{ types: { type: string; curShopId?: string; items: number }[]; total: number }> {
    const pd = await this.getPlayer(uid);
    const shop = (pd._playerdata.shop ?? {}) as Record<string, any>;
    const types = Object.entries(shop).map(([type, v]) => ({
      type,
      curShopId: typeof v?.curShopId === "string" ? v.curShopId : undefined,
      items: Array.isArray(v?.info) ? v.info.length : 0,
    }));
    return {
      types,
      total: types.reduce((s, t) => s + t.items, 0),
    };
  }

  /**
   * 修改干员属性（免费路径，不消耗道具；未传参数不改动）
   * 边界钳制：精二 ≤ phases 上限、等级 ≤ 当前阶段 maxLevel、潜能 ≤ maxPotentialLevel、技能 ≤ 7
   */
  async setCharAttrs(uid: string, instId: number, attrs: CharAttrs): Promise<CharSummary> {
    if (!attrs || Object.keys(attrs).length === 0) {
      throw new Error("未提供任何要修改的属性");
    }
    const pd = await this.getPlayer(uid);
    const ch = pd._playerdata.troop?.chars?.[String(instId)];
    if (!ch) {
      throw new Error(`干员不存在: instId=${instId}`);
    }
    const info = (excel.CharacterTable as Record<string, any>)?.[ch.charId];
    const phases = info?.phases as any[] | undefined;
    const maxEvolve = phases?.length ? phases.length - 1 : 2;
    const maxPotential = info?.maxPotentialLevel ?? 5;

    await pd.update(async (draft) => {
      const target = draft.troop.chars[String(instId)];
      if (attrs.evolvePhase !== undefined) {
        target.evolvePhase = Math.min(Math.max(attrs.evolvePhase, 0), maxEvolve);
      }
      const maxLevel = phases?.[target.evolvePhase]?.maxLevel ?? 90;
      if (attrs.level !== undefined) {
        target.level = Math.min(Math.max(attrs.level, 1), maxLevel);
      } else {
        target.level = Math.min(target.level, maxLevel);
      }
      if (attrs.potentialRank !== undefined) {
        target.potentialRank = Math.min(Math.max(attrs.potentialRank, 0), maxPotential);
      }
      if (attrs.mainSkillLvl !== undefined) {
        target.mainSkillLvl = Math.min(Math.max(attrs.mainSkillLvl, 1), 7);
      }
      target.exp = 0;
    });
    await this.savePlayer(uid);
    await this._audit(
      "setCharAttrs",
      uid,
      `instId=${instId} ${JSON.stringify(attrs)}`,
    );
    return (await this.listChars(uid)).find((c) => c.instId === instId)!;
  }

  /**
   * 一键满配（软满配——不覆盖阵容，最大化当前账号）：
   * 大额资源 + 全背包物品 999 + 已有干员拉满（精二满级/满潜/满技能/专三/满信赖/满专精装备）
   * + 已拥有干员的全部皮肤解锁 + 基建满级。
   * @returns 影响统计 {chars, items, skins, rooms}
   */
  async maxOutAccount(uid: string): Promise<{ chars: number; items: number; skins: number; rooms: number }> {
    const pd = await this.getPlayer(uid);
    const stats = { chars: 0, items: 0, skins: 0, rooms: 0 };
    const ownedCharIds = new Set(
      Object.values(pd._playerdata.troop?.chars ?? {}).map((c) => c.charId),
    );

    await pd.update(async (draft) => {
      // 1. 大额资源（与 generate-max-account 保持一致）
      draft.status.gold = 99999999;
      draft.status.androidDiamond = 99999;
      draft.status.iosDiamond = 99999;
      draft.status.level = 120;
      draft.status.exp = 0;
      if (draft.status.maxAp) draft.status.ap = draft.status.maxAp;

      // 2. 全背包物品（sortId>0；CONSUME → consumable，其余 → inventory）
      const items = excel.ItemTable?.items ?? {};
      for (const [itemId, info] of Object.entries(items)) {
        if (info.sortId <= 0) continue;
        if (info.classifyType === "CONSUME") {
          draft.consumable[itemId] = { "0": { ts: -1, count: 999 } };
        } else if (info.classifyType === "NORMAL" || info.classifyType === "MATERIAL") {
          draft.inventory[itemId] = 999;
        }
        stats.items++;
      }

      // 3. 已有干员拉满
      for (const ch of Object.values(draft.troop?.chars ?? {})) {
        const charData = (excel.CharacterTable as Record<string, any>)?.[ch.charId];
        const phases = charData?.phases as any[] | undefined;
        const maxEvolve = phases?.length ? phases.length - 1 : 2;
        ch.evolvePhase = maxEvolve;
        ch.level = phases?.[maxEvolve]?.maxLevel ?? 90;
        ch.exp = 0;
        ch.potentialRank = 5;
        ch.mainSkillLvl = 7;
        ch.favorPoint = 25570;
        const skills = buildMaxedSkills(charData);
        if (skills.length) {
          ch.skills = skills;
          ch.defaultSkillIndex = ch.defaultSkillIndex ?? 0;
        }
        const { ids: equipIds, equip } = buildMaxedEquip(ch.charId);
        ch.currentEquip = equipIds[0] || null;
        // buildMaxedEquip 返回 Record<string, unknown>（excel 动态结构），与 PlayerCharEquipInfo 映射兼容
        ch.equip = equip as any;
        stats.chars++;
      }

      // 4. 已拥有干员的全部皮肤解锁
      for (const [skinId, skin] of Object.entries(excel.SkinTable?.charSkins ?? {})) {
        if (skin?.charId && ownedCharIds.has(skin.charId)) {
          draft.skin.characterSkins[skinId] = 1;
          draft.skin.skinTs[skinId] = now();
          stats.skins++;
        }
      }

      // 5. 基建满级
      for (const slot of Object.values(draft.building?.roomSlots ?? {})) {
        if (!slot?.roomId) continue;
        let level = slot.level ?? 1;
        while (getRoomPhase(slot.roomId, level + 1)) level++;
        slot.level = level;
        stats.rooms++;
      }
    });

    await this.savePlayer(uid);
    await this._audit("maxOutAccount", uid, JSON.stringify(stats));
    return stats;
  }

  /** 基建满级（所有已建造房间升到最高相位等级） */
  async buildingMax(uid: string): Promise<{ rooms: number }> {
    const pd = await this.getPlayer(uid);
    let rooms = 0;
    await pd.update(async (draft) => {
      for (const slot of Object.values(draft.building?.roomSlots ?? {})) {
        if (!slot?.roomId) continue;
        let level = slot.level ?? 1;
        while (getRoomPhase(slot.roomId, level + 1)) level++;
        slot.level = level;
        rooms++;
      }
    });
    await this.savePlayer(uid);
    await this._audit("buildingMax", uid, `${rooms} 间房间`);
    return { rooms };
  }

  /** 备份用户存档（data/user/backups/{uid}-{YYYYMMDD-HHmmss}.json） */
  async backup(uid: string): Promise<BackupInfo> {
    const src = `./data/user/databases/${uid}.json`;
    if (!(await exists(src))) {
      throw new Error(`用户不存在: ${uid}（无存档文件）`);
    }
    await mkdir(BACKUP_DIR, { recursive: true });
    const name = `${uid}-${formatTs(now())}.json`;
    await copyFile(src, `${BACKUP_DIR}/${name}`);
    const st = await this.statBackup(name);
    await this._audit("backup", uid, name);
    return st;
  }

  /** 列出某用户全部备份（按时间倒序） */
  async listBackups(uid: string): Promise<BackupInfo[]> {
    let names: string[] = [];
    try {
      names = await readdir(BACKUP_DIR);
    } catch {
      return [];
    }
    const prefix = `${uid}-`;
    const list: BackupInfo[] = [];
    for (const name of names) {
      if (name.startsWith(prefix) && name.endsWith(".json")) {
        const st = await this.statBackup(name);
        if (st) list.push(st);
      }
    }
    return list.sort((a, b) => b.ts - a.ts);
  }

  /** 清理旧备份（保留最近 keep 个；按时间倒序） */
  async cleanBackups(uid: string, keep = 10): Promise<{ removed: number; kept: number }> {
    if (!Number.isInteger(keep) || keep < 0) {
      throw new Error(`keep 必须为非负整数: ${keep}`);
    }
    const list = await this.listBackups(uid);
    const remove = list.slice(keep);
    for (const b of remove) {
      await rm(`${BACKUP_DIR}/${b.name}`).catch(() => {});
    }
    await this._audit("cleanBackups", uid, `删除 ${remove.length} 个旧备份（保留 ${list.length - remove.length}）`);
    return { removed: remove.length, kept: list.length - remove.length };
  }

  /** 备份文件信息（不存在返回 null） */
  private async statBackup(name: string): Promise<BackupInfo> {
    const path = `${BACKUP_DIR}/${name}`;
    if (!(await exists(path))) {
      throw new Error(`备份不存在: ${name}`);
    }
    const buf = await readFile(path);
    const match = /^(\d+)-([\d-]+)\.json$/.exec(name);
    const tsMatch = /-(\d{14})\.json$/.exec(name);
    const ts = tsMatch
      ? this.parseTs(tsMatch[1])
      : Number(match?.[1] ?? 0);
    return { name, size: buf.length, ts };
  }

  /** YYYYMMDDHHmmss → 秒级时间戳（解析失败返回 0） */
  private parseTs(s: string): number {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(s);
    if (!m) return 0;
    const [, Y, Mo, D, H, Mi, Se] = m;
    return Math.floor(
      new Date(Number(Y), Number(Mo) - 1, Number(D), Number(H), Number(Mi), Number(Se)).getTime() /
        1000,
    );
  }

  /**
   * 从备份恢复用户存档
   * @param uid - 用户ID
   * @param backupName - 备份文件名（须匹配 {uid}-{ts}.json，防路径穿越）
   */
  async restore(uid: string, backupName: string): Promise<void> {
    if (!new RegExp(`^${uid}-[\\d-]+\\.json$`).test(backupName)) {
      throw new Error(`非法的备份文件名: ${backupName}`);
    }
    const path = `${BACKUP_DIR}/${backupName}`;
    if (!(await exists(path))) {
      throw new Error(`备份不存在: ${backupName}`);
    }
    const data = await readJson<PlayerDataModel>(path);
    accountManager.data[uid] = new PlayerDataManager(data);
    await this.savePlayer(uid);
    await this._audit("restore", uid, backupName);
  }

  /**
   * 发送系统邮件
   * @param uid - 接收者用户ID
   * @param args - 标题/内容/附件
   */
  async sendMail(
    uid: string,
    args: { subject: string; content: string; items: { id: string; count: number }[] },
  ) {
    if (!accountManager.data[uid]) {
      throw new Error(`用户不存在: ${uid}`);
    }
    const items = args.items.map((it) => ({ id: it.id, count: it.count }));
    const mail = await mailManager.sendMail(uid, {
      subject: args.subject,
      content: args.content,
      items,
    });
    await this._audit(
      "sendMail",
      uid,
      `mailId=${mail.mailId} ${args.subject}（附件 ${items.length} 种）`,
    );
    return mail;
  }

  /** 群发邮件（发送给所有用户） */
  async sendMailAll(
    args: { subject: string; content: string; items: { id: string; count: number }[] },
  ): Promise<{ sent: number }> {
    const uids = Object.keys(accountManager.data);
    for (const uid of uids) {
      await mailManager.sendMail(uid, {
        subject: args.subject,
        content: args.content,
        items: args.items,
      });
    }
    await this._audit("sendMailAll", "", `${args.subject} → ${uids.length} 人`);
    return { sent: uids.length };
  }

  /** 用户邮件列表 */
  async listMails(uid: string): Promise<MailSummary[]> {
    await this.getPlayer(uid);
    return mailManager.listAllMail(uid).map((mail) => ({
      mailId: mail.mailId,
      subject: mail.subject,
      content: mail.content,
      createAt: mail.createAt,
      expireAt: mail.expireAt,
      receiveAt: mail.receiveAt,
      state: mail.state,
      hasItem: mail.hasItem,
      items: (mail.items ?? []).map((it) => ({
        id: it.id,
        name: itemName(it.id),
        count: it.count,
      })),
    }));
  }

  /** 删除用户单封邮件 */
  async deleteMail(uid: string, mailId: number): Promise<boolean> {
    const ok = await mailManager.deleteMail(uid, mailId);
    if (ok) {
      await this._audit("deleteMail", uid, `mailId=${mailId}`);
    }
    return ok;
  }

  /** 触发每日/每周刷新（理智恢复、购买次数、任务重置等） */
  async refreshUser(uid: string): Promise<void> {
    const pd = await this.getPlayer(uid);
    try {
      await pd.status.refreshTime();
    } catch (e) {
      logger.warn("AdminService", `refreshTime 失败: ${(e as Error).message}`);
    }
    try {
      await pd.mission.dailyRefresh();
    } catch (e) {
      logger.warn("AdminService", `mission.dailyRefresh 失败: ${(e as Error).message}`);
    }
    await this.savePlayer(uid);
    await this._audit("refreshUser", uid, "每日/每周刷新");
  }

  /** 一键日常：每日/每周刷新 + 签到代签 + 落盘 */
  async dailyRoutine(uid: string): Promise<{ refreshed: boolean; checkin: string }> {
    const pd = await this.getPlayer(uid);
    try {
      await pd.status.refreshTime();
      await pd.mission.dailyRefresh();
    } catch (e) {
      logger.warn("AdminService", `dailyRoutine 刷新失败: ${(e as Error).message}`);
    }
    let checkin = "不可签";
    try {
      const res = await pd.checkIn.checkIn();
      if (res) checkin = "已签";
    } catch {
      checkin = "签到失败";
    }
    await this.savePlayer(uid);
    await this._audit("dailyRoutine", uid, `刷新 + ${checkin}`);
    return { refreshed: true, checkin };
  }

  /** 立即保存用户存档 */
  async saveUser(uid: string): Promise<void> {
    await this.getPlayer(uid);
    await this.savePlayer(uid);
    await this._audit("saveUser", uid, "手动保存");
  }

  /** 原始玩家数据（完整 JSON） */
  async getRawJson(uid: string): Promise<PlayerDataModel> {
    const pd = await this.getPlayer(uid);
    return pd.toJSON();
  }

  /**
   * 游戏协议代理：以目标玩家 secret 调用游戏端点（Dashboard「接口」协议调试用）
   * @param uid - 目标玩家 uid（取其 secret 认证；single 模式强制固定账号不受影响）
   * @param path - 游戏端点路径（须以 / 开头，禁止 /admin、/auth 控制面路径）
   * @param method - HTTP 方法（默认 GET）
   * @param body - 请求体 JSON
   * @returns 内层 HTTP 状态码与响应体（JSON 解析失败原样返回文本）
   */
  async gameProxy(
    uid: string,
    path: string,
    method: "GET" | "POST" | "DELETE" = "GET",
    body?: unknown,
  ): Promise<{ status: number; data: unknown; uid: string }> {
    const p = String(path ?? "").trim();
    if (!p.startsWith("/")) {
      throw new Error(`路径必须以 / 开头: ${path}`);
    }
    if (p.startsWith("/admin") || p.startsWith("/auth")) {
      throw new Error(`不允许代理控制面路径: ${path}`);
    }
    await this.getPlayer(uid);
    const token = await accountManager.getTokenByUid(uid);
    const url = `http://localhost:${config.PORT}${p}`;
    let res: Awaited<ReturnType<typeof fetch>>;
    try {
      res = await fetch(url, {
        method,
        headers: {
          secret: token,
          "Content-Type": "application/json",
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    } catch (e) {
      throw new Error(`服务器内部请求失败: ${(e as Error).message}`);
    }
    const text = await res.text();
    let data: unknown = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      // 非 JSON 响应（如错误页）原样返回文本
    }
    return { status: res.status, data, uid };
  }

  /** 卡池清单（excel.GachaTable.gachaPoolClient） */
  listPools(): PoolSummary[] {
    return (excel.GachaTable?.gachaPoolClient ?? []).map((p) => ({
      poolId: p.gachaPoolId,
      name: p.gachaPoolName,
      ruleType: p.gachaRuleType,
      gachaType: GACHA_RULE_TYPE[p.gachaRuleType] ?? "single",
      openTime: p.openTime,
      endTime: p.endTime,
      guarantee5Count: p.guarantee5Count,
      guarantee5Avail: p.guarantee5Avail,
      summary: p.gachaPoolSummary ?? "",
    }));
  }

  /** 卡池详情（UP/可用干员 + 概率；不存在返回 null） */
  poolDetail(poolId: string): PoolDetail | null {
    const pool = (excel.GachaTable?.gachaPoolClient ?? []).find(
      (p) => p.gachaPoolId === poolId,
    );
    if (!pool) return null;
    const detail = excel.GachaDetailTable?.details?.[poolId];
    const mapList = (
      list?: { charIdList: string[]; percent?: number; count?: number; rarityRank?: number }[],
    ): PoolCharInfo[] =>
      (list ?? []).flatMap((per) =>
        per.charIdList.map((charId) => ({
          charId,
          name: charName(charId),
          percent: per.percent,
          count: per.count,
          rarityRank: per.rarityRank,
        })),
      );
    return {
      poolId,
      name: pool.gachaPoolName,
      ruleType: pool.gachaRuleType,
      gachaType: GACHA_RULE_TYPE[pool.gachaRuleType] ?? "single",
      openTime: pool.openTime,
      endTime: pool.endTime,
      guarantee5Count: pool.guarantee5Count,
      guarantee5Avail: pool.guarantee5Avail,
      summary: pool.gachaPoolSummary ?? "",
      upChars: mapList(detail?.upCharInfo?.perCharList),
      availChars: mapList(detail?.availCharInfo?.perAvailList),
      limitedChars: detail?.limitedChar ?? [],
    };
  }

  /** 玩家卡池状态（UP 选择 + 保底计数） */
  async getPlayerPoolState(uid: string, poolId: string): Promise<PlayerPoolState> {
    const pool = (excel.GachaTable?.gachaPoolClient ?? []).find(
      (p) => p.gachaPoolId === poolId,
    );
    if (!pool) {
      throw new Error(`卡池不存在: ${poolId}`);
    }
    const pd = await this.getPlayer(uid);
    const gachaType = GACHA_RULE_TYPE[pool.gachaRuleType] ?? "single";
    const poolData = (pd._playerdata.gacha as any)?.[gachaType]?.[poolId];
    const upCharIds: string[] = Array.isArray(poolData?.upChar) ? poolData.upChar : [];
    const beforeNonHitCnt = await accountManager.getBeforeNonHitCnt(
      uid,
      pool.gachaRuleType,
    );
    return {
      poolId,
      name: pool.gachaPoolName,
      ruleType: pool.gachaRuleType,
      gachaType,
      upCharIds,
      upChars: upCharIds.map((id) => ({ charId: id, name: charName(id) })),
      beforeNonHitCnt,
      guarantee5Count: pool.guarantee5Count,
    };
  }

  /**
   * 设置玩家卡池 UP 选择（空数组清除；与 choosePoolUp 写入同一位置 gacha[gachaType][poolId].upChar）
   * @returns 更新后的玩家卡池状态
   */
  async setPlayerPoolUp(
    uid: string,
    poolId: string,
    charIds: string[],
  ): Promise<PlayerPoolState> {
    const pool = (excel.GachaTable?.gachaPoolClient ?? []).find(
      (p) => p.gachaPoolId === poolId,
    );
    if (!pool) {
      throw new Error(`卡池不存在: ${poolId}`);
    }
    const clean = charIds.map(String).map(resolveCharRef).filter(Boolean);
    const pd = await this.getPlayer(uid);
    const gachaType = GACHA_RULE_TYPE[pool.gachaRuleType] ?? "single";
    await pd.update(async (draft) => {
      const gacha = (draft as any).gacha;
      if (!gacha[gachaType]) gacha[gachaType] = {};
      if (!gacha[gachaType][poolId]) gacha[gachaType][poolId] = {};
      gacha[gachaType][poolId].upChar = clean;
    });
    await this.savePlayer(uid);
    await this._audit(
      "setPoolUp",
      uid,
      `${poolId} → ${clean.join(",") || "（清除）"}`,
    );
    return this.getPlayerPoolState(uid, poolId);
  }

  /**
   * 设置玩家保底计数（保底按 gachaRuleType 存于账号配置，如 NORMAL/LIMITED/CLASSIC）
   * @returns 更新后的保底计数
   */
  async setPlayerPity(
    uid: string,
    ruleType: string,
    count: number,
  ): Promise<{ uid: string; ruleType: string; beforeNonHitCnt: number }> {
    if (!Number.isInteger(count) || count < 0) {
      throw new Error(`保底计数必须为非负整数: ${count}`);
    }
    await this.getPlayer(uid);
    const key = String(ruleType).toUpperCase();
    await accountManager.saveBeforeNonHitCnt(uid, key, count);
    await this.savePlayer(uid);
    await this._audit("setPity", uid, `${key} → ${count}`);
    return {
      uid,
      ruleType: key,
      beforeNonHitCnt: await accountManager.getBeforeNonHitCnt(uid, key),
    };
  }

  /** 查看玩家某规则类型保底计数 */
  async getPlayerPity(
    uid: string,
    ruleType: string,
  ): Promise<{ uid: string; ruleType: string; beforeNonHitCnt: number }> {
    await this.getPlayer(uid);
    const key = String(ruleType).toUpperCase();
    return {
      uid,
      ruleType: key,
      beforeNonHitCnt: await accountManager.getBeforeNonHitCnt(uid, key),
    };
  }

  /** 列出玩家全部规则类型的保底计数 */
  async listPlayerPity(
    uid: string,
  ): Promise<{ ruleType: string; beforeNonHitCnt: number }[]> {
    await this.getPlayer(uid);
    const gacha = accountManager.configs[uid]?.gacha ?? {};
    return Object.entries(gacha).map(([ruleType, v]) => ({
      ruleType,
      beforeNonHitCnt: v?.beforeNonHitCnt ?? 0,
    }));
  }

  /**
   * 批量发放全部 ItemTable 物品（sortId>0；CONSUME → consumable，其余 → inventory）
   * @returns 发放物品种数
   */
  async grantAllItems(uid: string, count = 999): Promise<{ items: number }> {
    if (!Number.isInteger(count) || count <= 0) {
      throw new Error(`数量必须为正整数: ${count}`);
    }
    const pd = await this.getPlayer(uid);
    let n = 0;
    await pd.update(async (draft) => {
      for (const [itemId, info] of Object.entries(excel.ItemTable?.items ?? {})) {
        if (info.sortId <= 0) continue;
        if (info.classifyType === "CONSUME") {
          draft.consumable[itemId] = { "0": { ts: -1, count } };
        } else if (info.classifyType === "NORMAL" || info.classifyType === "MATERIAL") {
          draft.inventory[itemId] = count;
        } else {
          continue;
        }
        n++;
      }
    });
    await this.savePlayer(uid);
    await this._audit("grantAllItems", uid, `${n} 种物品 x${count}`);
    return { items: n };
  }

  /**
   * 批量拉满全部已有干员（精二满级/满潜/满技能/专三/满信赖/满专精装备；不含资源/背包）
   * @returns 拉满干员数
   */
  async maxAllChars(uid: string): Promise<{ chars: number }> {
    const pd = await this.getPlayer(uid);
    let n = 0;
    await pd.update(async (draft) => {
      for (const ch of Object.values(draft.troop?.chars ?? {})) {
        const charData = (excel.CharacterTable as Record<string, any>)?.[ch.charId];
        const phases = charData?.phases as any[] | undefined;
        const maxEvolve = phases?.length ? phases.length - 1 : 2;
        ch.evolvePhase = maxEvolve;
        ch.level = phases?.[maxEvolve]?.maxLevel ?? 90;
        ch.exp = 0;
        ch.potentialRank = 5;
        ch.mainSkillLvl = 7;
        ch.favorPoint = 25570;
        const skills = buildMaxedSkills(charData);
        if (skills.length) {
          ch.skills = skills;
          ch.defaultSkillIndex = ch.defaultSkillIndex ?? 0;
        }
        const { ids: equipIds, equip } = buildMaxedEquip(ch.charId);
        ch.currentEquip = equipIds[0] || null;
        // buildMaxedEquip 返回 Record<string, unknown>（excel 动态结构），与 PlayerCharEquipInfo 映射兼容
        ch.equip = equip as any;
        n++;
      }
    });
    await this.savePlayer(uid);
    await this._audit("maxAllChars", uid, `${n} 名干员`);
    return { chars: n };
  }

  /** 玩家推图进度（只读：已解锁/已完成关卡） */
  async listStages(
    uid: string,
  ): Promise<{
    total: number;
    done: number;
    stages: { stageId: string; state: number; completeTimes: number }[];
  }> {
    const pd = await this.getPlayer(uid);
    const stages = pd._playerdata.dungeon?.stages ?? {};
    const list = Object.entries(stages)
      .map(([stageId, s]) => ({
        stageId,
        state: s.state,
        completeTimes: s.completeTimes,
      }))
      .sort((a, b) => a.stageId.localeCompare(b.stageId));
    return {
      total: list.length,
      done: list.filter((s) => s.completeTimes > 0).length,
      stages: list.slice(0, 500),
    };
  }

  /** 解锁指定关卡（标记已完成 state=3 + completeTimes=1） */
  async unlockStage(uid: string, stageId: string): Promise<{ stageId: string }> {
    if (!excel.StageTable?.stages?.[stageId]) {
      throw new Error(`关卡不存在: ${stageId}`);
    }
    const pd = await this.getPlayer(uid);
    await pd.update(async (draft) => {
      draft.dungeon.stages[stageId] = {
        stageId,
        completeTimes: 1,
        startTimes: 1,
        practiceTimes: 0,
        state: 3,
        hasBattleReplay: 0,
        noCostCnt: 0,
      };
    });
    await this.savePlayer(uid);
    await this._audit("unlockStage", uid, stageId);
    return { stageId };
  }

  /** 推图全解锁（遍历 StageTable 全部关卡，跳过已有进度的） */
  async unlockAllStages(uid: string): Promise<{ stages: number; total: number }> {
    const pd = await this.getPlayer(uid);
    const ids = Object.keys(excel.StageTable?.stages ?? {});
    let n = 0;
    await pd.update(async (draft) => {
      for (const stageId of ids) {
        if (draft.dungeon.stages[stageId]) continue;
        draft.dungeon.stages[stageId] = {
          stageId,
          completeTimes: 1,
          startTimes: 1,
          practiceTimes: 0,
          state: 3,
          hasBattleReplay: 0,
          noCostCnt: 0,
        };
        n++;
      }
    });
    await this.savePlayer(uid);
    await this._audit("unlockAllStages", uid, `新增 ${n} 关（共 ${ids.length} 关）`);
    return { stages: n, total: ids.length };
  }

  /**
   * 物品搜索（按 ID/中文名过滤 ItemTable；供发放弹窗选择）
   * @param q - 关键字（空返回前 limit 条）
   * @returns 匹配物品（id/name/classifyType）
   */
  searchItems(q: string, limit = 50): { id: string; name: string; classifyType: string }[] {
    const kw = String(q ?? "").trim().toLowerCase();
    const items = excel.ItemTable?.items ?? {};
    const list: { id: string; name: string; classifyType: string }[] = [];
    for (const [id, info] of Object.entries(items)) {
      const name = info?.name ?? "";
      if (!kw || id.toLowerCase().includes(kw) || name.toLowerCase().includes(kw)) {
        list.push({ id, name, classifyType: info?.classifyType ?? "" });
        if (list.length >= limit) break;
      }
    }
    return list;
  }

  /** 任务进度统计（只读：各组任务数/已完成数；state≥2 视为已完成） */
  async listMissionStats(
    uid: string,
  ): Promise<{
    total: number;
    done: number;
    groups: { group: string; total: number; done: number }[];
  }> {
    const pd = await this.getPlayer(uid);
    const missions = pd._playerdata.mission?.missions ?? {};
    const groups = Object.entries(missions).map(([group, byId]) => {
      const list = Object.values(byId ?? {});
      return {
        group,
        total: list.length,
        done: list.filter((m) => m.state >= 2).length,
      };
    });
    return {
      total: groups.reduce((s, g) => s + g.total, 0),
      done: groups.reduce((s, g) => s + g.done, 0),
      groups,
    };
  }

  /** 勋章进度（只读：已解锁/总数；fts>0 视为已解锁） */
  async listMedals(
    uid: string,
  ): Promise<{ total: number; unlocked: number; medals: { id: string; unlocked: boolean; fts: number }[] }> {
    const pd = await this.getPlayer(uid);
    const medals = pd._playerdata.medal?.medals ?? {};
    const list = Object.values(medals)
      .map((m) => ({ id: m.id, unlocked: m.fts > 0, fts: m.fts }))
      .sort((a, b) => a.id.localeCompare(b.id));
    return {
      total: list.length,
      unlocked: list.filter((m) => m.unlocked).length,
      medals: list.slice(0, 500),
    };
  }

  /**
   * 导出用户存档到 JSON 文件（默认 ./exports/{uid}-{ts}.json）
   * @returns 导出路径与大小
   */
  async exportUser(
    uid: string,
    targetPath?: string,
  ): Promise<{ uid: string; path: string; size: number }> {
    const src = `./data/user/databases/${uid}.json`;
    if (!(await exists(src))) {
      throw new Error(`用户不存在: ${uid}（无存档文件）`);
    }
    const data = await readJson<PlayerDataModel>(src);
    const out = targetPath ?? `./exports/${uid}-${formatTs(now())}.json`;
    await mkdir(path.dirname(out), { recursive: true });
    await writeJson(out, data as any);
    const size = (await readFile(out)).length;
    await this._audit("exportUser", uid, out);
    return { uid, path: out, size };
  }

  /**
   * 从 JSON 文件导入存档（替换指定 uid；uid 缺省取文件内 status.uid）
   * @returns 目标 uid
   */
  async importUser(filePath: string, uid?: string): Promise<{ uid: string }> {
    const data = await readJson<PlayerDataModel>(filePath);
    if (!data?.status?.uid) {
      throw new Error(`存档缺少 status.uid，无法导入: ${filePath}`);
    }
    const targetUid = uid ?? String(data.status.uid);
    accountManager.data[targetUid] = new PlayerDataManager(data);
    await this.savePlayer(targetUid);
    await this._audit("importUser", targetUid, filePath);
    return { uid: targetUid };
  }

  /** 数据完整性校验：遍历已加载用户，检查 status/troop 与 JSON 可序列化 */
  async checkData(): Promise<{
    ok: boolean;
    users: { uid: string; ok: boolean; error?: string }[];
  }> {
    const uids = Object.keys(accountManager.data).sort((a, b) => Number(a) - Number(b));
    const users: { uid: string; ok: boolean; error?: string }[] = [];
    for (const uid of uids) {
      try {
        const d = accountManager.data[uid]._playerdata;
        if (!d?.status || !d?.troop) {
          throw new Error("缺少 status/troop");
        }
        // 干员结构校验（历史问题：旧生成器 currentTmpl:null 卡死——逐字段检查）
        const chars = d.troop?.chars ?? {};
        for (const [instId, ch] of Object.entries(chars)) {
          if (!ch?.charId || !excel.CharacterTable?.[ch.charId]) {
            throw new Error(`干员 instId=${instId} 缺失 charId 或不在 CharacterTable`);
          }
          for (const f of ["level", "evolvePhase", "potentialRank", "mainSkillLvl", "favorPoint", "gainTime", "voiceLan"]) {
            if ((ch as any)[f] === undefined) {
              throw new Error(`干员 ${ch.charId}(instId=${instId}) 缺少 ${f}`);
            }
          }
          if (ch.charId === "char_002_amiya" && (!ch.currentTmpl || !ch.tmpl)) {
            throw new Error("阿米娅缺少 currentTmpl/tmpl（旧生成器结构问题）");
          }
        }
        JSON.stringify(d); // 可序列化检查
        users.push({ uid, ok: true });
      } catch (e) {
        users.push({ uid, ok: false, error: (e as Error).message });
      }
    }
    return { ok: users.every((u) => u.ok), users };
  }

  /** 存档文件级校验：遍历磁盘 data/user/databases/*.json（含未加载用户），检查可解析与基本结构 */
  async checkDataFiles(): Promise<{
    ok: boolean;
    files: { uid: string; ok: boolean; error?: string }[];
  }> {
    let names: string[] = [];
    try {
      names = await readdir("./data/user/databases");
    } catch {
      return { ok: true, files: [] };
    }
    const files: { uid: string; ok: boolean; error?: string }[] = [];
    for (const name of names.filter((n) => n.endsWith(".json"))) {
      const uid = name.replace(/\.json$/, "");
      try {
        const d = await readJson<PlayerDataModel>(`./data/user/databases/${name}`);
        if (!d?.status || !d?.troop) {
          throw new Error("缺少 status/troop");
        }
        JSON.stringify(d);
        files.push({ uid, ok: true });
      } catch (e) {
        files.push({ uid, ok: false, error: (e as Error).message });
      }
    }
    return { ok: files.every((f) => f.ok), files };
  }

  /** 活动数据摘要（只读：各类型活动数） */
  async getActivitySummary(
    uid: string,
  ): Promise<{ total: number; types: { type: string; activities: number }[] }> {
    const pd = await this.getPlayer(uid);
    const act = (pd._playerdata.activity ?? {}) as Record<string, any>;
    const types = Object.entries(act)
      .map(([type, v]) => ({
        type,
        activities: v && typeof v === "object" ? Object.keys(v).length : 0,
      }))
      .filter((t) => t.activities > 0);
    return { total: types.reduce((s, t) => s + t.activities, 0), types };
  }

  /**
   * 删除用户（危险操作：删除存档文件 + 从 configs/data 移除 + saveUserConfig 同步 SQLite）
   * @param uid - 目标用户
   * @param confirmWord - 确认词，必须为 "DELETE"（防误删）
   */
  async deleteUser(uid: string, confirmWord = ""): Promise<{ uid: string }> {
    if (confirmWord !== "DELETE") {
      throw new Error("危险操作：需传 confirmWord=\"DELETE\" 确认");
    }
    if (!accountManager.configs[uid] && !accountManager.data[uid]) {
      throw new Error(`用户不存在: ${uid}`);
    }
    if (Object.keys(accountManager.data).length <= 1) {
      throw new Error("不能删除最后一个用户");
    }
    const src = `./data/user/databases/${uid}.json`;
    if (await exists(src)) {
      await rm(src);
    }
    delete accountManager.data[uid];
    delete accountManager.configs[uid];
    // saveUserConfig → upsertAll 全量同步：删除的账号从 SQLite 清除
    await accountManager.saveUserConfig();
    await this._audit("deleteUser", uid, "已删除");
    return { uid };
  }

  /**
   * 修复干员结构（对应历史"旧生成器干员结构"问题，如 check 发现的缺 voiceLan）：
   * 补齐 voiceLan/starMark/favorPoint/gainTime/skills/equip，阿米娅补 currentTmpl/tmpl 三形态。
   * @returns 修复统计 {chars: 有缺口的干员数, fields: 补全字段数}
   */
  async repairChars(uid: string): Promise<{ chars: number; fields: number }> {
    const pd = await this.getPlayer(uid);
    let chars = 0;
    let fields = 0;
    await pd.update(async (draft) => {
      for (const ch of Object.values(draft.troop?.chars ?? {})) {
        let changed = false;
        const patch = (cond: boolean, fn: () => void): void => {
          if (cond) {
            fn();
            changed = true;
            fields++;
          }
        };
        patch(ch.voiceLan === undefined, () => {
          ch.voiceLan = "CN_MANDARIN";
        });
        patch(ch.starMark === undefined, () => {
          ch.starMark = 0;
        });
        patch(ch.favorPoint === undefined, () => {
          ch.favorPoint = 0;
        });
        patch(ch.gainTime === undefined, () => {
          ch.gainTime = now();
        });
        const charData = (excel.CharacterTable as Record<string, any>)?.[ch.charId];
        patch(!ch.skills || !ch.skills.length, () => {
          const skills = buildMaxedSkills(charData);
          if (skills.length) {
            ch.skills = skills;
            ch.defaultSkillIndex = 0;
          }
        });
        patch(ch.equip === undefined, () => {
          const { ids: equipIds, equip } = buildMaxedEquip(ch.charId);
          ch.currentEquip = equipIds[0] || null;
          ch.equip = equip as any;
        });
        patch(ch.charId === "char_002_amiya" && (!ch.currentTmpl || !ch.tmpl), () => {
          const full = buildMaxedChar(Number(ch.instId), "char_002_amiya");
          ch.currentTmpl = "char_002_amiya";
          ch.tmpl = full.tmpl as any;
        });
        if (changed) chars++;
      }
    });
    await this.savePlayer(uid);
    await this._audit("repairChars", uid, `${chars} 名干员 / ${fields} 个字段`);
    return { chars, fields };
  }

  /** 玩家签到状态（只读） */
  async getCheckInState(uid: string): Promise<CheckInState> {
    const pd = await this.getPlayer(uid);
    const ci = pd._playerdata.checkIn;
    const group = excel.CheckinTable?.groups?.[ci?.checkInGroupId];
    return {
      groupId: ci?.checkInGroupId ?? "",
      groupTitle: group?.title ?? "",
      canCheckIn: ci?.canCheckIn ?? 0,
      rewardIndex: ci?.checkInRewardIndex ?? 0,
      historyCount: (ci?.checkInHistory ?? []).length,
      total: group?.items?.length ?? 0,
    };
  }

  /** 重置签到（切到当前进行中的签到组，清空进度） */
  async resetCheckIn(uid: string): Promise<CheckInState> {
    const pd = await this.getPlayer(uid);
    await pd.checkIn.monthlyRefresh();
    await this.savePlayer(uid);
    await this._audit("resetCheckIn", uid, "重置签到");
    return this.getCheckInState(uid);
  }

  /** 代签（领取当前档位奖励；当日已签返回空奖励） */
  async doCheckIn(
    uid: string,
  ): Promise<{ rewards: { id: string; name: string; count: number }[]; state: CheckInState }> {
    const pd = await this.getPlayer(uid);
    const res = await pd.checkIn.checkIn();
    await this.savePlayer(uid);
    const rewards = [...(res?.signInRewards ?? []), ...(res?.subscriptionRewards ?? [])].map(
      (r) => ({ id: r.id, name: itemName(r.id), count: r.count }),
    );
    await this._audit(
      "doCheckIn",
      uid,
      rewards.length ? `奖励 ${rewards.map((r) => `${r.name}x${r.count}`).join(",")}` : "当日已签",
    );
    return { rewards, state: await this.getCheckInState(uid) };
  }

  /**
   * 官服账号迁移（联网拉取官服数据 → 转私服存档 → 注册账号）
   * 成功后热加载新用户到内存（服务器运行中可直接使用），并写审计日志。
   * @param accountsText - 账号内容文本（每行「手机号 密码」或两行一组「手机号\n密码」）
   * @param templateUid - 模板存档 uid（私服特有字段兜底，默认 1）
   * @returns 每账号迁移结果（成功 uid/昵称，失败 error；单个失败不中断）
   */
  async migrateOfficial(
    accountsText: string,
    templateUid = "1",
  ): Promise<Awaited<ReturnType<typeof runMigration>>> {
    if (!accountsText?.trim()) {
      throw new Error("账号内容为空");
    }
    const results = await runMigration({
      accounts: accountsText,
      templateUid,
    });
    for (const r of results) {
      if (r.uid) {
        try {
          await this.reloadUser(r.uid); // 热加载到内存（服务器运行中创建后立即可用）
        } catch (e) {
          logger.warn(
            "AdminService",
            `迁移后加载用户 ${r.uid} 失败: ${(e as Error).message}`,
          );
        }
        await this._audit(
          "officialMigrate",
          r.uid,
          `${r.phone} 昵称=${r.nickName ?? ""}`,
        );
      }
    }
    return results;
  }

  /**
   * 官服操作（无状态会话：登录官服 → 执行签到/邮件等 → 即弃）
   * @param phone - 官服手机号
   * @param pwd - 官服密码
   * @param action - status/signin/mails/receive/daily
   * @returns 操作结果（失败抛错由路由层返回 400）
   */
  async officialAction(
    phone: string,
    pwd: string,
    action: OfficialAction,
  ): Promise<{ action: string; ok: boolean; data?: any; reason?: string }> {
    if (!phone || !pwd) {
      throw new Error("需提供官服手机号与密码");
    }
    const result = await runOfficialAction(String(phone), String(pwd), action);
    await this._audit(
      "officialAction",
      "",
      `${phone} → ${action}（${result.ok ? "成功" : result.reason ?? "失败"}）`,
    );
    return result;
  }

  /**
   * 官服通用 API 调用（登录后调用任意官方 cgi）
   * @param phone - 官服手机号
   * @param pwd - 官服密码
   * @param cgi - 官服接口路径（如 /user/checkIn）
   * @param body - 请求体（可选）
   * @returns 官服完整响应
   */
  async officialCall(
    phone: string,
    pwd: string,
    cgi: string,
    body?: unknown,
  ): Promise<{ cgi: string; result: any }> {
    if (!phone || !pwd) {
      throw new Error("需提供官服手机号与密码");
    }
    const result = await runOfficialCall(String(phone), String(pwd), String(cgi), body);
    await this._audit("officialCall", "", `${phone} → ${result.cgi}`);
    return result;
  }

  /**
   * 从官服同步卡池详情到 data/gacha_detail_table.json
   * @param phone - 官服手机号
   * @param pwd - 官服密码
   * @param poolIds - 目标池列表（缺省读 data/excel/gacha_table.json 的 gachaPoolClient 全部）
   * @returns 同步统计（成功合并写回，旧文件备份 .bak；重启后服务器生效）
   */
  async syncGachaPools(
    phone: string,
    pwd: string,
    poolIds?: string[],
  ): Promise<{
    total: number;
    ok: number;
    failed: { poolId: string; error: string }[];
    updated: number;
  }> {
    if (!phone || !pwd) {
      throw new Error("需提供官服手机号与密码");
    }
    // 缺省池列表：读本地 gacha_table（不依赖 excel.init）
    let targets = poolIds?.map(String).filter(Boolean) ?? [];
    if (!targets.length) {
      const table = await readJson<any>("./data/excel/gacha_table.json");
      targets = (table?.gachaPoolClient ?? []).map((p: any) => p.gachaPoolId);
    }
    if (!targets.length) {
      throw new Error("未提供 poolId 且本地 gachaPoolClient 为空");
    }
    const results = await runGachaSync(phone, pwd, targets);
    const ok = results.filter((r) => r.detailInfo);
    const failed = results
      .filter((r) => r.error)
      .map((r) => ({ poolId: r.poolId, error: r.error! }));

    // 备份旧详情表 + 合并写回（保留未抓取的池）
    const target = "./data/gacha_detail_table.json";
    if (await exists(target)) {
      await copyFile(target, `${target}.${formatTs(now())}.bak`);
    }
    const current = (await readJson<any>(target).catch(() => ({}))) ?? {};
    const details = current.details ?? {};
    for (const r of ok) {
      details[r.poolId] = r.detailInfo;
    }
    await writeJson(target, { details });
    await this._audit(
      "syncGachaPools",
      "",
      `${phone} → ${ok.length}/${results.length} 池（失败 ${failed.length}）`,
    );
    return { total: results.length, ok: ok.length, failed, updated: ok.length };
  }

  /** 统计聚合（等级分布/注册分布/资源合计） */
  async stats(): Promise<AdminStats> {
    const users = await this.listUsers();
    const levelDist: { [bucket: string]: number } = {};
    const registerDist: { [month: string]: number } = {};
    let totalChars = 0;
    let totalGold = 0;
    let totalDiamond = 0;
    let levelSum = 0;
    for (const u of users) {
      const info = await this.getUserInfo(u.uid);
      if (!info) continue;
      const bucket = `${Math.floor(info.level / 10) * 10}-${Math.floor(info.level / 10) * 10 + 9}`;
      levelDist[bucket] = (levelDist[bucket] ?? 0) + 1;
      const month = new Date(info.registerTs * 1000).toISOString().slice(0, 7);
      registerDist[month] = (registerDist[month] ?? 0) + 1;
      totalChars += info.charCnt;
      totalGold += info.gold;
      totalDiamond += info.androidDiamond;
      levelSum += info.level;
    }
    return {
      userCount: users.length,
      totalChars,
      totalGold,
      totalDiamond,
      avgLevel: users.length ? Math.round(levelSum / users.length) : 0,
      levelDist,
      registerDist,
    };
  }

  /** 审计日志（最新在前） */
  async logs(limit = 50): Promise<AuditLogEntry[]> {
    let raw = "";
    try {
      raw = await readFile(ADMIN_LOG_PATH, "utf8");
    } catch {
      return [];
    }
    const entries: AuditLogEntry[] = [];
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      try {
        entries.push(JSON.parse(line));
      } catch {
        // 跳过损坏行
      }
    }
    return entries.slice(-limit).reverse();
  }

  /** 清空审计日志（确认词保护，防误清） */
  async clearLogs(confirmWord = ""): Promise<{ cleared: number }> {
    if (confirmWord !== "CLEAR") {
      throw new Error("危险操作：需传 confirmWord=\"CLEAR\" 确认");
    }
    const before = await this.logs(100000);
    await writeFile(ADMIN_LOG_PATH, "", "utf8"); // JSONL 清空（空文件）
    await this._audit("clearLogs", "", `清空 ${before.length} 条审计日志`);
    return { cleared: before.length };
  }

  /** 常用物品别名（展示给服主参考） */
  getCommonItems(): { name: string; id: string }[] {
    return Object.entries(COMMON_ITEMS).map(([name, id]) => ({ name, id }));
  }

  /** 邮件模板列表（完整模板：供 CLI 展示与 Dashboard 填充用） */
  getMailTemplates(): { name: string; subject: string; content: string; items: { id: string; count: number }[] }[] {
    return MAIL_TEMPLATES;
  }

  /** 当前官服操作后端（自定义后端配置摘要） */
  getOfficialBackend(): {
    enabled: boolean;
    game: string;
    account: string;
    conf: string;
  } {
    return {
      enabled: config.officialBackend?.enabled === true,
      game: GAME_API,
      account: ACCOUNT_API,
      conf: CONF_API,
    };
  }

  /**
   * 创建新用户
   * 以 1 号用户数据库为模板复制，替换 uid/昵称/注册时间，写入文件并更新内存配置。
   * @param phone - 登录手机号
   * @param password - 登录密码
   * @returns 新用户 uid
   */
  async createUser(phone: string, password: string): Promise<string> {
    // 注册逻辑统一在 AccountManager（模板复制 + uid 递增 + 写文件 + 更新配置）
    const uid = await accountManager.registerUser(phone, password);
    await this._audit("createUser", uid, `${phone}`);
    return uid;
  }

  /**
   * 热加载用户到内存（服务器运行中创建用户后调用；CLI 场景无需）
   * @param uid - 用户ID
   */
  async reloadUser(uid: string): Promise<void> {
    const playerData = await readJson<PlayerDataModel>(
      `./data/user/databases/${uid}.json`,
    );
    accountManager.data[uid] = new PlayerDataManager(playerData);
  }

  /** 服务器状态 */
  async status(): Promise<ServerStatus> {
    const files = [
      "./data/config.json",
      "./data/user/users.json",
      "./data/user/mails.json",
      "./data/gacha_detail_table.json",
      "./data/rlv2.json",
    ];
    const dataFiles: ServerStatus["dataFiles"] = [];
    let totalBytes = 0;
    for (const path of files) {
      const s = (await exists(path)) ? await size(path) : 0;
      totalBytes += s;
      dataFiles.push({ path, exists: s > 0, size: s });
    }
    // 用户存档目录总量
    try {
      const dbDir = "./data/user/databases";
      if (await exists(dbDir)) {
        for (const f of await readdir(dbDir)) {
          if (f.endsWith(".json")) {
            totalBytes += (await size(`${dbDir}/${f}`)).valueOf();
          }
        }
      }
    } catch {
      // 目录不存在忽略
    }
    return {
      port: config.PORT,
      offline:
        (config as any).offline === true ||
        process.argv.includes("--offline") ||
        process.argv.includes("-o"),
      clientVersion: config.version.clientVersion,
      resVersion: config.version.resVersion,
      uptime: Math.floor(process.uptime()),
      userCount: Object.keys(accountManager.data).length,
      dataFiles,
      totalDataKB: Math.round(totalBytes / 1024),
      memoryMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
    };
  }
}

/** 管理服务全局实例 */
export const adminService = new AdminService();
