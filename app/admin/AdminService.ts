/**
 * 管理服务层
 *
 * 供 CLI 与 HTTP 管理接口共用的纯逻辑层：
 * 用户管理、物品/干员/皮肤发放、干员属性编辑、一键满配、基建满级、
 * 备份/回滚、邮件（单发/群发/查看/删除）、每日刷新、原始 JSON、统计与审计日志。
 * 所有数据操作均基于本地 JSON（AccountManager / mailManager），离线可用。
 */
import { appendFile, copyFile, mkdir, readFile, readdir } from "fs/promises";
import excel from "@excel/excel";
import { getRoomPhase } from "@excel/building_excel";
import { buildMaxedSkills, buildMaxedEquip } from "@game/maxout";
import { accountManager } from "@game/manager/AccountManger";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { PlayerDataModel } from "@game/model/playerdata";
import { mailManager } from "@game/manager/mail";
import { exists, size, readJson } from "@utils/file";
import { now } from "@utils/time";
import { logger } from "@utils/logger";
import {
  itemName,
  charName,
  skinName,
  resolveItemRef,
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

  /** 审计日志：追加一行 JSONL（失败不阻断业务操作） */
  private async _audit(action: string, uid: string, detail: string): Promise<void> {
    try {
      await mkdir("./data/admin", { recursive: true });
      await appendFile(
        ADMIN_LOG_PATH,
        JSON.stringify({ ts: now(), action, uid, detail }) + "\n",
        "utf8",
      );
    } catch (e) {
      logger.warn("AdminService", `审计日志写入失败: ${(e as Error).message}`);
    }
  }

  /** 用户列表（按 uid 排序） */
  async listUsers(): Promise<UserSummary[]> {
    return Object.keys(accountManager.data)
      .sort((a, b) => Number(a) - Number(b))
      .map((uid) => toUserSummary(uid, accountManager.data[uid]));
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
    const resolved = (excel.CharacterTable as Record<string, any>)[charId]
      ? charId
      : this.resolveCharByName(charId);
    if (!resolved) {
      throw new Error(`未知干员: ${charId}`);
    }
    const pd = await this.getPlayer(uid);
    // 直接调用 onCharGet（char:get 事件监听为无操作，见 char.ts 构造器）
    const res = await pd.char.onCharGet([resolved, { from: "ADMIN" }]);
    await this.savePlayer(uid);
    await this._audit("grantChar", uid, `${resolved}(${charName(resolved)})`);
    return { isNew: res?.isNew ?? 0, name: charName(resolved) };
  }

  /** 按中文名反查干员 ID（精确匹配；无结果返回空串） */
  private resolveCharByName(name: string): string {
    for (const [charId, info] of Object.entries(excel.CharacterTable as Record<string, any>)) {
      if (info?.name === name) return charId;
    }
    return "";
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
          rarity: info?.rarity ?? 0,
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

  /** 常用物品别名（展示给服主参考） */
  getCommonItems(): { name: string; id: string }[] {
    return Object.entries(COMMON_ITEMS).map(([name, id]) => ({ name, id }));
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
    for (const path of files) {
      dataFiles.push({
        path,
        exists: await exists(path),
        size: (await exists(path)) ? await size(path) : 0,
      });
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
    };
  }
}

/** 管理服务全局实例 */
export const adminService = new AdminService();
