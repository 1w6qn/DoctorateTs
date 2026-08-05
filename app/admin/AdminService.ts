/**
 * 管理服务层
 *
 * 供 CLI 与 HTTP 管理接口共用的纯逻辑层：
 * 用户管理、物品发放、邮件发送、服务器状态。
 * 所有数据操作均基于本地 JSON（AccountManager / mailManager），离线可用。
 */
import { accountManager, UserConfig } from "@game/manager/AccountManger";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { PlayerDataModel } from "@game/model/playerdata";
import { mailManager } from "@game/manager/mail";
import { exists, size, readJson, writeJson } from "@utils/file";
import { now } from "@utils/time";
import config from "../config";

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

export class AdminService {
  /** 玩家数据快照（grant 等写操作后的落盘） */
  private async savePlayer(uid: string): Promise<void> {
    await accountManager.savePlayerData(uid);
    await accountManager.saveUserConfig();
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
      inventory: pd._playerdata.inventory,
    };
  }

  /**
   * 发放物品/资源
   * @param uid - 目标用户ID
   * @param itemId - 物品ID（如 4001=金币、5001=合成玉）
   * @param count - 数量（正整数）
   */
  async grantItem(uid: string, itemId: string, count: number): Promise<void> {
    if (!Number.isInteger(count) || count <= 0) {
      throw new Error(`数量必须为正整数，收到: ${count}`);
    }
    const pd = accountManager.data[uid];
    if (!pd) {
      throw new Error(`用户不存在: ${uid}`);
    }
    await pd.inventory.gainItem({ id: itemId, count });
    await this.savePlayer(uid);
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
    return mailManager.sendMail(uid, {
      subject: args.subject,
      content: args.content,
      items,
    });
  }

  /**
   * 创建新用户
   * 以 1 号用户数据库为模板复制，替换 uid/昵称/注册时间，写入文件并更新内存配置。
   * @param phone - 登录手机号
   * @param password - 登录密码
   * @returns 新用户 uid
   */
  async createUser(phone: string, password: string): Promise<string> {
    const phoneStr = String(phone ?? "").trim();
    if (!phoneStr) {
      throw new Error(`手机号不能为空`);
    }
    if (Object.values(accountManager.configs).some((c) => c.auth.phone === phoneStr)) {
      throw new Error(`手机号已存在: ${phoneStr}`);
    }
    const uids = Object.keys(accountManager.configs).map(Number);
    const newUid = String((uids.length ? Math.max(...uids) : 0) + 1);

    const templatePath = `./data/user/databases/1.json`;
    if (!(await exists(templatePath))) {
      throw new Error(`找不到模板存档 ${templatePath}，无法创建用户`);
    }
    const templateData = await readJson<any>(templatePath);
    const playerData = JSON.parse(JSON.stringify(templateData));
    playerData.status.uid = newUid;
    playerData.status.nickName = `博士${newUid}`;
    playerData.status.nickNumber = "1";
    playerData.status.registerTs = now();
    playerData.status.lastOnlineTs = 0;

    const userConfig: UserConfig = {
      uid: newUid,
      password,
      auth: {
        hgId: newUid,
        phone: phoneStr,
        email: "",
        identityNum: "doctorate",
        identityName: "doctorate",
        isMinor: false,
        isLatestUserAgreement: true,
      },
      social: { friends: [], friendRequests: [], visited: [] },
      battle: { stageId: "", replays: {}, infos: {} },
      gacha: {},
      rlv2: {},
    };

    await writeJson(`./data/user/databases/${newUid}.json`, playerData);
    accountManager.configs[newUid] = userConfig;
    await accountManager.saveUserConfig();
    return newUid;
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
