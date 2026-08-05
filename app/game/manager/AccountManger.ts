/**
 * 账户管理类
 * 
 * 负责管理所有玩家账户的配置数据、登录验证、好友系统和战斗回放等功能。
 * 作为全局单例存在，通过 accountManager 实例访问。
 */

import { PlayerDataModel } from "../model/playerdata";
import { PlayerDataManager } from "./PlayerDataManager";
import { readJson } from "@utils/file";
import { writeFile } from "fs/promises";
import { TypedEventEmitter } from "@game/model/events";
import Emittery from "emittery";
import { FriendRepository } from "../../db/friend-repo";
import { openDatabase } from "../../db/database";
import { migrateFromUserConfigs } from "../../db/migrate";
import { logger } from "@utils/logger";

export class AccountManager {
  /** 玩家数据管理器映射，key为uid */
  data: { [key: string]: PlayerDataManager };
  /** 用户配置数据映射，key为uid */
  configs: { [key: string]: UserConfig };
  /** 事件触发器 */
  _trigger: TypedEventEmitter;
  /** 好友关系仓储（SQLite，init() 中初始化，避免模块加载时创建数据库文件） */
  _friendRepo!: FriendRepository;

  constructor() {
    this.configs = {};
    this.data = {};
    this._trigger = new Emittery();
  }

  /**
   * 初始化账户管理器
   * 
   * 从 data/user/users.json 加载用户配置，从 data/user/databases/ 加载玩家数据。
   * 设置保存事件监听器。
   */
  async init() {
    logger.info("AccountManager", "loading users...");
    // 打开好友关系数据库（social.db 首次运行自动创建）
    this._friendRepo = new FriendRepository(openDatabase());
    this.configs = await readJson(`./data/user/users.json`);
    this._trigger.on("save", async () => {
      await this.saveUserConfig();
    });
    // 社交数据迁移：social.db 首次创建时从 users.json 导入，之后 SQLite 为唯一事实源
    migrateFromUserConfigs(openDatabase(), this.configs);
    await this.saveUserConfig();
    for (const uid in this.configs) {
      this.data[uid] = new PlayerDataManager(
        await readJson<PlayerDataModel>(`./data/user/databases/${uid}.json`),
      );
      this.data[uid]._playerdata.status.uid = uid;
      this.data[uid]._trigger.on("save", async () => {
        await this.savePlayerData(uid);
        await this.saveUserConfig();
      });
    }
    logger.info(
      "AccountManager",
      `${Object.keys(this.configs).length} users loaded`,
    );
  }

  /**
   * 获取战斗回放数据
   * @param uid - 用户ID
   * @param stageId - 关卡ID
   * @returns 战斗回放数据字符串
   */
  async getBattleReplay(uid: string, stageId: string): Promise<string> {
    return this.configs[uid]?.battle.replays[stageId] || "";
  }

  /**
   * 保存战斗回放数据
   * @param uid - 用户ID
   * @param stageId - 关卡ID
   * @param replay - 战斗回放数据字符串
   */
  async saveBattleReplay(
    uid: string,
    stageId: string,
    replay: string,
  ): Promise<void> {
    this.configs[uid]!.battle.replays[stageId] = replay;
    await this._trigger.emit("save", []);
  }

  /**
   * 获取用户配置
   * @param uid - 用户ID
   * @returns 用户配置对象
   */
  async getUserConfig(uid: string): Promise<UserConfig> {
    return this.configs[uid]!;
  }

  /**
   * 保存用户配置到文件
   */
  async saveUserConfig(): Promise<void> {
    await writeFile(
      `./data/user/users.json`,
      JSON.stringify(this.configs, null, 4),
    );
  }

  /**
   * 获取战斗信息
   * @param uid - 用户ID
   * @param battleId - 战斗ID
   * @returns 战斗信息对象
   */
  async getBattleInfo(uid: string, battleId: string): Promise<BattleInfo> {
    return this.configs[uid]!.battle.infos[battleId];
  }

  /**
   * 保存战斗信息
   * @param uid - 用户ID
   * @param battleId - 战斗ID
   * @param info - 战斗信息对象
   */
  async saveBattleInfo(
    uid: string,
    battleId: string,
    info: BattleInfo,
  ): Promise<void> {
    this.configs[uid]!.battle.infos[battleId] = info;
    await this._trigger.emit("save", []);
  }

  /**
   * 获取玩家数据管理器
   * @param uid - 用户ID
   * @returns 玩家数据管理器实例
   */
  async getPlayerData(uid: string): Promise<PlayerDataManager> {
    return this.data[uid];
  }

  /**
   * 获取玩家社交信息（好友相关）
   * @param uid - 用户ID
   * @returns 玩家社交信息
   */
  async getPlayerFriendInfo(uid: string) {
    return (await this.getPlayerData(uid)).socialInfo;
  }

  /**
   * 保存玩家数据到文件
   * @param uid - 用户ID
   */
  async savePlayerData(uid: string): Promise<void> {
    await writeFile(
      `./data/user/databases/${uid}.json`,
      JSON.stringify(this.data[uid], null, 4),
    );
  }

  /**
   * 获取抽卡保底计数
   * @param uid - 用户ID
   * @param gachaType - 抽卡类型
   * @returns 保底计数
   */
  async getBeforeNonHitCnt(uid: string, gachaType: string): Promise<number> {
    return this.configs[uid]!.gacha[gachaType].beforeNonHitCnt;
  }

  /**
   * 保存抽卡保底计数
   * @param uid - 用户ID
   * @param gachaType - 抽卡类型
   * @param cnt - 保底计数
   */
  async saveBeforeNonHitCnt(
    uid: string,
    gachaType: string,
    cnt: number,
  ): Promise<void> {
    this.configs[uid]!.gacha[gachaType].beforeNonHitCnt = cnt;
    await this._trigger.emit("save", []);
  }

  /**
   * 获取社交信息（好友列表、好友请求、访问记录）
   * @param uid - 用户ID
   * @returns 社交信息对象
   */
  async getSocial(uid: string): Promise<{
    friends: { uid: string; alias: string }[];
    friendRequests: string[];
    visited: string[];
  }> {
    return {
      friends: this._friendRepo.getFriendList(uid),
      friendRequests: this._friendRepo.getFriendRequests(uid),
      visited: this._friendRepo.getVisited(uid),
    };
  }

  /**
   * 删除好友（双向删除：双方好友列表都移除对方）
   * @param uid - 用户ID
   * @param friendUid - 好友用户ID
   */
  async deleteFriend(uid: string, friendUid: string): Promise<void> {
    this._friendRepo.deleteFriend(uid, friendUid);
    this._friendRepo.deleteFriend(friendUid, uid);
    await this._trigger.emit("save", []);
  }

  /**
   * 添加好友（单向；双向关系由调用方决定，如 processFriendRequest）
   * @param uid - 用户ID
   * @param friendUid - 好友用户ID
   */
  async addFriend(uid: string, friendUid: string): Promise<void> {
    this._friendRepo.addFriend(uid, friendUid);
    await this._trigger.emit("save", []);
  }

  /**
   * 发送好友请求（带校验：不能给自己发、已是好友拒绝、重复申请拒绝）
   * @param from - 发送请求的用户ID
   * @param to - 接收请求的用户ID
   */
  async sendFriendRequest(from: string, to: string): Promise<void> {
    if (from === to) {
      throw new Error("不能向自己发送好友请求");
    }
    if (this._friendRepo.hasFriend(from, to)) {
      throw new Error("对方已是你的好友");
    }
    if (this._friendRepo.hasFriendRequest(to, from)) {
      throw new Error("好友请求已发送，请勿重复发送");
    }
    this._friendRepo.sendFriendRequest(from, to);
    const friendData = await this.getPlayerData(to);
    await friendData.update(async (draft) => {
      draft.pushFlags.hasFriendRequest = 1;
    });
    await this._trigger.emit("save", []);
  }

  /**
   * 删除好友请求
   * @param uid - 用户ID
   * @param friendId - 发起请求的用户ID
   */
  async deleteFriendRequest(uid: string, friendId: string): Promise<void> {
    this._friendRepo.deleteFriendRequest(uid, friendId);
    await this._trigger.emit("save", []);
  }

  /**
   * 设置好友别名
   * @param uid - 用户ID
   * @param friendId - 好友用户ID
   * @param alias - 别名
   */
  async setFriendAlias(
    uid: string,
    friendId: string,
    alias: string,
  ): Promise<void> {
    this._friendRepo.setFriendAlias(uid, friendId, alias);
    await this._trigger.emit("save", []);
  }

  /**
   * 获取好友请求列表
   * @param uid - 用户ID
   * @returns 好友请求用户ID列表
   */
  async getFriendRequests(uid: string): Promise<string[]> {
    return this._friendRepo.getFriendRequests(uid);
  }

  /**
   * 搜索玩家
   * @param keyword - 搜索关键词（支持uid、昵称、昵称#数字）
   * @returns 匹配的用户ID列表
   */
  async searchPlayer(keyword: string): Promise<string[]> {
    return Object.entries(this.data)
      .filter(([uid, data]) => {
        return (
          keyword.includes(uid) ||
          data.socialInfo.nickName == keyword ||
          data.socialInfo.nickName + "#" + data.socialInfo.nickNumber == keyword
        );
      })
      .map(([uid]) => uid);
  }

  /**
   * 通过手机号和密码获取Token
   * @param phone - 用户手机号
   * @param password - 用户密码
   * @returns 用户Token（即uid）
   */
  async tokenByPhonePassword(phone: string, password: string): Promise<string> {
    const uid =
      Object.entries(this.configs).find(([, conf]) => {
        return conf.auth.phone == phone && conf.password == password;
      })?.[0] ?? "";
    return this.getTokenByUid(uid);
  }

  /**
   * 通过uid获取Token
   * @param uid - 用户ID
   * @returns 用户Token（即uid）
   */
  async getTokenByUid(uid: string): Promise<string> {
    return uid;
  }

  /**
   * 通过Token获取uid
   * @param token - 用户Token
   * @returns 用户ID（即token）
   */
  async getUidByToken(token: string): Promise<string> {
    return token;
  }

  /** 登出方法（预留） */
  async loginout() {}
}

/**
 * 好友排序视图模型
 */
export interface FriendSortViewModel {
  uid: string;
  level: number;
  infoShare?: number;
  infoShareVisited?: number;
  recentVisited?: number;
}

/**
 * 用户配置接口
 * 
 * 存储用户的账户认证、社交、战斗、抽卡等配置信息。
 */
export interface UserConfig {
  uid: string;
  password: string;
  auth: {
    hgId: string;
    phone: string;
    email: string;
    identityNum: string;
    identityName: string;
    isMinor: false;
    isLatestUserAgreement: true;
  };
  social: {
    friends: { uid: string; alias: string }[];
    friendRequests: string[];
    visited: string[];
  };
  battle: {
    stageId: string;
    replays: { [key: string]: string };
    infos: { [key: string]: BattleInfo };
  };
  gacha: {
    [key: string]: {
      beforeNonHitCnt: number;
    };
  };
  rlv2: object;
}

/**
 * 战斗信息接口
 */
export interface BattleInfo {
  stageId: string;
  isPractice: number;
  /** 出战编队（用于结算信赖等后处理） */
  squad?: { slots: ({ charInstId: number } | null)[] };
}

/** 账户管理器全局实例 */
export const accountManager = new AccountManager();