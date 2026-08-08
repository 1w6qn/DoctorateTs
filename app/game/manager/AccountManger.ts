/**
 * 账户管理类
 * 
 * 负责管理所有玩家账户的配置数据、登录验证、好友系统和战斗回放等功能。
 * 作为全局单例存在，通过 accountManager 实例访问。
 */

import { PlayerDataModel } from "../model/playerdata";
import { PlayerDataManager } from "./PlayerDataManager";
import { readJson } from "@utils/file";
import { now } from "@utils/time";
import { writeFile, rename } from "fs/promises";
import { createHash } from "crypto";
import { TypedEventEmitter } from "@game/model/events";
import Emittery from "emittery";
import { FriendRepository } from "../../db/friend-repo";
import { openDatabase } from "../../db/database";
import { ReplayRepository } from "../../db/replay-repo";
import { UserRepository, migrateUsersFromJsonFile } from "../../db/user-repo";
import config from "../../config";
import { migrateFromUserConfigs } from "../../db/migrate";
import { acquireLock } from "@utils/mutex";
import { hashPassword, verifyPassword, isHashedPassword } from "@utils/crypt";
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
  /** 用户配置仓储（SQLite，init() 中初始化——users.json 仅首次迁移种子） */
  _userRepo!: UserRepository;
  /** 战斗回放仓储（SQLite replays 表——回放独立于用户配置存储） */
  _replayRepo!: ReplayRepository;

  constructor() {
    this.configs = {};
    this.data = {};
    this._trigger = new Emittery();
  }

  /** secret→uid 索引（真实模式 getUidByToken 懒构建，避免每次请求线性扫描 configs） */
  private _secretIndex: Map<string, string> | null = null;
  /** 构建 _secretIndex 时的 configs 引用（检测 configs 被整体替换——init 重新加载/测试直接赋值时失效重建） */
  private _secretIndexConfigs: { [key: string]: UserConfig } | null = null;

  /**
   * 初始化账户管理器
   * 
   * 从 SQLite（users 表）加载用户配置（首次表空时从 users.json 种子迁移），
   * 从 data/user/databases/ 加载玩家数据。设置保存事件监听器。
   */
  async init() {
    logger.info("AccountManager", "loading users...");
    // 打开好友关系数据库（social.db 首次运行自动创建）
    this._friendRepo = new FriendRepository(openDatabase());
    this._userRepo = new UserRepository(openDatabase());
    this._replayRepo = new ReplayRepository(openDatabase());
    // 用户配置：SQLite 唯一事实源；首次（表空）从 users.json 种子迁移
    this.configs = this._userRepo.getAll();
    if (Object.keys(this.configs).length === 0) {
      await migrateUsersFromJsonFile(openDatabase(), this._userRepo);
      this.configs = this._userRepo.getAll();
    }
    this._trigger.on("save", async () => {
      await this.saveUserConfig();
    });
    // 社交数据迁移：social.db 首次创建时从 users.json 导入，之后 SQLite 为唯一事实源
    migrateFromUserConfigs(openDatabase(), this.configs);
    // 回放迁移：旧 configs 内嵌回放 → replays 表（一次性；此后 users 表/内存均不再保留回放）
    for (const [uid, conf] of Object.entries(this.configs)) {
      const replays = (conf as any).battle?.replays;
      if (replays && Object.keys(replays).length > 0) {
        for (const [stageId, replay] of Object.entries<string>(replays)) {
          this._replayRepo.upsert(uid, stageId, replay);
        }
        delete (conf as any).battle.replays;
      }
    }
    await this.saveUserConfig();
    // 并行加载所有账号（_loadPlayer 有 data[uid] 守卫且各 uid 完全独立，并发安全）
    await Promise.all(
      Object.keys(this.configs).map((uid) => this._loadPlayer(uid)),
    );
    logger.info(
      "AccountManager",
      `${Object.keys(this.configs).length} users loaded`,
    );
  }

  /**
   * 获取战斗回放数据（replays 表独立存储）
   * @param uid - 用户ID
   * @param stageId - 关卡ID
   * @returns 战斗回放数据字符串
   */
  async getBattleReplay(uid: string, stageId: string): Promise<string> {
    return this._replayRepo?.get(uid, stageId) ?? "";
  }

  /**
   * 保存战斗回放数据（replays 表独立存储——不再改写 users 表，避免大字符串全量重写配置）
   * @param uid - 用户ID
   * @param stageId - 关卡ID
   * @param replay - 战斗回放数据字符串
   */
  async saveBattleReplay(
    uid: string,
    stageId: string,
    replay: string,
  ): Promise<void> {
    this._replayRepo?.upsert(uid, stageId, replay);
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
   * 保存用户配置到 SQLite（全量同步 upsert）
   * 未 init（_userRepo 未初始化，如单测直接操作 configs）时 no-op——不污染真实库
   */
  async saveUserConfig(): Promise<void> {
    if (this._userRepo) {
      await this._userRepo.upsertAll(this.configs);
    }
  }

  /**
   * 获取战斗信息
   * @param uid - 用户ID
   * @param battleId - 战斗ID
   * @returns 战斗信息对象
   */
  async getBattleInfo(uid: string, battleId: string): Promise<BattleInfo> {
    // 防御：uid 不在 configs / battleId 不存在时返回 undefined（调用方 `!` 或 `?.` 自行处理）
    return this.configs[uid]?.battle?.infos?.[battleId] as BattleInfo;
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
   * 获取玩家数据管理器（懒加载：data 未加载时从存档文件读取——real 模式注册新账号后免重启）
   * @param uid - 用户ID
   * @returns 玩家数据管理器实例
   */
  async getPlayerData(uid: string): Promise<PlayerDataManager> {
    if (!this.data[uid]) {
      await this._loadPlayer(uid);
    }
    return this.data[uid];
  }

  /**
   * 加载玩家数据到内存（文件读取 + 事件接线；init/ensureSingleUser/懒加载共用）
   *
   * 并发安全：进行中的加载以 promise 缓存（_loadingPlayers），并发请求共享同一次加载，
   * 避免同一 uid 两个请求都过了 data[uid] 守卫、各建一个 PlayerDataManager 实例互踩。
   * @param uid - 用户ID
   * @param playerData - 可选：已有数据对象则跳过文件读取（ensureSingleUser 用）
   */
  private _loadingPlayers: { [uid: string]: Promise<void> } = {};

  private async _loadPlayer(uid: string, playerData?: PlayerDataModel): Promise<void> {
    if (this.data[uid]) return;
    if (!this._loadingPlayers[uid]) {
      this._loadingPlayers[uid] = this._doLoadPlayer(uid, playerData).finally(() => {
        delete this._loadingPlayers[uid];
      });
    }
    await this._loadingPlayers[uid];
  }

  private async _doLoadPlayer(uid: string, playerData?: PlayerDataModel): Promise<void> {
    const data =
      playerData ??
      (await readJson<PlayerDataModel>(`./data/user/databases/${uid}.json`));
    this.data[uid] = new PlayerDataManager(data);
    // 构造期子管理器可能原地初始化数据（如 rlv2 current 结构），标记脏使首个请求落盘一次
    // （与条件落盘前"每次请求都落盘"的首请求行为保持一致）
    this.data[uid].markDirty();
    // 仅当文件里的 uid 与目录键不一致时才自愈写回（文件 uid 写错）；否则纯 no-op 不落盘
    if (data.status.uid !== uid) {
      this.data[uid]._playerdata.status.uid = uid;
      void this.flushSave(uid);
    }
    this.data[uid]._trigger.on("save", () => {
      // 防抖合并：500ms 内的多次变更只落盘一次
      this.scheduleSave(uid);
    });
  }

  /**
   * 获取全部已加载账号 uid 列表
   */
  getPlayerUidList(): string[] {
    return Object.keys(this.data);
  }

  /**
   * 获取玩家社交信息（好友相关）
   * @param uid - 用户ID
   * @returns 玩家社交信息
   */
  async getPlayerFriendInfo(uid: string) {
    return (await this.getPlayerData(uid)).socialInfo;
  }

  /** 保存防抖定时器（key 为 uid） */
  private _saveTimers: { [uid: string]: NodeJS.Timeout } = {};

  /** 保存防抖窗口（毫秒） */
  private _saveDebounceMs = 500;

  /**
   * 防抖调度保存：窗口内的多次变更合并为一次落盘（原子写 + 配置保存）
   * @param uid - 用户ID
   */
  private scheduleSave(uid: string): void {
    if (this._saveTimers[uid]) return;
    this._saveTimers[uid] = setTimeout(() => {
      delete this._saveTimers[uid];
      void this.flushSave(uid);
    }, this._saveDebounceMs);
  }

  /**
   * 立即保存玩家数据（原子写 + 用户配置）
   * 服务器关闭/测试可显式调用；防抖到期也会调用
   * @param uid - 用户ID
   */
  async flushSave(uid: string): Promise<void> {
    if (this._saveTimers[uid]) {
      clearTimeout(this._saveTimers[uid]);
      delete this._saveTimers[uid];
    }
    try {
      await this.savePlayerData(uid);
      await this.saveUserConfig();
    } catch (e) {
      logger.error("AccountManager", `save ${uid} failed: ${(e as Error).message}`);
    }
  }

  /**
   * 保存玩家数据到文件（原子写：临时文件 + rename，避免写盘中断损坏存档）
   * @param uid - 用户ID
   */
  async savePlayerData(uid: string): Promise<void> {
    const finalPath = `./data/user/databases/${uid}.json`;
    const tmpPath = `${finalPath}.tmp`;
    await writeFile(tmpPath, JSON.stringify(this.data[uid]));
    await rename(tmpPath, finalPath);
  }

  /**
   * 获取抽卡保底计数
   * @param uid - 用户ID
   * @param gachaType - 抽卡类型
   * @returns 保底计数（未初始化时 0）
   */
  async getBeforeNonHitCnt(uid: string, gachaType: string): Promise<number> {
    const config = this.configs[uid];
    if (!config || !config.gacha[gachaType]) {
      return 0;
    }
    return config.gacha[gachaType].beforeNonHitCnt;
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
    const config = this.configs[uid]!;
    if (!config.gacha[gachaType]) {
      config.gacha[gachaType] = { beforeNonHitCnt: 0 };
    }
    config.gacha[gachaType].beforeNonHitCnt = cnt;
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
          data._playerdata.status.nickName == keyword ||
          data._playerdata.status.nickName + "#" + data._playerdata.status.nickNumber ==
            keyword
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
    if (config.authMode !== "real") {
      // 单例模式：任意登录返回固定账号（不查询/不注册——单账号私服）
      return config.singleUid || "1";
    }
    const found = Object.entries(this.configs).find(([, conf]) => {
      return conf.auth.phone == phone && verifyPassword(conf.password, password);
    });
    if (found) {
      // 真实模式：返回账号 secret（参考 DoctoratePy——token=secret）
      const [uid, conf] = found;
      // 旧明文账号登录成功后惰性升级为哈希（之后不再明文存储）
      if (!isHashedPassword(conf.password)) {
        conf.password = hashPassword(password);
      }
      return conf.secret || this.getTokenByUid(uid);
    }
    // 账号不存在：自动注册（私服创建新用户），返回新 uid 作为 token
    const uid = await this.registerUser(phone, password);
    return this.getTokenByUid(uid);
  }

  /**
   * 创建新用户
   * 以 1 号用户数据库为模板复制，替换 uid/昵称/注册时间，写入文件并更新内存配置。
   *
   * - single 模式：不建号（注册收敛到固定账号——避免生成永远无法登录的垃圾账号污染 configs/users 表）
   * - real 模式：并发注册以互斥锁串行化（newUid = max+1 分配，并发下会拿到相同 uid 互相覆盖）
   * @param phone - 登录手机号
   * @param password - 登录密码
   * @returns 新用户 uid
   */
  async registerUser(phone: string, password: string): Promise<string> {
    if (config.authMode === "single") {
      return config.singleUid || "1";
    }
    const release = await acquireLock("account:register");
    try {
      const phoneStr = String(phone ?? "").trim();
      if (!phoneStr) {
        throw new Error(`手机号不能为空`);
      }
      if (Object.values(this.configs).some((c) => c.auth.phone === phoneStr)) {
        throw new Error(`手机号已存在: ${phoneStr}`);
      }
      const uids = Object.keys(this.configs).map(Number);
      const newUid = String((uids.length ? Math.max(...uids) : 0) + 1);

      const templatePath = `./data/user/databases/1.json`;
      let templateData: any;
      try {
        templateData = await readJson(templatePath);
      } catch {
        throw new Error(`找不到模板存档 ${templatePath}，无法创建用户`);
      }
      const playerData = JSON.parse(JSON.stringify(templateData));
      playerData.status.uid = newUid;
      playerData.status.nickName = `博士${newUid}`;
      playerData.status.nickNumber = "1";
      playerData.status.registerTs = now();
      playerData.status.lastOnlineTs = 0;

      const userConfig: UserConfig = {
        uid: newUid,
        password: hashPassword(password), // 哈希存储（不落明文）
        secret: generateSecret(phoneStr),
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
        battle: { stageId: "", infos: {} },
        gacha: {},
        rlv2: {},
      };

      // 原子写（.tmp + rename——与 savePlayerData 一致，避免写一半崩溃留坏档）
      const finalPath = `./data/user/databases/${newUid}.json`;
      const tmpPath = `${finalPath}.tmp`;
      await writeFile(tmpPath, JSON.stringify(playerData));
      await rename(tmpPath, finalPath);
      this.configs[newUid] = userConfig;
      this._secretIndex = null; // 新增账号：secret 索引失效，下次查询重建
      await this.saveUserConfig();
      // 注册后加载玩家数据（与 ensureSingleUser 一致——searchPlayer/getPlayerData 立即可用，免重启）
      await this._loadPlayer(newUid, playerData as PlayerDataModel);
      return newUid;
    } finally {
      release();
    }
  }

  /**
   * 确保单例账号存在（不存在时以模板创建——干净账号）
   * 单例模式固定账号（config.singleUid）可能不存在（如切到 2222 过渡）
   *
   * 模板优先级：1.json → player_data.json（官服满配基底）→ 报错。
   * 1.json 缺失或结构过期时回退 player_data.json；随后 index.ts 的 generateMaxedAccount
   * 会按版本刷新内容字段（S1 合并式刷新），故模板结构差异会被自动纠正。
   * @param uid - 单例账号 uid
   */
  async ensureSingleUser(uid: string): Promise<void> {
    if (this.configs[uid]) return;
    const templatePath = `./data/user/databases/1.json`;
    let templateData: any;
    try {
      templateData = await readJson(templatePath);
    } catch {
      // 1.json 缺失：回退 player_data.json 官服基底（结构更完整）
      templateData = await readJson<any>("./player_data.json").catch(() => null);
      if (!templateData) {
        throw new Error(
          `找不到模板存档 ${templatePath}（player_data.json 亦缺失），无法创建账号`,
        );
      }
    }
    const playerData = JSON.parse(JSON.stringify(templateData));
    playerData.status.uid = uid;
    playerData.status.nickName = `博士${uid}`;
    playerData.status.nickNumber = "1";
    playerData.status.registerTs = now();
    playerData.status.lastOnlineTs = 0;

    const userConfig: UserConfig = {
      uid,
      password: hashPassword("single"),
      secret: generateSecret(`single_${uid}`),
      auth: {
        hgId: uid,
        phone: uid,
        email: "",
        identityNum: "doctorate",
        identityName: "doctorate",
        isMinor: false,
        isLatestUserAgreement: true,
      },
      social: { friends: [], friendRequests: [], visited: [] },
      battle: { stageId: "", infos: {} },
      gacha: {},
      rlv2: {},
    };

    // 原子写（.tmp + rename——与 savePlayerData 一致，避免写一半崩溃留坏档）
    const finalPath = `./data/user/databases/${uid}.json`;
    const tmpPath = `${finalPath}.tmp`;
    await writeFile(tmpPath, JSON.stringify(playerData));
    await rename(tmpPath, finalPath);
    this.configs[uid] = userConfig;
    this._secretIndex = null; // 新增账号：secret 索引失效，下次查询重建
    await this.saveUserConfig();

    // 加载玩家数据（与 init 一致——getPlayerData 可用；直接使用内存 playerData，避免重读文件）
    await this._loadPlayer(uid, playerData as PlayerDataModel);
  }

  /**
   * 通过uid获取Token（真实模式：账号 secret；旧账号无 secret 回退 uid）
   * @param uid - 用户ID
   * @returns 用户Token（secret 或 uid）
   */
  async getTokenByUid(uid: string): Promise<string> {
    return this.configs[uid]?.secret || uid;
  }

  /**
   * 通过Token获取uid
   * @param token - 用户Token（uid 或账号 secret）
   * @returns 用户ID（匹配 uid 或 secret；无效返回空串）
   */
  async getUidByToken(token: string): Promise<string> {
    if (config.authMode === "real") {
      // 真实模式：token 匹配账号 secret（参考 DoctoratePy query_account_by_secret）
      // 收紧：有 secret 的账号必须以 secret 登录（防止 uid 数字直通枚举冒用）；
      // 仅无 secret 的旧账号保留 uid 直通（兼容迁移前账号）
      if (this.configs[token] && !this.configs[token].secret) return token;
      // 懒构建 secret→uid 索引；configs 被整体替换（init/直接赋值）或新增账号（register/ensure）后失效重建
      if (!this._secretIndex || this._secretIndexConfigs !== this.configs) {
        this._secretIndexConfigs = this.configs;
        this._secretIndex = new Map<string, string>();
        for (const uid of Object.keys(this.configs)) {
          const secret = this.configs[uid]?.secret;
          if (secret && !this._secretIndex.has(secret)) {
            this._secretIndex.set(secret, uid);
          }
        }
      }
      return this._secretIndex.get(token) ?? "";
    }
    // 单例模式：任意 token 收敛到固定账号（oauth2/basic/u8 全流程返回单例 uid）。
    // 语义契约：single 下 token=secret=uid 三者语义统一（middleware 会强制覆盖 secret header），
    // real 下 token 为账号 secret（旧账号无 secret 回退 uid）。
    return config.singleUid || "1";
  }
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

/** 账号密钥渠道常量（参考 DoctoratePy USER_TOKEN_KEY——官方 appCode） */
const USER_TOKEN_KEY = "7318def77669979d";

/**
 * 生成账号密钥（参考 DoctoratePy user.py：MD5(account + 渠道密钥)——确定性）
 * @param phone - 注册手机号
 */
export function generateSecret(phone: string): string {
  return createHash("md5").update(`${phone}${USER_TOKEN_KEY}`).digest("hex");
}

/**
 * 用户配置接口
 * 
 * 存储用户的账户认证、社交、战斗、抽卡等配置信息。
 */
export interface UserConfig {
  uid: string;
  password: string;
  /** 账号密钥（参考 DoctoratePy：MD5(phone + 渠道密钥)，真实模式 token 用） */
  secret?: string;
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
    // 回放独立存于 replays 表（R4）——configs 不再携带 replays
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
  /** 助战好友信息（编队借用好友干员） */
  assistFriend?: {
    uid: string;
    nickName: string;
    assistChar: { charId: string; level?: number }[];
    assistSlotIndex: number;
  } | null;
}

/** 账户管理器全局实例 */
export const accountManager = new AccountManager();