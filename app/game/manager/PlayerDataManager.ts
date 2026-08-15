/**
 * 玩家数据管理器类
 *
 * 作为单个玩家数据的核心管理类，负责协调玩家的所有子系统（背包、队伍、地牢、基建等）。
 * 状态引擎（Immer draft 生命周期、patch 聚合、序列化）已拆分至 PlayerStatus，
 * 本类退化为组合根：持有子管理器、事件总线与序列化入口，并委托状态操作。
 */

import { PlayerDataModel } from "../model/playerdata";
import { InventoryManager } from "./inventory";
import { TroopManager } from "./troop";
import { DungeonManager } from "./dungeon";
import { HomeManager } from "./home";
import { StatusManager } from "./status";
import { CheckInManager } from "./checkin";
import { StoryreviewManager } from "./storyreview";
import { MissionManager } from "./mission";
import ShopController from "../controller/shop";
import { RecruitManager } from "./recruit";
import { RoguelikeV2Controller } from "../controller/rlv2";
import { BattleManager } from "./battle";
import { GachaController } from "../controller/gacha";
import { SocialManager } from "./social";
import { DexNavManager } from "./dexnav";
import { MedalManager } from "./medal";
import { BuildingManager } from "./building";
import { FriendDataWithNameCard, FriendMedalBoard } from "@game/model/social";
import { OpenServerManager } from "@game/manager/activity/openServer";
import { PlayerStatus } from "./PlayerStatus";
import { BattleInfo, BattleInfoStore } from "./BattleInfoStore";
import { Draft } from "mutative";
import { logger } from "@utils/logger";
import { TypedEventEmitter } from "@game/model/events";
import { CharRotationManager } from "@game/manager/charRotation";
import { RetroManager } from "@game/manager/retro";
import { CharManager } from "@game/manager/char";
import { AprilFoolManager } from "@game/manager/aprilFool";

export class PlayerDataManager {
  /** 状态引擎（Immer 状态管理、patch 聚合、序列化） */
  playerStatus: PlayerStatus;
  /** 地牢管理器 */
  dungeon: DungeonManager;
  /** 背包管理器 */
  inventory: InventoryManager;
  /** 队伍管理器 */
  troop: TroopManager;
  /** 状态管理器 */
  status: StatusManager;
  /** 家园管理器 */
  home: HomeManager;
  /** 角色轮换管理器 */
  charRotation: CharRotationManager;
  /** 签到管理器 */
  checkIn: CheckInManager;
  /** 剧情回顾管理器 */
  storyreview: StoryreviewManager;
  /** 任务管理器 */
  mission!: MissionManager;
  /** 商店控制器 */
  shop: ShopController;
  /** 招募管理器 */
  recruit: RecruitManager;
  /** 肉鸽V2控制器 */
  rlv2: RoguelikeV2Controller;
  /** 抽卡控制器 */
  gacha: GachaController;
  /** 社交管理器 */
  social: SocialManager;
  /** 索引导航管理器 */
  dexNav: DexNavManager;
  /** 基建管理器 */
  building: BuildingManager;
  /** 开服活动管理器 */
  openServer: OpenServerManager;
  /** 怀旧活动管理器 */
  retro: RetroManager;
  /** 角色管理器 */
  char: CharManager;
  /** 勋章管理器 */
  medal: MedalManager;
  /** 愚人节活动管理器 */
  aprilFool: AprilFoolManager;
  /** 战斗管理器 */
  battle!: BattleManager;
  /** 事件触发器 */
  _trigger: TypedEventEmitter;
  /** 战斗信息存储（构造器注入，解耦 AccountManager） */
  private _battleStore: BattleInfoStore;

  /**
   * 构造函数
   * @param playerdata - 玩家数据模型
   * @param battleStore - 战斗信息存储（默认 no-op，由 AccountManager 注入）
   */
  constructor(playerdata: PlayerDataModel, battleStore?: BattleInfoStore) {
    this.playerStatus = new PlayerStatus(playerdata);
    this._battleStore = battleStore ?? {
      getBattleInfo: async () => undefined as unknown as BattleInfo,
      saveBattleInfo: async () => {},
    };
    this._trigger = new TypedEventEmitter();
    this.status = new StatusManager(this, this._trigger);
    this.inventory = new InventoryManager(this, this._trigger);
    this.troop = new TroopManager(this, this._trigger);
    this.dungeon = new DungeonManager(this, this._trigger);
    this.home = new HomeManager(this, this._trigger);
    this.charRotation = new CharRotationManager(this, this._trigger);
    this.checkIn = new CheckInManager(this, this._trigger);
    this.storyreview = new StoryreviewManager(this, this._trigger);
    this.mission = new MissionManager(this, this._trigger);
    // init 的 promise 暴露给外部（AccountManager 加载后先 await 再播种活动任务，
    // 避免 MissionManager.init 的 missions["ACTIVITY"] = {} 清掉已播种条目）
    this.mission.initPromise = this.mission
      .init()
      .catch((e) => logger.error("MissionManager", `init failed: ${(e as Error).message}`));
    this.shop = new ShopController(this, this._trigger);
    this.battle = new BattleManager(this, this._trigger);
    this.recruit = new RecruitManager(this, this._trigger);
    this.rlv2 = new RoguelikeV2Controller(this, this._trigger);
    this.social = new SocialManager(this, this._trigger);
    this.gacha = new GachaController(this, this._trigger);
    this.dexNav = new DexNavManager(this, this._trigger);
    this.building = new BuildingManager(this, this._trigger);
    this.openServer = new OpenServerManager(this, this._trigger);
    this.retro = new RetroManager(this, this._trigger);
    this.char = new CharManager(this, this._trigger);
    this.medal = new MedalManager(this, this._trigger);
    void this.medal.init().catch((e) => logger.error("MedalManager", `init failed: ${(e as Error).message}`));
    this.aprilFool = new AprilFoolManager(this, this._trigger);
    this._trigger.on(
      "save:battle",
      async ([battleId, info]: [string, BattleInfo]) => {
        await this._battleStore.saveBattleInfo(this.uid, battleId, info);
      },
    );
  }

  /**
   * 获取玩家原始数据模型（只读 getter，委托状态引擎）
   *
   * 供子管理器与序列化读取；状态变更一律通过 update()/markDirty()。
   */
  get _playerdata(): PlayerDataModel {
    return this.playerStatus._playerdata;
  }

  /**
   * 获取增量更新数据
   *
   * 委托 PlayerStatus 计算增量并清空变更，仅当有变更时触发保存事件。
   * @returns 包含 playerDataDelta 的增量数据
   */
  get delta() {
    const { playerDataDelta, changed } = this.playerStatus.delta;
    if (changed) {
      this._trigger.emit("save", []);
    }
    return {
      playerDataDelta,
    };
  }

  /**
   * 获取用户ID
   * @returns 用户ID
   */
  get uid(): string {
    return this.playerStatus.uid;
  }

  /**
   * 会话时间戳（syncData 每次同步刷新为 now()）
   *
   * 用作战斗数据加解密（decryptBattleData/encryptBattleData）的密钥种子。
   * @returns 会话锚点时间戳
   */
  get loginTime(): number {
    return this.playerStatus.loginTime;
  }

  /**
   * 获取玩家社交信息（用于好友展示）
   *
   * 包含昵称、等级、助战角色、勋章板等信息。
   * @returns 玩家社交信息对象
   */
  get socialInfo(): FriendDataWithNameCard {
    const pd = this.playerStatus._playerdata;
    let medalBoard: FriendMedalBoard;
    if (pd.social.medalBoard.custom) {
      medalBoard = {
        custom: pd.medal.custom.customs[pd.social.medalBoard.custom],
        type: pd.social.medalBoard.type,
        template: null,
      };
    } else {
      medalBoard = {
        custom: null,
        type: pd.social.medalBoard.type,
        template: {
          groupId: pd.social.medalBoard.template!,
          medalList: pd.social.medalBoard.templateMedalList!,
        },
      };
    }
    const assistCharList = pd.social.assistCharList.map((char) => {
      const charInfo = pd.troop.chars[char.charInstId];
      const res = {
        charId: charInfo.charId,
        skinId: charInfo.skin,
        skills: charInfo.skills,
        mainSkillLvl: charInfo.mainSkillLvl,
        skillIndex: char.skillIndex,
        evolvePhase: charInfo.evolvePhase,
        favorPoint: charInfo.favorPoint,
        potentialRank: charInfo.potentialRank,
        level: charInfo.level,
        crisisRecord: {},
        crisisV2Record: {},
        currentEquip: char.currentEquip,
        equip: charInfo.equip,
      };
      if (char?.currentTmpl) {
        return Object.assign({}, res, {
          currentTmpl: char.currentTmpl,
          tmpl: charInfo.tmpl!,
        });
      } else {
        return res;
      }
    });
    return {
      nickName: pd.status.nickName,
      nickNumber: pd.status.nickNumber,
      uid: this.uid,
      registerTs: pd.status.registerTs,
      mainStageProgress: pd.status.mainStageProgress,
      charCnt: pd.troop.curCharInstId - 1,
      furnCnt: this.building.furnCnt,
      skinCnt: this.inventory.skinCnt,
      secretary: pd.status.secretary,
      secretarySkinId: pd.status.secretarySkinId,
      resume: pd.status.resume,
      teamV2: this.dexNav.teamV2Info,
      serverName: pd.status.serverName,
      level: pd.status.level,
      avatar: pd.status.avatar,
      assistCharList: assistCharList,
      lastOnlineTime: pd.status.lastOnlineTs,
      board: this.building.boardInfo,
      infoShare: this.building.infoShare,
      recentVisited: 0,
      skin: {
        selected: pd.nameCardStyle.skin.selected,
        state: {},
      },
      birthday: pd.status.birthday,
      medalBoard: medalBoard,
      nameCardStyle: pd.nameCardStyle,
    };
  }

  /**
   * 标记直接变更（绕过 update() 的原地修改，委托状态引擎）
   */
  markDirty(): void {
    this.playerStatus.markDirty();
  }

  /**
   * 更新玩家数据（使用 mutative，委托状态引擎）
   *
   * 通过传入的 recipe 函数修改数据，自动记录变更补丁（嵌套 update 复用当前 draft）。
   * @param recipe - 数据修改函数
   * @returns recipe 函数的返回值
   */
  async update<T>(
    recipe: (draft: Draft<PlayerDataModel>) => Promise<T>,
  ): Promise<T> {
    return this.playerStatus.update(recipe);
  }

  /**
   * 追加一个强制补丁（委托状态引擎）
   *
   * 供 update() recipe 内主动注入 Immer 无法产生的增量（如 building.event），
   * 避免子管理器直接访问已迁移的 _changes 私有字段。
   * @param path - 补丁路径（如 ["event", "building"]）
   * @param value - 补丁值
   */
  forcePatch(path: (string | number)[], value: unknown): void {
    this.playerStatus.forcePatch(path, value);
  }

  /**
   * 获取战斗信息
   * @param battleId - 战斗ID
   * @returns 战斗信息对象
   */
  async getBattleInfo(battleId: string): Promise<BattleInfo> {
    return (await this._battleStore.getBattleInfo(this.uid, battleId))!;
  }

  /**
   * 序列化为JSON（委托状态引擎）
   * @returns 玩家数据模型对象
   */
  toJSON(): PlayerDataModel {
    return this.playerStatus.toJSON();
  }

  /**
   * 预序列化 JSON 字符串（B4 响应缓存，委托状态引擎）
   */
  toJSONString(): string {
    return this.playerStatus.toJSONString();
  }
}