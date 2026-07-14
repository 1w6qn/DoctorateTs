/**
 * 玩家数据管理器类
 * 
 * 作为单个玩家数据的核心管理类，负责协调玩家的所有子系统（背包、队伍、地牢、基建等）。
 * 使用 Immer 进行状态管理，支持增量更新和撤销操作。
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
import { accountManager, BattleInfo } from "./AccountManger";
import { SocialManager } from "./social";
import { DexNavManager } from "./dexnav";
import { BuildingManager } from "./building";
import { FriendDataWithNameCard, FriendMedalBoard } from "@game/model/social";
import { OpenServerManager } from "@game/manager/activity/openServer";
import { createDraft, finishDraft, Patch, WritableDraft } from "immer";
import { patchesToObject } from "@utils/delta";
import { TypedEventEmitter } from "@game/model/events";
import { CharRotationManager } from "@game/manager/charRotation";
import { RetroManager } from "@game/manager/retro";
import { CharManager } from "@game/manager/char";
import { AprilFoolManager } from "@game/manager/aprilFool";

export class PlayerDataManager {
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
  /** 愚人节活动管理器 */
  aprilFool: AprilFoolManager;
  /** 战斗管理器 */
  battle!: BattleManager;
  /** 事件触发器 */
  _trigger: TypedEventEmitter;
  /** 玩家原始数据模型 */
  _playerdata: PlayerDataModel;
  /** 变更补丁列表 */
  _changes: Patch[][];
  /** 逆变更补丁列表（用于撤销） */
  _inverseChanges: Patch[][];

  /**
   * 构造函数
   * @param playerdata - 玩家数据模型
   */
  constructor(playerdata: PlayerDataModel) {
    this._playerdata = playerdata;
    this._changes = [];
    this._inverseChanges = [];
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
    this.aprilFool = new AprilFoolManager(this, this._trigger);
    this._trigger.on(
      "save:battle",
      async ([battleId, info]: [string, BattleInfo]) => {
        await accountManager.saveBattleInfo(this.uid, battleId, info);
      },
    );
  }

  /**
   * 获取增量更新数据
   * 
   * 将所有变更补丁转换为对象形式，用于客户端同步。
   * @returns 包含 playerDataDelta 的增量数据
   */
  get delta() {
    const delta = patchesToObject(
      this._changes.reduce((pre, acc) => acc.concat(pre), []),
      this._playerdata,
    );
    this._changes = [];
    this._trigger.emit("save", []);
    console.log("delta", JSON.stringify(delta));
    return {
      playerDataDelta: delta,
    };
  }

  /**
   * 获取用户ID
   * @returns 用户ID
   */
  get uid() {
    return this._playerdata.status.uid;
  }

  /**
   * 获取登录时间戳
   * @returns 登录时间戳
   */
  get loginTime() {
    return this._playerdata.pushFlags.status;
  }

  /**
   * 获取玩家社交信息（用于好友展示）
   * 
   * 包含昵称、等级、助战角色、勋章板等信息。
   * @returns 玩家社交信息对象
   */
  get socialInfo(): FriendDataWithNameCard {
    let medalBoard: FriendMedalBoard;
    if (this._playerdata.social.medalBoard.custom) {
      medalBoard = {
        custom:
          this._playerdata.medal.custom.customs[
            this._playerdata.social.medalBoard.custom
          ],
        type: this._playerdata.social.medalBoard.type,
        template: null,
      };
    } else {
      medalBoard = {
        custom: null,
        type: this._playerdata.social.medalBoard.type,
        template: {
          groupId: this._playerdata.social.medalBoard.template!,
          medalList: this._playerdata.social.medalBoard.templateMedalList!,
        },
      };
    }
    const assistCharList = this._playerdata.social.assistCharList.map(
      (char) => {
        const charInfo = this._playerdata.troop.chars[char.charInstId];
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
      },
    );
    return {
      nickName: this._playerdata.status.nickName,
      nickNumber: this._playerdata.status.nickNumber,
      uid: this.uid,
      registerTs: this._playerdata.status.registerTs,
      mainStageProgress: this._playerdata.status.mainStageProgress,
      charCnt: this._playerdata.troop.curCharInstId - 1,
      furnCnt: this.building.furnCnt,
      skinCnt: this.inventory.skinCnt,
      secretary: this._playerdata.status.secretary,
      secretarySkinId: this._playerdata.status.secretarySkinId,
      resume: this._playerdata.status.resume,
      teamV2: this.dexNav.teamV2Info,
      serverName: this._playerdata.status.serverName,
      level: this._playerdata.status.level,
      avatar: this._playerdata.status.avatar,
      assistCharList: assistCharList,
      lastOnlineTime: this._playerdata.status.lastOnlineTs,
      board: this.building.boardInfo,
      infoShare: this.building.infoShare,
      recentVisited: 0,
      skin: {
        selected: this._playerdata.nameCardStyle.skin.selected,
        state: {},
      },
      birthday: this._playerdata.status.birthday,
      medalBoard: medalBoard,
      nameCardStyle: this._playerdata.nameCardStyle,
    };
  }

  /** 初始化方法（预留） */
  async init() {}

  /**
   * 更新玩家数据（使用 Immer）
   * 
   * 通过传入的 recipe 函数修改数据，自动记录变更补丁。
   * @param recipe - 数据修改函数
   * @returns recipe 函数的返回值
   */
  async update<T>(
    recipe: (draft: WritableDraft<PlayerDataModel>) => Promise<T>,
  ) {
    const draft = createDraft(this._playerdata);
    const result = await recipe(draft);
    this._playerdata = finishDraft(draft, (patches, inversePatches) => {
      this._changes.push(patches);
      console.log("patches", patches);
      this._inverseChanges.push(inversePatches);
    });
    return result;
  }

  /**
   * 获取战斗信息
   * @param battleId - 战斗ID
   * @returns 战斗信息对象
   */
  async getBattleInfo(battleId: string): Promise<BattleInfo> {
    return (await accountManager.getBattleInfo(this.uid, battleId))!;
  }

  /**
   * 序列化为JSON
   * @returns 玩家数据模型对象
   */
  toJSON() {
    return this._playerdata;
  }
}