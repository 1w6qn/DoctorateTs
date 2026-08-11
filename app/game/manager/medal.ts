/**
 * 勋章管理器
 * 
 * 负责明日方舟中所有勋章的管理，包括：
 * - 勋章进度追踪
 * - 勋章完成检测
 * - 勋章奖励发放
 * - 勋章展示自定义
 * 
 * 勋章系统核心机制：
 * 1. 勋章通过完成特定目标获得（如升级干员、通关关卡等）
 * 2. 每个勋章有独立的进度追踪逻辑
 * 3. 完成勋章可获得相应奖励（通常为家具或头像框）
 * 4. 玩家可自定义勋章展示布局
 */
import {
  PlayerCampaign,
  PlayerDataModel,
  PlayerMedal,
  PlayerMedalCustom,
  PlayerMedalCustomLayout,
  PlayerPerMedal,
} from "../model/playerdata";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import moment from "moment";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { EventMap, TypedEventEmitter } from "@game/model/events";
import { PlayerCharacter } from "../model/character";
import { logger } from "@utils/logger";

export class MedalManager implements PlayerMedal {
  medals: { [key: string]: MedalProgress };
  custom: PlayerMedalCustom;
  _trigger: TypedEventEmitter;
  _player: PlayerDataManager;

  /**
   * 玩家数据（getter：实时读取 PlayerDataManager 当前状态。
   * Immer finishDraft 会替换 _playerdata 引用，若构造时持有固定引用会读到旧对象——
   * 直接写回 rts 等标量会丢失，故必须经 _player 动态取）
   */
  get _playerdata(): PlayerDataModel {
    return this._player._playerdata;
  }

  /**
   * 构造函数
   * @param player 玩家数据管理器实例（动态取 _playerdata，避免 finishDraft 替换引用后读到旧对象）
   * @param _trigger 事件发射器实例
   */
  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this.medals = {};
    this.custom = player._playerdata.medal.custom;
    this._trigger = _trigger;
    this._trigger.on("medal:complete", this.onMedalComplete.bind(this));
  }

  /**
   * 初始化勋章系统
   * 遍历所有勋章数据，创建MedalProgress实例并初始化
   */
  async init() {
    for (const [id, item] of Object.entries(this._playerdata.medal.medals)) {
      this.medals[id] = new MedalProgress(item, this._trigger, () =>
        this._player.markDirty(),
      );
    }
  }

  /**
   * 设置勋章自定义展示数据
   * @param index 自定义布局索引
   * @param data 自定义布局数据
   */
  setCustomData(args: { index: string; data: PlayerMedalCustomLayout }) {
    this.custom.currentIndex = args.index;
    this.custom.customs[args.index] = args.data;
  }

  /**
   * 发放勋章奖励
   * @param medalId 勋章ID
   * @param group 奖励组ID
   * @returns 获得的物品奖励列表
   * 
   * 勋章奖励通常包括：家具、头像框、名片装饰等
   */
  rewardMedal(args: { medalId: string; group: string }) {
    // 已领取（rts != -1）不重复发放
    const current =
      this.medals[args.medalId] ?? this._playerdata.medal.medals[args.medalId];
    if (current && current.rts !== undefined && current.rts !== -1) {
      return [];
    }
    const medalInfo = excel.MedalTable.medalList.find(
      (m) => m.medalId == args.medalId,
    )!;
    const medalRewardGroup = medalInfo.medalRewardGroup;
    const items: ItemBundle[] = medalRewardGroup.find(
      (m) => m.groupId == args.group,
    )!.itemList;
    const rts = now();
    if (this.medals[args.medalId]) {
      this.medals[args.medalId].rts = rts;
      // 同步写回持久态（MedalProgress 构造持有引用，rts 为标量需显式同步）
      if (this._playerdata.medal.medals[args.medalId]) {
        this._playerdata.medal.medals[args.medalId].rts = rts;
      }
    } else if (this._playerdata.medal.medals[args.medalId]) {
      this._playerdata.medal.medals[args.medalId].rts = rts;
    }
    // 绕过 update() 的原地写回不产生 Immer 补丁，显式标记脏以触发条件落盘
    this._player.markDirty();
    this._trigger.emit("items:get", [items]);
    return items;
  }

  /**
   * 勋章完成事件处理
   * @param medalId 完成的勋章ID
   * 
   * 当勋章进度达到目标时触发，自动发放奖励
   */
  async onMedalComplete([{ medalId }]: [{ medalId: string }]) {
    const medalInfo = excel.MedalTable.medalList.find(
      (m) => m.medalId == medalId,
    )!;
    if (!medalInfo || !medalInfo.medalRewardGroup || medalInfo.medalRewardGroup.length === 0) {
      return;
    }
    const defaultRewardGroup = medalInfo.medalRewardGroup[0];
    await this.rewardMedal({ medalId, group: defaultRewardGroup.groupId });
  }

  /**
   * 序列化勋章数据
   * @returns 勋章数据的JSON表示
   */
  toJSON() {
    return {
      medals: Object.fromEntries(
        Object.entries(this.medals).map(([id, medal]) => [id, medal.toJSON()]),
      ),
      customs: this.custom,
    };
  }
}
/**
 * 勋章进度管理类
 * 
 * 负责单个勋章的进度追踪、事件监听和完成检测。
 * 明日方舟勋章系统的核心逻辑实现，包括：
 * - 根据勋章模板注册相应的事件监听器
 * - 实时更新勋章进度
 * - 勋章完成后触发奖励发放事件
 * 
 * 勋章进度数据结构：
 * - val[0][0]: 当前进度值
 * - val[0][1]: 目标进度值
 * - fts: 首次获得时间戳（完成时间）
 * - rts: 奖励领取时间戳
 * - reward: 奖励领取状态
 */
export class MedalProgress implements PlayerPerMedal {
  [key: string]: any;

  val: number[][];
  id: string;
  rts: number;
  fts: number;
  reward: string;
  _trigger: TypedEventEmitter;
  _v: number;
  param!: string[];
  /** 持久态勋章数据引用（_syncToPersist 显式写回用） */
  _item?: PlayerPerMedal;
  /** 进度更新脏标记回调（条件落盘） */
  _markDirty?: () => void;

  /**
   * 构造函数
   * @param item 玩家勋章数据
   * @param _trigger 事件发射器实例
   * @param _markDirty 进度更新后的脏标记回调（由 MedalManager 传入——进度绕过 update()，需显式标记条件落盘）
   */
  constructor(
    item: PlayerPerMedal,
    _trigger: TypedEventEmitter,
    _markDirty?: () => void,
  ) {
    this.id = item.id;
    // scratch：init() 在此构建进度结构（[0, target]）；with-val 时末尾改绑存档数组，此结构丢弃
    this.val = [[]];
    this.rts = item.rts;
    this.fts = item.fts;
    this.reward = item.reward || "";
    this._v = item.val?.[0]?.[0] || 0;
    this._trigger = _trigger;
    this._item = item;
    this._markDirty = _markDirty;
    // 未完成（fts 未设或进度未满）的勋章注册进度监听，使既有存档也能继续追踪
    const target = item.val?.[0]?.[1];
    if (!this.fts || (target && this._v < target)) {
      this.init();
    }
    // 持久态绑定：
    // - with-val：共享存档数组（模板 update 原地写 this.val 即落入 _playerdata）
    // - missing-val：把 init 构建的结构回填到 item.val 并共享引用（否则构建结果被丢弃、
    //   进度更新断链丢失——旧数据勋章进度永不持久化）
    const missingVal = !item.val;
    if (missingVal) {
      item.val = this.val;
    } else {
      this.val = item.val;
    }
  }

  /**
   * 显式写回持久态并标记脏（A1）
   *
   * 进度更新绕过 update()（无 Immer 补丁），依赖共享引用隐式落盘——此方法显式重链接
   * （自愈：即使共享引用被 Immer 克隆打断也重新指向）并触发条件落盘脏标记。
   */
  private _syncToPersist(): void {
    if (this._item) {
      this._item.val = this.val;
      this._item.rts = this.rts;
      this._item.fts = this.fts;
    }
    this._markDirty?.();
  }

  /**
   * 初始化勋章进度
   * 
   * 根据勋章模板注册事件监听器，监听相关游戏事件以更新勋章进度。
   * 如果勋章已完成（进度达到目标），则不注册监听器。
   */
  init() {
    // excel 未初始化时跳过（私服健壮性：PlayerDataManager 构造早于 excel 加载的场景不崩）
    if (!excel.MedalTable?.medalList) {
      return;
    }
    const medalInfo = excel.MedalTable.medalList.find(
      (m) => m.medalId == this.id,
    );
    // 勋章不在配置表中（活动下架残留等）时跳过进度注册
    if (!medalInfo) {
      return;
    }
    const template = medalInfo.template as string;
    if (!template) {
      this.val = [];
      return;
    }
    this.param = medalInfo.unlockParam;
    if (!(template in this)) {
      throw new Error(`template ${template} not implemented yet`);
    }

    (this as any)[template]({}, "init");

    const target = this.val[0][1];
    if (this.val[0][0] >= target) {
      return;
    }

    const func = (args: any[]) => {
      (this as any)[template](args[0], "update");
      // 进度更新显式写回持久态 + 标记脏（A1——不依赖共享引用隐式落盘）
      this._syncToPersist();
      if (this.val[0][0] >= target) {
        logger.info("MedalManager", `${this.id} complete`);
        this._trigger.off(template as any, func);
        this._trigger.emit("medal:complete", [{ medalId: this.id }]);
      }
    };

    this._trigger.on(template as any, func);
  }

  /**
   * 空更新方法（用于兼容性）
   */
  update() {}

  /**
   * 玩家等级勋章模板
   * 追踪玩家等级达到指定等级
   * @param param[0] 目标等级
   */
  PlayerLevel(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { level: number }) => {
        this.val[0][0] = args.level;
      },
    };
    funcs[mode](args);
  }

  /**
   * 加入游戏天数勋章模板
   * 追踪玩家加入游戏的天数
   * @param param[0] 目标天数
   */
  JoinGameDays(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 干员数量勋章模板
   * 追踪玩家拥有的干员数量
   * @param param[0] 目标干员数量
   */
  CharNum(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { curCharInstId: number }) => {
        this.val[0][0] = args.curCharInstId;
      },
    };
    funcs[mode](args);
  }

  /**
   * 招募次数勋章模板
   * 追踪玩家招募干员的次数
   * @param param[0] 目标招募次数
   */
  RecruitCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: {}) => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关特定关卡勋章模板
   * 追踪玩家通关指定关卡的数量
   * @param param[0] 通关状态要求
   * @param param[1] 关卡ID列表（分号分隔）
   * @param param[2] 目标通关数量
   */
  PassStageSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[2])),
      update: (args: PlayerDataManager) => {
        const stages: string[] = this.param[1].split(";");
        let count = 0;
        Object.values(args._playerdata.dungeon.stages).forEach((stage) => {
          if (
            stages.includes(stage.stageId) &&
            stage.state >= parseInt(this.param[0])
          ) {
            count += 1;
          }
        });
        this.val[0][0] = count;
      },
    };
    funcs[mode](args);
  }

  /**
   * 剿灭作战花费理智勋章模板
   * 追踪玩家在剿灭作战中花费的理智（源石碎片）数量
   * @param param[0] 目标花费数量
   */
  CampaignsDiamondLimit(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: PlayerCampaign) => {
        this.val[0][0] = args.campaignTotalFee;
      },
    };
    funcs[mode](args);
  }

  /**
   * 剿灭作战完成勋章模板
   * 追踪玩家完成剿灭作战的次数（击杀400敌人且领取奖励）
   * @param param[0] 剿灭作战ID
   */
  CampaignsComplete(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, 1),
      update: (args: PlayerCampaign) => {
        if (args.instances[this.param[0]].maxKills != 400) {
          return;
        }
        if (args.instances[this.param[0]].rewardStatus.includes(0)) {
          return;
        }
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关剿灭作战勋章模板
   * 追踪玩家通关剿灭作战的数量
   * @param param[0] 目标通关数量
   */
  PassTower(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { count: number }) => {
        this.val[0][0] += args.count;
      },
    };
    funcs[mode](args);
  }

  /**
   * 干员精英化次数勋章模板
   * 追踪玩家将干员精英化到指定阶段的次数
   * @param param[0] 目标精英化次数
   * @param param[1] 精英化阶段要求（默认为2，即精英二）
   */
  CharEvolveCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { char: PlayerCharacter }) => {
        if (args.char.evolvePhase >= parseInt(this.param[1] || "2")) {
          this.val[0][0] += 1;
        }
      },
    };
    funcs[mode](args);
  }

  /**
   * 干员技能升级次数勋章模板
   * 追踪玩家升级干员技能的总次数（按等级累加）
   * @param param[0] 目标技能等级累加值
   */
  CharSkillCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { targetLevel: number }) => {
        this.val[0][0] += args.targetLevel;
      },
    };
    funcs[mode](args);
  }

  /**
   * 干员技能专精次数勋章模板
   * 追踪玩家将干员技能专精到指定等级的次数
   * @param param[0] 目标专精次数
   * @param param[1] 专精等级要求（默认为3）
   */
  CharSkillSpecCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { targetLevel: number }) => {
        if (args.targetLevel >= parseInt(this.param[1] || "3")) {
          this.val[0][0] += 1;
        }
      },
    };
    funcs[mode](args);
  }

  /**
   * 干员信赖度达成勋章模板
   * 追踪玩家将干员信赖度提升到指定百分比的次数
   * @param param[0] 目标干员数量
   * @param param[1] 信赖度百分比要求（默认为200%）
   */
  CharFavorCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { favorPoint: number }) => {
        let percent: number;
        if (args.favorPoint == excel.FavorTable.maxFavor) {
          percent = 200;
        } else {
          const frame = excel.FavorTable.favorFrames.find((_f, idx, table) => {
            return (
              args.favorPoint >= table[idx].level &&
              args.favorPoint < (table[idx + 1]?.level || Infinity)
            );
          });
          percent = (frame?.data as { percent?: number })?.percent || 0;
        }
        if (percent >= parseInt(this.param[1] || "200")) {
          this.val[0][0] += 1;
        }
      },
    };
    funcs[mode](args);
  }

  /**
   * 获取干员勋章模板
   * 追踪玩家获取指定稀有度干员的数量
   * @param param[0] 目标干员数量
   * @param param[1] 干员稀有度要求（默认为5星）
   */
  GotChars(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { char: PlayerCharacter }) => {
        const data = excel.CharacterTable[args.char.charId];
        if (data.rarity >= parseInt(this.param[1] || "5")) {
          this.val[0][0] += 1;
        }
      },
    };
    funcs[mode](args);
  }

  /**
   * 干员潜能提升勋章模板
   * 追踪玩家将干员潜能提升到指定等级的次数
   * @param param[0] 目标潜能提升次数
   * @param param[1] 潜能等级要求（默认为6）
   */
  CharPotential(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { targetLevel: number }) => {
        if (args.targetLevel >= parseInt(this.param[1] || "6")) {
          this.val[0][0] += 1;
        }
      },
    };
    funcs[mode](args);
  }

  /**
   * 解锁干员档案勋章模板
   * 追踪玩家解锁干员档案的数量
   * @param param[0] 目标解锁数量
   */
  CharStoryUnlock(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  Sbv2UpgradeBase(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2FinishQuest(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2BattleFinishWithChar(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2UnlockCook(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2PlaceBuilding(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2PassRiftLevel(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2PassRiftCount(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2CatchAnimal(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2UnlockTech(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2SurviveDays(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Sbv2KillBoss(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Rlv2PassNode(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  Rlv2BpLevel(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { level: number }) => {
        this.val[0][0] = args.level;
      },
    };
    funcs[mode](args);
  }

  PermUpgrade(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  UseAlchemy(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  Rlv2Recruit(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  Rlv2GetTeamReward(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  Rlv2EndingCollect(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { ending: string }) => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  Rlv2CollectRelic(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Rlv2FinishBattleWithSpecChar(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Rlv2EndingWithModeGrade(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Rlv2UnlockBand(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Rlv2TotemResonance(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Rlv2CompleteNodeMission(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Rlv2GainCapsule(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  BuildingGotFurnitureThemeCount(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  BuildingManufactureProductTimes(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  BuildingWorkshopSynthesisGroupByID(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  GotCharsBeforeTime(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityCoinCost(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  MissionCompleteSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityPassStageWithSimpleTokenCountMore(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Act35SideFinishCarving(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithSimpleCountMore(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithDetailDiffCountMore(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithSimpleTokenCountLess(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { tokenCount: number }) => {
        if (args.tokenCount <= parseInt(this.param[1])) {
          this.val[0][0] += 1;
        }
      },
    };
    funcs[mode](args);
  }

  PassStageKilledTotal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { killCnt: number }) => {
        this.val[0][0] += args.killCnt;
      },
    };
    funcs[mode](args);
  }

  ActMultiplayVerify2StageTotalScore(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActMultiplayVerify2PassStageWithScore(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityMilestonePoint(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  GotItemBeforeTime(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithSimpleTokenCountMore(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { tokenCount: number }) => {
        if (args.tokenCount >= parseInt(this.param[1])) {
          this.val[0][0] += 1;
        }
      },
    };
    funcs[mode](args);
  }

  CrisisV2DimScoreTotal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { score: number }) => {
        this.val[0][0] += args.score;
      },
    };
    funcs[mode](args);
  }

  CrisisV2NodeSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  CrisisV2DimScoreSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  CrisisV2UseAssist(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithBossRush(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithSimpleCountLess(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  TotalSimpleTokenCount(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithSimpleTokenCountMax(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Act29SideInvestigateDailyNPC(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  SimpleTokenCountMoreInManyStages(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Act29SideSyncthesizeMelody(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Act42D0UnlockArea(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Act42D0UseAssistPassStage(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Act42D0FinishChallenge(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithTrapSurvivedLess(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityAct38d1DimScoreTotal(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityAct38d1DimScoreSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityAct38d1UnlockNodeSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityAct38d1UseAssist(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStoryStageSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Act25SideSimpleEventAtLeast(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  Act25SideFinInvestigation(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  CrisisStageScoreSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  CrisisTempClearSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  CrisisTaskSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  CrisisUnlockPermRuneSome(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  CrisisUseAssist(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithKillSurvive(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithTrapSurvived(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithReedResidue(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityLikeOperaComment(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityFinishCharCardTask(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityUnlockSiracusaArea(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  GainCarAccessories(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageKilled(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageKilledLess(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityTechTreeActive(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityTreasureGain(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithTechTree(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithEnemyActiveLess(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithAtLeast(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityCostAgenda(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityReachPrestigeLevel(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityMilestoneReward(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  CharmUnlock(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityCharmRecycleReward(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithActiveTotal(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithActiveLess(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithDeadInLess(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityHoldTaichi(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithLessDeploy(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithoutBossShield(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityConfinementTotal(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityKilledTotal(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityCasimirReadNews(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivityCutTree(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithCutTree(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  PassStageWithTower(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivitySandboxCreateItem(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  ActivitySandboxAchieveEnding(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  UnlockStoryGroup(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  FullPotentialOverflow(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  CrisisStageScoreBeforeTime(args: {}, mode: string = "update") {
    /**
     *
     *
     */
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * Act1ArcadeCollectAllBadge勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Act1ArcadeCollectAllBadge(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Act1FootballScores勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Act1FootballScores(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Act1HalfidleUpgradeChar勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Act1HalfidleUpgradeChar(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Act38SideCompletePuzzle勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Act38SideCompletePuzzle(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Act42sideUnlockGunCnt勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Act42sideUnlockGunCnt(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Act46sidePassMonopolyStage勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Act46sidePassMonopolyStage(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActMultiV3CommitAlbum勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActMultiV3CommitAlbum(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActMultiV3CompleteSimpleEvent勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActMultiV3CompleteSimpleEvent(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActMultiV3DefenceWave勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActMultiV3DefenceWave(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActMultiV3FootballGoal勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActMultiV3FootballGoal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActMultiV3GainTitle勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActMultiV3GainTitle(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActMultiV3StageDefenceDamage勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActMultiV3StageDefenceDamage(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActMultiV3StageStar勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActMultiV3StageStar(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActMultiV3TotalStar勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActMultiV3TotalStar(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActVecBreakV2LevelSimpleEventAtLeast勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActVecBreakV2LevelSimpleEventAtLeast(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActVecBreakV2PassStageBeforeTime勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActVecBreakV2PassStageBeforeTime(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActVecBreakV2PassStageWithEnemyKilled勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActVecBreakV2PassStageWithEnemyKilled(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActVecBreakV2PassStageWithSkillUsed勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActVecBreakV2PassStageWithSkillUsed(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActVecBreakV2SimpleEventAtLeast勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActVecBreakV2SimpleEventAtLeast(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityAutoChessBandBadgeCount勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActivityAutoChessBandBadgeCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityAutoChessCharChessUpgrade勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActivityAutoChessCharChessUpgrade(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityAutoChessPassGame勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActivityAutoChessPassGame(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityAutoChessPassWithBandAccumulative勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActivityAutoChessPassWithBandAccumulative(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityAutoChessPassWithBondAccumulative勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActivityAutoChessPassWithBondAccumulative(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityBattleHeal勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActivityBattleHeal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityEnemyDuelRank勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  ActivityEnemyDuelRank(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * CharEvolvePhase勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  CharEvolvePhase(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * GainSixStarGroupPoint勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  GainSixStarGroupPoint(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * RecalRuneStageScoreSome勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  RecalRuneStageScoreSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Rlv2CopperDraw勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Rlv2CopperDraw(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Rlv2PassNodeStrict勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Rlv2PassNodeStrict(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Rlv2PassZone勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Rlv2PassZone(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Rlv2SpecialZoneEnter勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Rlv2SpecialZoneEnter(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3BaseUpgrade勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3BaseUpgrade(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3BattleTaskCount勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3BattleTaskCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3ClearDebris勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3ClearDebris(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3DeployBuilding勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3DeployBuilding(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3DungeonKillEnemyType勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3DungeonKillEnemyType(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3ElectricScore勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3ElectricScore(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3GainCookbook勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3GainCookbook(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3PassDungeon勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3PassDungeon(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3QuestFinish勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3QuestFinish(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Sbv3TechUnlock勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  Sbv3TechUnlock(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * TotalCheckinCount勋章模板
   * 追踪玩家在游戏中的相关行为
   */
  TotalCheckinCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  toJSON(): PlayerPerMedal {
    return {
      id: this.id,
      val: this.val,
      fts: this.fts,
      rts: this.rts,
      ...(this.reward ? { reward: this.reward } : {}),
    };
  }
}
