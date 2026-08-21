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
import { rarityToIndex } from "@utils/rarity";
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
    );
    // 防御：未知勋章/未知奖励组不 500
    if (!medalInfo?.medalRewardGroup) return [];
    const medalRewardGroup = medalInfo.medalRewardGroup.find(
      (m) => m.groupId == args.group,
    );
    if (!medalRewardGroup?.itemList) return [];
    // 修复：未完成的勋章不允许领取（原实现只查 rts → 任意勋章任意领）。
    // 完成判定：首次获得时间戳（fts>0）或进度达标（val[0][0] >= val[0][1]）
    const persisted = this._playerdata.medal.medals[args.medalId];
    const progress = current?.val?.[0] ?? persisted?.val?.[0];
    const completed =
      (current?.fts ?? persisted?.fts) > 0 ||
      (progress?.[1] != null && progress[0] >= progress[1]);
    if (!completed) return [];
    const items = medalRewardGroup.itemList;
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
    // 勋章完成推送（path 自拟 gamepp）：随本次响应下发，客户端据此刷新勋章界面
    this._player.pushMessage("medalFinish", { medalId: args.medalId, rts });
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
    );
    // 集齐章结算：无 template 的章靠 preMedalIdList 集齐解锁——任一章达成后重算，
    // 使组内「01 号集章」在前置普通章全部完成时自动点亮
    await this._settleCollectionMedals();
    if (
      !medalInfo ||
      !medalInfo.medalRewardGroup ||
      medalInfo.medalRewardGroup.length === 0
    ) {
      return;
    }
    const defaultRewardGroup = medalInfo.medalRewardGroup[0];
    await this.rewardMedal({ medalId, group: defaultRewardGroup.groupId });
  }

  /**
   * 集齐章（无 template 且含 preMedalIdList）结算
   *
   * 无 template 的章（多为活动组「01 号」全收集章，如 medal_activity_49side_01）没有进度
   * 模板，官方获取方式 = 获得 preMedalIdList 中所有前置普通章后自动解锁。本方法在任一
   * 章完成（medal:complete）后重算：前置全部达成（fts>0 或进度满）即点亮该集章（写 fts +
   * markDirty），不再次触发 medal:complete（避免递归），有奖励组则发放。
   */
  private async _settleCollectionMedals(): Promise<void> {
    const medalList = excel.MedalTable?.medalList ?? [];
    for (const m of medalList) {
      // 仅处理无 template 的集齐章（跳过有模板的普通章）
      if (m.template || !m.preMedalIdList || m.preMedalIdList.length === 0) {
        continue;
      }
      const progress =
        this.medals[m.medalId] ?? this._playerdata.medal.medals[m.medalId];
      if (!progress || (progress.fts ?? 0) > 0) {
        continue;
      }
      // 前置章全部达成才点亮
      const allDone = m.preMedalIdList.every((pre) => {
        const p = this.medals[pre] ?? this._playerdata.medal.medals[pre];
        if (!p) return false;
        if ((p.fts ?? 0) > 0) return true;
        const v = p.val?.[0];
        return v?.[1] != null && v[0] >= v[1];
      });
      if (!allDone) {
        continue;
      }
      const fts = now();
      if (this.medals[m.medalId]) {
        this.medals[m.medalId].fts = fts;
      }
      if (this._playerdata.medal.medals[m.medalId]) {
        this._playerdata.medal.medals[m.medalId].fts = fts;
      }
      this._player.markDirty();
      this._player.pushMessage("medalFinish", { medalId: m.medalId, fts });
      if (m.medalRewardGroup?.length) {
        await this.rewardMedal({
          medalId: m.medalId,
          group: m.medalRewardGroup[0].groupId,
        });
      }
    }
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
  /**
   * 进度更新脏标记回调（条件落盘）
   *
   * 保留说明：MedalProgress 采用「共享引用」模型——模板 update 直接原地写 this.val，
   * 且 this.val 与 _playerdata.medal.medals[id].val 为同一数组（构造时重链接，见
   * tests/unit/manager/medal.test.ts L282~L322/L695~L722 断言）。单一勋章进度更新
   * 体量极小，若迁入 update() 配方需按 draft.medal.medals[id] 定位重写全部模板方法并
   * 破坏共享引用契约，故事件处理器内保留直改 + 显式 markDirty（迁移前需先重构引用模型）。
   */
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
      // 未实现模板（数据版本新增 / 活动模板）——降级为不追踪进度，避免整服崩溃
      logger.debug(
        "MedalManager",
        `template ${template} not implemented, skip ${this.id}`,
      );
      this.val = [[0, 0]];
      return;
    }

    (this as any)[template]({}, "init");

    const target = this.val[0][1];
    if (this.val[0][0] >= target) {
      return;
    }

    const func = async (args: any[]) => {
      (this as any)[template](args[0], "update");
      // 进度更新显式写回持久态 + 标记脏（A1——不依赖共享引用隐式落盘）
      this._syncToPersist();
      if (this.val[0][0] >= target) {
        logger.info("MedalManager", `${this.id} complete`);
        // 修复：完成时记录首次获得时间戳（原实现从不设 fts，完成态判定仅靠进度）
        this.fts = now();
        this._syncToPersist();
        this._trigger.off(template as any, func);
        // 修复：await 完成事件——Emittery.emit 并行执行监听器，原 fire-and-forget
        // 的 medal:complete 与同批任务监听器的 update() 并发竞争共享 Immer draft，
        // 可触发 "proxy revoked"（与 mission.ts 同源交错问题）
        await this._trigger.emit("medal:complete", [{ medalId: this.id }]);
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
        // 修复：实际干员数 = curCharInstId - 1（instId 从 1 递增，与
        // PlayerDataManager.socialInfo.charCnt 一致）——原实现多算 1
        this.val[0][0] = Math.max(0, (args.curCharInstId ?? 1) - 1);
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
      init: (args: {}) => {
        // 修复：param[0] 可能是分号分隔的干员列表（medal_growth_char_*）——
        // parseInt 得 NaN → 目标永远无法达成；列表形式目标 = 列表长度
        const p0 = String(this.param[0] ?? "");
        const target = p0.includes(";")
          ? p0.split(";").length
          : parseInt(p0) || 0;
        this.val[0].push(0, target);
      },
      update: (args: { char: PlayerCharacter }) => {
        const data = excel.CharacterTable[args.char.charId];
        const p0 = String(this.param[0] ?? "");
        if (p0.includes(";")) {
          // 指定干员列表形式：命中列表内干员 +1
          if (p0.split(";").includes(args.char.charId)) {
            this.val[0][0] += 1;
          }
          return;
        }
        // 稀有度阈值形式：rarity 为 "TIER_N" 字符串——原 `"TIER_5" >= 5` 恒 false，
        // 统一经 rarityToIndex 转 0~5 再比较
        if (rarityToIndex(data?.rarity) >= parseInt(this.param[1] || "5")) {
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
      init: (args: {}) => {
        // 修复：param[0] 可能是分号分隔的干员列表（medal_growth_potential_*）——
        // parseInt 得 NaN → 目标永不可达成；列表形式目标 = 列表长度
        const p0 = String(this.param[0] ?? "");
        const target = p0.includes(";")
          ? p0.split(";").length
          : parseInt(p0) || 0;
        this.val[0].push(0, target);
      },
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

  /**
   * 生息演算（Sbv2）— 升级基地等级
   *
   * 追踪玩家在生息演算玩法中升级基地的进度。目标为 param[0]。
   * 注：当前为占位实现（进度恒取注册后天数，未接入玩法真实状态）。
   * @param param[0] 目标基地等级
   */
  Sbv2UpgradeBase(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 完成任务
   *
   * 追踪玩家在生息演算玩法中完成的任务数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标完成任务数
   */
  Sbv2FinishQuest(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 使用指定角色通关战斗
   *
   * 追踪玩家使用指定干员完成生息演算战斗的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  Sbv2BattleFinishWithChar(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 解锁菜谱
   *
   * 追踪玩家在生息演算玩法中解锁的菜谱数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标菜谱数量
   */
  Sbv2UnlockCook(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 放置建筑
   *
   * 追踪玩家在生息演算基建中放置建筑的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标建筑放置数
   */
  Sbv2PlaceBuilding(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 通关指定裂隙关卡
   *
   * 追踪玩家通关生息演算指定关卡（裂隙）的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标关卡进度
   */
  Sbv2PassRiftLevel(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 通关裂隙次数
   *
   * 追踪玩家通关生息演算裂隙关卡的总次数。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标通关次数
   */
  Sbv2PassRiftCount(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 捕获生物
   *
   * 追踪玩家在生息演算玩法中捕获生物的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标捕获生物数
   */
  Sbv2CatchAnimal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 解锁科技
   *
   * 追踪玩家在生息演算玩法中解锁的科技数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标科技解锁数
   */
  Sbv2UnlockTech(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 存活天数
   *
   * 追踪玩家在生息演算玩法中存活的天数。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标存活天数
   */
  Sbv2SurviveDays(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 生息演算（Sbv2）— 击杀首领
   *
   * 追踪玩家在生息演算玩法中击杀首领的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标击杀首领数
   */
  Sbv2KillBoss(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 通关节点
   *
   * 每次通关节点 +1，达 param[0] 完成。
   * @param param[0] 目标节点数
   */
  Rlv2PassNode(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 月度小队/点数等级
   *
   * 进度直接取当前点数等级 level（覆盖式），达 param[0] 完成。
   * @param param[0] 目标等级
   */
  Rlv2BpLevel(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { level: number }) => {
        this.val[0][0] = args.level;
      },
    };
    funcs[mode](args);
  }

  /**
   * 装扮/通用养成到位
   *
   * 每次事件 +1，达 param[0] 完成。
   * @param param[0] 目标次数
   */
  PermUpgrade(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 炼金/合成使用
   *
   * 每次使用炼金（合成）事件 +1，达 param[0] 完成。
   * @param param[0] 目标次数
   */
  UseAlchemy(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 招募干员
   *
   * 每次招募干员 +1，达 param[0] 完成。
   * @param param[0] 目标招募次数
   */
  Rlv2Recruit(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 获得小队奖励
   *
   * 每次获得小队奖励 +1，达 param[0] 完成。
   * @param param[0] 目标奖励获取次数
   */
  Rlv2GetTeamReward(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 结局收集
   *
   * 每次获得结局（args.ending）事件 +1，达 param[0] 完成。
   * @param param[0] 目标结局数
   */
  Rlv2EndingCollect(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { ending: string }) => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 收藏收集
   *
   * 追踪玩家收藏密室宝箱/战利品的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标收藏数
   */
  Rlv2CollectRelic(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 使用指定角色通关战斗
   *
   * 追踪玩家使用指定干员完成肉鸽战斗的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  Rlv2FinishBattleWithSpecChar(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 指定模式与难度达成结局
   *
   * 追踪玩家在指定开局/难度下达成结局的次数。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标结局次数
   */
  Rlv2EndingWithModeGrade(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 解锁乐/节奏带
   *
   * 追踪玩家解锁玩法乐带进度的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标解锁数
   */
  Rlv2UnlockBand(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 图腾共鸣
   *
   * 追踪玩家触发图腾共鸣进度的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标共鸣数
   */
  Rlv2TotemResonance(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 完成节点任务
   *
   * 追踪玩家完成节点隐藏任务的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标任务数
   */
  Rlv2CompleteNodeMission(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 获得密文胶囊
   *
   * 追踪玩家获得密文胶囊的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标胶囊数
   */
  Rlv2GainCapsule(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 基建家具主题数量勋章模板
   * 追踪玩家拥有的家具主题数量（按 furniture 去重主题计数）
   * @param param[0] 目标主题数量
   */
  BuildingGotFurnitureThemeCount(args: { count?: number }, mode: string = "update") {
    const funcs: { [key: string]: (args: { count?: number }) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 修复：原实现复制 JoinGameDays（按注册天数）——主题数恒为注册天数；
      // 现按家具主题去重计数（args.count 由 inventory FURN 发放时下发）
      update: (args: { count?: number }) => {
        this.val[0][0] = Math.max(this.val[0][0], args.count ?? 0);
      },
    };
    funcs[mode](args);
  }

  /**
   * 基建制造产品次数勋章模板
   * 追踪玩家制造站累计产出的方案数
   * @param param[0] 目标制造次数
   */
  BuildingManufactureProductTimes(args: { count?: number }, mode: string = "update") {
    const funcs: { [key: string]: (args: { count?: number }) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 修复：原实现复制 JoinGameDays——制造次数恒为注册天数；
      // 现按 settleManufacture 实际产出方案数累加
      update: (args: { count?: number }) => {
        this.val[0][0] += args.count ?? 0;
      },
    };
    funcs[mode](args);
  }

  /**
   * 基建工坊合成（按组）勋章模板
   * 追踪玩家加工站指定配方类型（param[1]，如 F_EVOLVE）的合成次数
   * @param param[0] 目标合成次数
   * @param param[1] 配方类型过滤（formulaType）
   */
  BuildingWorkshopSynthesisGroupByID(args: { groupId?: string }, mode: string = "update") {
    const funcs: { [key: string]: (args: { groupId?: string }) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 修复：原实现复制 JoinGameDays——合成次数恒为注册天数；
      // 现按 workshopSynthesis 配方类型匹配 param[1] 累加
      update: (args: { groupId?: string }) => {
        if (args.groupId && args.groupId === this.param[1]) {
          this.val[0][0] += 1;
        }
      },
    };
    funcs[mode](args);
  }

  /**
   * 限时获取角色勋章模板
   * 在指定结束时间（param[1]，unix 秒）前获得 param[0] 指定干员即达成
   *（act53side medal_activity_53side_02）。事件 GotCharsBeforeTime:[{charId}] 由
   * 干员入账处发射。
   */
  GotCharsBeforeTime(args: { charId: string }, mode: string = "update") {
    const funcs: { [key: string]: (args: { charId: string }) => void } = {
      init: (args) => this.val[0].push(0, 1),
      update: (args) => {
        if (args.charId !== this.param[0]) return;
        if (now() > parseInt(this.param[1])) return;
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动代币消耗勋章模板
   * 累计消耗活动币，消耗来源（coinType，取 activity id）匹配 param[0] 即累加
   * 花费 param[2] 达成（act53side medal_activity_53side_03）。事件
   * ActivityCoinCost:[{coinType, cost}] 由活动商店扣币处发射。
   */
  ActivityCoinCost(args: { coinType: string; cost: number }, mode: string = "update") {
    const funcs: { [key: string]: (args: { coinType: string; cost: number }) => void } = {
      init: (args) => this.val[0].push(0, parseInt(this.param[2])),
      update: (args) => {
        if (typeof args?.coinType === "string" && !String(args.coinType).includes(this.param[0])) {
          return;
        }
        this.val[0][0] += args.cost ?? 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 任务完成数量勋章模板
   * 完成 param[0]（分号分隔的任务 id 列表，如 53sideActivity_*）指定的任务组，
   * 目标 = 列表长度（act53side medal_activity_53side_04）。事件
   * MissionCompleteSome:[{count}] 在活动任务成功领取后发射（每完成一个 +1）。
   */
  MissionCompleteSome(args: { count: number }, mode: string = "update") {
    const funcs: { [key: string]: (args: { count?: number }) => void } = {
      init: () => {
        const p0 = String(this.param[0] ?? "");
        const target = p0.includes(";") ? p0.split(";").length : parseInt(p0) || 0;
        this.val[0].push(0, target);
      },
      update: (args) => {
        this.val[0][0] += args?.count ?? 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动关卡内累计代币数（下限）
   *
   * 追踪在活动关卡中获得的代币数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标代币数量
   */
  ActivityPassStageWithSimpleTokenCountMore(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act35side）— 完成雕刻
   *
   * 追踪完成活动雕刻的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标雕刻数
   */
  Act35SideFinishCarving(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡且击杀指定敌人勋章模板
   * 官服语义：一次通关战斗中，当关击倒（counterType=param[3]，如 FALLDOWN）目标敌人
   *（param[2]，enemy_10228_agball）即计 1 次，累计 param[4] 次完成；通关状态门槛
   * 取 param[0]（活动章 completeState>=3=三星）。事件
   * PassStageWithSimpleCountMore:[{stageId, completeState, enemyStats}] 由 battle 结算发射。
   */
  PassStageWithSimpleCountMore(
    args: {
      stageId: string;
      completeState: number;
      enemyStats?: { Key: { enemyId: string; counterType: string }; Value: number }[];
    },
    mode: string = "update",
  ) {
    const funcs: {
      [key: string]: (args: {
        stageId: string;
        completeState: number;
        enemyStats?: { Key: { enemyId: string; counterType: string }; Value: number }[];
      }) => void;
    } = {
      init: (args) => this.val[0].push(0, parseInt(this.param[4])),
      update: (args) => {
        if (args.stageId !== this.param[1]) return;
        if ((args.completeState ?? 0) < parseInt(this.param[0] || "2")) return;
        const stats = args.enemyStats ?? [];
        const downed = stats.some(
          (s) =>
            s.Key?.enemyId === this.param[2] &&
            s.Key?.counterType === this.param[3] &&
            s.Value > 0,
        );
        if (!downed) return;
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡且击杀敌方指定单位种类（细分）
   *
   * 追踪通关活动关卡且累计击杀指定敌人种类的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标等级
   */
  PassStageWithDetailDiffCountMore(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（代币上限）
   *
   * 通关时场内置放/使用代币数不超过 param[1] 即 +1，达 param[0] 完成。
   * @param param[0] 目标场次
   * @param param[1] 代币数量上限
   */
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

  /**
   * 累计击杀敌人总数
   *
   * 每场累计击杀数 killCnt 累加，达 param[0] 完成。
   * @param param[0] 目标击杀总数
   */
  PassStageKilledTotal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { killCnt: number }) => {
        this.val[0][0] += args.killCnt;
      },
    };
    funcs[mode](args);
  }

  /**
   * 联合行动（多人）— 关卡总分
   *
   * 追踪联合行动关卡的累计总分。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标总分
   */
  ActMultiplayVerify2StageTotalScore(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 联合行动（多人）— 达成分数通关
   *
   * 追踪联合行动中达到指定分数通关的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  ActMultiplayVerify2PassStageWithScore(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动里程碑点数
   *
   * 追踪活动里程碑累计点数。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标点数
   */
  ActivityMilestonePoint(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 限时获得指定物品
   *
   * 追踪在限时内获得指定物品（param[?]）的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标物品数
   */
  GotItemBeforeTime(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（代币下限）
   *
   * 通关时场内置放/使用代币数不低于 param[1] 即 +1，达 param[0] 完成。
   * @param param[0] 目标场次
   * @param param[1] 代币数量下限
   */
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

  /**
   * 危机合约V2 — 维度总分
   *
   * 每次单局得分 score 累加，达 param[0] 完成。
   * @param param[0] 目标总分
   */
  CrisisV2DimScoreTotal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { score: number }) => {
        this.val[0][0] += args.score;
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约V2 — 通关指定节点
   *
   * 每次通关节点 +1，达 param[0] 完成。
   * @param param[0] 目标节点数
   */
  CrisisV2NodeSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约V2 — 指定维度达成得分
   *
   * 追踪在指定维度达成得分的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标得分
   */
  CrisisV2DimScoreSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 该维度单局峰值得分（battleFinish 发 scoreCurrent 的最大维度分）
      update: (args: { score?: number }) => {
        this.val[0][0] = Math.max(this.val[0][0], args.score ?? 0);
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约V2 — 使用助战
   *
   * 追踪携带助战通关危机合约V2的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  CrisisV2UseAssist(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 携带助战通关次数（battleFinish 按是否用助战发 used）
      update: (args: { used?: number }) => {
        this.val[0][0] += args.used ?? 0;
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关首领讨伐（BossRush）
   *
   * 追踪通关首领讨伐玩法的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标进度
   */
  PassStageWithBossRush(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（击杀数上限）
   *
   * 追踪通关时击杀数不超过阈值的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithSimpleCountLess(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 累计代币获得数量勋章模板
   * 累计获得 param[3]（分号分隔的活动材料 id 列表）中指定材料达 param[2] 数量
   *（act53side medal_activity_53side_10/105）。事件 TotalSimpleTokenCount:[{itemId,count}]
   * 由 inventory items:get 处对获得的每个物品发射。
   */
  TotalSimpleTokenCount(args: { itemId: string; count: number }, mode: string = "update") {
    const funcs: { [key: string]: (args: { itemId: string; count: number }) => void } = {
      init: (args) => this.val[0].push(0, parseInt(this.param[2])),
      update: (args) => {
        if (typeof args?.itemId !== "string") return;
        const ids = String(this.param[3] ?? "").split(";");
        if (!ids.includes(args.itemId)) return;
        this.val[0][0] += args.count ?? 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（代币达最大值）
   *
   * 追踪单局代币数达到最大值（满场）的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithSimpleTokenCountMax(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act29side）— 每日调查 NPC
   *
   * 追踪参与活动每日调查 NPC 的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标调查数
   */
  Act29SideInvestigateDailyNPC(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 多关卡累计代币数（下限）
   *
   * 追踪在多个指定关卡累计获得代币数。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标代币总数
   */
  SimpleTokenCountMoreInManyStages(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act29side）— 合成旋律
   *
   * 追踪合成活动旋律的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标合成数
   */
  Act29SideSyncthesizeMelody(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act42d0）— 解锁区域
   *
   * 追踪解锁活动区域的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标区域数
   */
  Act42D0UnlockArea(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act42d0）— 携带助战通关
   *
   * 追踪使用助战通关活动关卡的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  Act42D0UseAssistPassStage(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act42d0）— 完成挑战
   *
   * 追踪完成活动挑战的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标挑战数
   */
  Act42D0FinishChallenge(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（陷阱存活数上限）
   *
   * 追踪通关时陷阱载体/装置存活数不超过阈值的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithTrapSurvivedLess(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act38d1）— 维度总分
   *
   * 追踪活动危机维度累计分。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标总分
   */
  ActivityAct38d1DimScoreTotal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act38d1）— 指定维度达成得分
   *
   * 追踪在指定活动维度达成得分的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标得分
   */
  ActivityAct38d1DimScoreSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act38d1）— 解锁指定节点
   *
   * 追踪解锁活动节点的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标节点数
   */
  ActivityAct38d1UnlockNodeSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act38d1）— 使用助战
   *
   * 追踪使用助战通关活动关卡的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  ActivityAct38d1UseAssist(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关剧情关卡（story 关卡）
   *
   * 追踪通关指定剧情关卡的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标关卡数
   */
  PassStoryStageSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act25side）— 完成简单事件至少
   *
   * 追踪完成活动简单事件达指定次数。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标事件数
   */
  Act25SideSimpleEventAtLeast(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act25side）— 完成调查
   *
   * 追踪完成活动调查任务的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标调查数
   */
  Act25SideFinInvestigation(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约 — 指定关卡达成得分
   *
   * 追踪危机合约关卡达成指定得分的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标关卡数
   */
  CrisisStageScoreSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 达成得分：单局峰值（V1 battleFinish 发 totalRisks，V2 发最高维度分）
      update: (args: { score?: number }) => {
        this.val[0][0] = Math.max(this.val[0][0], args.score ?? 0);
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约 — 临时派遣结算
   *
   * 追踪危机合约临时派遣结算的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标结算数
   */
  CrisisTempClearSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 临时派遣结算次数（V1 battleFinish 每局 +1）
      update: (args: { count?: number }) => {
        this.val[0][0] += args.count ?? 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约 — 完成任务
   *
   * 追踪危机合约任务完成进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标任务数
   */
  CrisisTaskSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 完成任务数（battleFinish/挑战任务确认处 +1）
      update: (args: { count?: number }) => {
        this.val[0][0] += args.count ?? 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约 — 解锁永久词条（Rune）
   *
   * 追踪危机合约永久词条解锁进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标词条数
   */
  CrisisUnlockPermRuneSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 解锁永久词条数（unlockRune 处 +1）
      update: (args: { count?: number }) => {
        this.val[0][0] += args.count ?? 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约 — 使用助战
   *
   * 追踪危机合约携带助战通关的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  CrisisUseAssist(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 携带助战通关次数（battleFinish 按是否用助战发 used）
      update: (args: { used?: number }) => {
        this.val[0][0] += args.used ?? 0;
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（击杀与存活条件）
   *
   * 追踪同时满足击杀与存活条件的通关场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithKillSurvive(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（陷阱存活）
   *
   * 追踪通关时指定陷阱存活数量的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标陷阱数
   */
  PassStageWithTrapSurvived(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（残留实体）
   *
   * 追踪通关时关卡残留实体数量的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标残留数
   */
  PassStageWithReedResidue(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动点赞歌剧评论
   *
   * 追踪为活动歌剧评论点赞的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标点赞数
   */
  ActivityLikeOperaComment(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动完成角色卡任务
   *
   * 追踪完成活动角色卡任务的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标任务数
   */
  ActivityFinishCharCardTask(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（西西里）— 解锁区域
   *
   * 追踪解锁活动（西西里语地区）区域的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标区域数
   */
  ActivityUnlockSiracusaArea(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 获取载具配件
   *
   * 追踪获取载具配件的累计进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标配件数
   */
  GainCarAccessories(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡累计击杀
   *
   * 追踪通关关卡时累计击杀指定敌人的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标击杀数
   */
  PassStageKilled(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡击杀数上限
   *
   * 追踪通关时指定击杀数不超过阈值的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageKilledLess(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动科技树激活
   *
   * 追踪激活活动科技树科技的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标科技数
   */
  ActivityTechTreeActive(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动宝藏获得
   *
   * 追踪获得活动宝藏的累计进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标宝藏数
   */
  ActivityTreasureGain(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（携带科技树）
   *
   * 追踪携带指定科技通关的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithTechTree(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（场上敌人上限）
   *
   * 追踪通关时场上活跃敌人数不超过阈值的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithEnemyActiveLess(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（至少达成）
   *
   * 追踪通关时达成指定条件的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithAtLeast(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动消耗日程（Agenda）
   *
   * 追踪活动日程资源消耗量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标消耗量
   */
  ActivityCostAgenda(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动达到声望等级
   *
   * 追踪达到活动声望等级的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标声望等级
   */
  ActivityReachPrestigeLevel(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动里程碑奖励
   *
   * 追踪领取活动里程碑奖励的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标奖励数
   */
  ActivityMilestoneReward(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 饰物（Charm）解锁
   *
   * 追踪解锁饰物格位/词条的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标解锁数
   */
  CharmUnlock(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动饰物回收奖励
   *
   * 追踪活动饰物回收获得奖励的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标奖励数
   */
  ActivityCharmRecycleReward(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（活跃装置总数）
   *
   * 追踪通关时活跃装置/载具总数的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标总数
   */
  PassStageWithActiveTotal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（活跃装置上限）
   *
   * 追踪通关时活跃装置/载具数不超过阈值的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithActiveLess(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（阵亡数上限）
   *
   * 追踪通关时阵亡单位数不超过阈值的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithDeadInLess(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（太极拳）持有
   *
   * 追踪活动（太极拳）累计持有量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标持有量
   */
  ActivityHoldTaichi(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（低部署）
   *
   * 追踪通关时部署干员数不超过阈值的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithLessDeploy(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关首领关卡（不破盾）
   *
   * 追踪未破除首领护盾即通关的场次。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithoutBossShield(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动监禁总数（Confinement）
   *
   * 追踪活动监禁/囚禁总数的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标总数
   */
  ActivityConfinementTotal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动累计击杀总数
   *
   * 追踪活动累计击杀敌人的总数。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标击杀总数
   */
  ActivityKilledTotal(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动阅读新闻
   *
   * 追踪阅读活动新闻的数量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标新闻数
   */
  ActivityCasimirReadNews(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动砍树（资源采集）
   *
   * 追踪砍伐活动树木（资源）的总量。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标采伐量
   */
  ActivityCutTree(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（砍树）
   *
   * 追踪通关时砍伐树木数量的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithCutTree(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 通关关卡（塔/建筑）
   *
   * 追踪通关时使用/留存塔类装置的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标场次
   */
  PassStageWithTower(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动沙盒创建物品
   *
   * 追踪在沙盒玩法中创建物品的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标物品数
   */
  ActivitySandboxCreateItem(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动沙盒达成结局
   *
   * 追踪在沙盒玩法中达成结局的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标结局数
   */
  ActivitySandboxAchieveEnding(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 解锁剧情组（章节）
   *
   * 追踪解锁剧情章节组的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标章节数
   */
  UnlockStoryGroup(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 潜能溢出（满潜后再获得）
   *
   * 追踪干员潜能溢出材料的获取进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标溢出数
   */
  FullPotentialOverflow(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: (args: { registerTs: number }) => {
        this.val[0][0] = moment().diff(moment(args.registerTs), "days");
      },
    };
    funcs[mode](args);
  }

  /**
   * 危机合约 — 指定时限前达成得分
   *
   * 追踪在指定时间前达成危机合约关卡得分的进度。目标为 param[0]。
   * 注：当前为占位实现（未接入玩法真实状态）。
   * @param param[0] 目标关卡数
   */
  CrisisStageScoreBeforeTime(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 限时峰值得分（battleFinish 发 score）
      update: (args: { score?: number }) => {
        this.val[0][0] = Math.max(this.val[0][0], args.score ?? 0);
      },
    };
    funcs[mode](args);
  }

  /**
   * 活动（act1 街机）— 收集全部徽章
   *
   * 每次获得街机徽章 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标徽章数
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
   * 活动（act1 足球）— 得分
   *
   * 每次获得足球活动得分 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标得分
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
   * 活动（act1 挂机）— 升级干员
   *
   * 每次升级干员 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标升级数
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
   * 活动（act38side）— 完成拼图
   *
   * 每次完成拼图 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标拼图数
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
   * 活动（act42side）— 解锁枪支
   *
   * 每次解锁枪支 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标解锁枪数
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
   * 活动（act46side）— 通过大富翁关卡
   *
   * 每次通过大富翁关卡 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标关卡数
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
   * 联合行动（MultiV3）— 提交相册
   *
   * 每次提交相册 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标提交数
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
   * 联合行动（MultiV3）— 完成简单事件
   *
   * 每次完成简单事件 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标事件数
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
   * 联合行动（MultiV3）— 防守波次
   *
   * 每次完成防守波次 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标波次数
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
   * 联合行动（MultiV3）— 足球进球
   *
   * 每次进球 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标进球数
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
   * 联合行动（MultiV3）— 获得头衔
   *
   * 每次获得头衔 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标头衔数
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
   * 联合行动（MultiV3）— 关卡防守承伤
   *
   * 每次达成防守承伤条件 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标承伤值
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
   * 联合行动（MultiV3）— 关卡星级
   *
   * 每次达成指定关卡星级 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标星级数
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
   * 联合行动（MultiV3）— 总星级
   *
   * 每次累计星级 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标总星级
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
   * 破碎维度（VecBreak V2）— 关卡简单事件
   *
   * 每次完成关卡简单事件 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标事件数
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
   * 破碎维度（VecBreak V2）— 时限前过关
   *
   * 每次在指定时间前过关 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标关卡数
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
   * 破碎维度（VecBreak V2）— 过关注击杀敌人
   *
   * 每次达成指定击杀即 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标击杀数
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
   * 破碎维度（VecBreak V2）— 过关注使用技能
   *
   * 每次达成指定技能使用即 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标技能使用数
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
   * 破碎维度（VecBreak V2）— 完成简单事件
   *
   * 每次完成简单事件 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标事件数
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
   * 自动棋（AutoChess）— 乐带徽章数
   *
   * 每次获得乐带徽章 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标徽章数
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
   * 自动棋（AutoChess）— 干员棋升级
   *
   * 每次升级干员棋 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标升级数
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
   * 自动棋（AutoChess）— 通过对局
   *
   * 每次通过对局 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标对局数
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
   * 自动棋（AutoChess）— 累计乐带通关
   *
   * 每次累计乐带通关 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标通关数
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
   * 自动棋（AutoChess）— 累计羁绊通关
   *
   * 每次累计羁绊通关 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标通关数
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
   * 战斗治疗量
   *
   * 每次达成累计治疗量 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标治疗量
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
   * 活动对决排行榜名次
   *
   * 每次达成指定对决名次 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标任务次数
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
   * 干员精二阶段达成
   *
   * 每次达成指定精二阶段 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标任务次数
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
   * 获得六星小组积分
   *
   * 每次获得六星小组积分 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标积分
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
   * 危机合约（Recal）— 关卡得分
   *
   * 每次达成关卡得分 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标得分
   */
  RecalRuneStageScoreSome(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      // 重构符文单局得分峰值（recal battleFinish 发 score）
      update: (args: { score?: number }) => {
        this.val[0][0] = Math.max(this.val[0][0], args.score ?? 0);
      },
    };
    funcs[mode](args);
  }

  /**
   * 肉鸽（Roguelike）— 铜币抽取
   *
   * 每次铜币抽取 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标抽取次数
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
   * 肉鸽（Roguelike）— 严格条件通关节点
   *
   * 每次苛刻条件下通关节点 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标节点数
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
   * 肉鸽（Roguelike）— 通关区域
   *
   * 每次通关区域 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标区域数
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
   * 肉鸽（Roguelike）— 进入特殊区域
   *
   * 每次进入特殊区域 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标区域数
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
   * 生息演算（Sbv3）— 升级基地
   *
   * 每次升级基地 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标基地等级
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
   * 生息演算（Sbv3）— 战斗任务数
   *
   * 每次完成战斗任务 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标任务数
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
   * 生息演算（Sbv3）— 清理障碍
   *
   * 每次清理障碍 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标清理数
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
   * 生息演算（Sbv3）— 部署建筑
   *
   * 每次部署建筑 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标部署数
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
   * 生息演算（Sbv3）— 地牢击杀敌人类型
   *
   * 每次击杀指定类型敌人 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标任务次数
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
   * 生息演算（Sbv3）— 电力得分
   *
   * 每次获得电力得分 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标电力分
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
   * 生息演算（Sbv3）— 解锁菜谱
   *
   * 每次解锁菜谱 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标菜谱数
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
   * 生息演算（Sbv3）— 通过地牢
   *
   * 每次通过地牢 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标地牢数
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
   * 生息演算（Sbv3）— 完成任务
   *
   * 每次完成任务 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标任务数
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
   * 生息演算（Sbv3）— 解锁科技
   *
   * 每次解锁科技 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标科技数
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
   * 累计签到次数
   *
   * 每次签到 +1，达 param[0] 完成（未接入玩法真实状态）。
   * @param param[0] 目标签到次数
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

  /**
   * ActivityArkhubPixelCollect勋章模板（巡展印象奖章）
   * 奇象巡展期间收集画像（unlockParam=[act1arkhub, 0, 4] → target=param[2]）。
   * 事件参数 {activityId, count}：count=ARK_HUB.pixelCollected 累计收集数。
   */
  ActivityArkhubPixelCollect(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[2])),
      update: (args: { activityId: string; count: number }) => {
        if (args.activityId !== this.param[0]) return;
        this.val[0][0] = Math.max(
          this.val[0][0],
          Math.min(args.count ?? 0, this.val[0][1]),
        );
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityArkhubCreatureCollect勋章模板（巡展珍奇奖章）
   * 收录 N 种奇象生物数据（unlockParam=[act1arkhub, arkhubMissionCollection1, 10]
   * → target=param[2]）。事件 {activityId, count, collectionKey}：count=已收录种类数。
   */
  ActivityArkhubCreatureCollect(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[2])),
      update: (args: { activityId: string; count: number }) => {
        if (args.activityId !== this.param[0]) return;
        this.val[0][0] = Math.max(
          this.val[0][0],
          Math.min(args.count ?? 0, this.val[0][1]),
        );
      },
    };
    funcs[mode](args);
  }

  /**
   * ActivityArkhubAlterCollect勋章模板（巡展珍奇奖章·镀层）
   * 收录 N 种 + 至少 1 只亚种（unlockParam=[act1arkhub, arkhubMissionCollection1, 10, 1]
   * → target=param[2]、亚种要求=param[3]）。事件 {activityId, count, alterCount}：
   * 仅当 alterCount >= param[3] 时进度才随 count 推进（镀层条件缺一不可）。
   */
  ActivityArkhubAlterCollect(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[2])),
      update: (args: { activityId: string; count: number; alterCount: number }) => {
        if (args.activityId !== this.param[0]) return;
        const needAlter = parseInt(this.param[3] ?? "0");
        if ((args.alterCount ?? 0) < needAlter) return;
        this.val[0][0] = Math.max(
          this.val[0][0],
          Math.min(args.count ?? 0, this.val[0][1]),
        );
      },
    };
    funcs[mode](args);
  }

  /**
   * ArkodcVarSeqAtLeast勋章模板
   * arkodc 主题变量序列(param[1]，如 bool_all_unlocked)达到 param[2] 值达成
   *（act53side medal_activity_53side_05）。事件 ArkodcVarSeqAtLeast:[{activityId, varSeqs}]
   * 由 arkodc 状态更新处发射，模板读 varSeqs[param[1]] 作为进度。
   */
  ArkodcVarSeqAtLeast(args: { activityId: string; varSeqs: Record<string, number> }, mode: string = "update") {
    const funcs: { [key: string]: (args: { activityId: string; varSeqs: Record<string, number> }) => void } = {
      init: (args) => this.val[0].push(0, parseInt(this.param[2])),
      update: (args) => {
        if (args.activityId !== this.param[0]) return;
        this.val[0][0] = Math.max(
          this.val[0][0],
          Math.min(args.varSeqs?.[this.param[1]] ?? 0, this.val[0][1]),
        );
      },
    };
    funcs[mode](args);
  }

  /**
   * Rlv2KillWeather勋章模板
   * 肉鸽中击杀天气敌人（target=param[0]；等待 rlv2 KillWeather 事件驱动）
   */
  Rlv2KillWeather(args: {}, mode: string = "update") {
    const funcs: { [key: string]: (args: any) => void } = {
      init: (args: {}) => this.val[0].push(0, parseInt(this.param[0])),
      update: () => {
        this.val[0][0] += 1;
      },
    };
    funcs[mode](args);
  }

  /**
   * Rlv2MoveByScrap勋章模板
   * 肉鸽废品玩法中移动/推进（target=param[0]；等待 rlv2 scrap move 事件驱动）
   */
  Rlv2MoveByScrap(args: {}, mode: string = "update") {
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
