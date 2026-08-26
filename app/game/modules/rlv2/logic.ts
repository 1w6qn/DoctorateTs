import {
  PlayerRoguelikeV2,
  RoguelikeItemBundle,
  RoguelikeNodePosition,
  TorappuRoguelikeEventType,
} from "../model/rlv2";
import excel from "@excel/excel";
import { readFileSync } from "fs";
import zlib from "node:zlib";
import { logger } from "@utils/logger";
import { RoguelikeInventoryManager } from "./rlv2/inventory";
import { TroopManager } from "../manager/troop";
import { RoguelikeBuffManager } from "./rlv2/buff";
import { RoguelikePlayerStatusManager } from "./rlv2/status";
import { now } from "@utils/time";
import { RoguelikeModuleManager } from "./rlv2/module";
import { RoguelikeTroopManager } from "./rlv2/troop";
import { RoguelikeMapManager } from "./rlv2/map";
import { PlayerSquad } from "@game/model/character";
import { RoguelikeBattleManager } from "./rlv2/battle";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { PlayerDataModel } from "@game/model/playerdata";
import { BattleData } from "@game/model/battle";
import { RoguelikePoolManager } from "./rlv2/pool";
import {
  composeRlv2ChildModules,
  type Rlv2ChildModules,
} from "./rlv2-composition";
import { ROGUE6_NODE } from "./rlv2/modules/grid_zone";
import {
  ROGUE6_BATTLE_NODES,
  ROGUE6_SHOP_NODES,
  ROGUE6_NODE_SCENE_PREFIX,
  ROGUE6_END2_BOSS_STAGE,
  ROGUE6_END2_RELICS,
  ROGUE6_END3_RELIC,
  ROGUE6_BEAK_OUTBUFF,
  ROGUE6_NON_PORTABLE_SCRAPS,
  ROLL_NODE_TYPE_VALUES,
  isBlackstream,
} from "./rlv2/theme-rules";
import { RoguelikeGameInitData } from "@excel/roguelike_topic_table";
import { TypedEventEmitter } from "@game/model/events";
import { RoguelikePushMessage } from "../model/protocol/common";
import { Draft } from "mutative";
import { ItemBundle } from "@excel/character_table";
import { Rogue6IncidentEngine } from "./rlv2/incident";

export class RoguelikeV2Config {
  choiceScenes: { [key: string]: { choices: { [key: string]: number } } };
  eventChoices: {
    [theme: string]: {
      enter: { [sceneId: string]: string[] };
      choices: {
        [choiceId: string]: {
          choices: string[] | string;
          lose?: any;
          get?: any;
          m_lose?: any;
          m_get?: any;
          i_get?: any;
          i_lose?: any;
          curse?: boolean;
          get_id?: any;
        };
      };
    };
  };

  constructor() {
    this.choiceScenes = JSON.parse(
      readFileSync(`${__dirname}/../../../data/rlv2/choices.json`, "utf-8"),
    );
    this.eventChoices = JSON.parse(
      readFileSync(`${__dirname}/../../../data/rlv2/event_choices.json`, "utf-8"),
    );
  }
}

export class RoguelikeV2Controller implements PlayerRoguelikeV2 {
  /**
   * 本控制器对 _playerdata.rlv2 的读视图（outer/current/pinned 恒为 live 引用）。
   *
   * autoFreeze=true 下 PlayerStatus.update() 在 finishDraft 后会把 rlv2 子树替换为深可变
   * 副本（见 PlayerStatus._ensureMutableRlv2），因此这里用 getter 每次读取 _playerdata.rlv2，
   * 避免控制器持有对旧冻结对象的陈旧引用（非 rlv2 的 update 会原地冻结旧 rlv2 引用）。
   * getter 天然保证 this.outer/current/pinned 与 _playerdata.rlv2 引用别名一致
   * （rlv2-ref-sync 测试依赖），且无需 update() wrapper 末尾手动刷新。
   */
  get pinned(): string | undefined {
    return this._player._playerdata.rlv2.pinned;
  }
  get outer(): { [key: string]: PlayerRoguelikeV2.OuterData } {
    const rlv2 = this._player._playerdata.rlv2;
    if (!rlv2.outer) rlv2.outer = {} as any;
    return rlv2.outer as unknown as {
      [key: string]: PlayerRoguelikeV2.OuterData;
    };
  }
  get current(): PlayerRoguelikeV2.CurrentData {
    const rlv2 = this._player._playerdata.rlv2;
    if (!rlv2.current) rlv2.current = {} as any;
    return rlv2.current as unknown as PlayerRoguelikeV2.CurrentData;
  }
  troop: RoguelikeTroopManager;
  _map!: RoguelikeMapManager;
  _status!: RoguelikePlayerStatusManager;
  _buff!: RoguelikeBuffManager;
  _module!: RoguelikeModuleManager;
  _battle!: RoguelikeBattleManager;
  _troop: TroopManager;
  _pool: RoguelikePoolManager;
  _data: RoguelikeV2Config;
  /** 黑流树海不期而遇事件引擎（事件池/场景图/效果结算，数据驱动） */
  _incident!: Rogue6IncidentEngine;
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;
  inventory!: RoguelikeInventoryManager | null;
  /** 本次对局所选分队（开局 chooseInitialRelic 记录，结算 brief.band 用） */
  _bandId = "";
  /**
   * 结算完成标志：gameSettle 置 true，令 toJSON/persistCurrent 输出 current 全空
   * （player/map/troop/inventory/game/buff/module/record = null）——结算后本局已结束，
   * 不再保留可"继续探索"的运行态。createGame 开新局时重置为 false。
   */
  _settled = false;
  /** 多边贸易分队：当前行商节点已卖出零件数（进入行商节点重置，节点内限 1 次奖励） */
  _shopSellCount?: number;
  /**
   * 本次 rlv2 请求的 pushMessage 收集器（官服对齐新增）。
   * 控制器为玩家持久实例，故每次会发推送的端点（createGame/moveTo 等）需先清空再累积，
   * 并由对应 router 端点经 `takePushMessages()` 读取并清空后随响应下发。
   * 仅 rogue_6（黑流树海）在范围内下发，其余主题 `pushMessage()` 直接跳过。
   */
  _pushMessages: RoguelikePushMessage[] = [];

  /**
   * 构造函数
   * @param player - 玩家数据管理器（父）
   * @param _trigger - 类型化事件触发器
   * @param deps - 可选依赖（DI）：`deps.modules` 可部分覆写子模块，用于测试缩小构造面
   */
  constructor(
    player: PlayerDataManager,
    _trigger: TypedEventEmitter,
    deps?: { modules?: Partial<Rlv2ChildModules> },
  ) {
    // rlv2 内部模型（model/rlv2.ts）与生成模型（types-playerdata）为同一数据的两种视图：
    // 内部模型为功能实现的类型契约，生成模型为线格式存储视图，边界处做显式桥接
    this._player = player;
    this._trigger = _trigger;
    this._data = new RoguelikeV2Config();
    this._incident = new Rogue6IncidentEngine(this);
    // 规范化持久态为可写（autoFreeze 兼容）：构造期同步填充 current.game/buff/record
    // 缺失字段，若 _playerdata.rlv2 已被 Immer 冻结（autoFreeze=true 下 finishDraft 冻结
    // 整个 _playerdata），则以深可变副本替换 rlv2 子树，避免构造期原地写抛错。
    this._normalizeMutablePlayerdata();
    this._troop = player.troop;
    // 构造期占位：仅当存档无进行中的对局（current.game.theme 空——新登录/无对局）
    // 时初始化 NONE 占位；有进行中游戏（重启后重登"继续探索"）保留存档
    // current.game/buff/record——无条件重置会把进行中对局清空 → 重登后无法继续。
    // 防御：game.theme 存在但 player.state 缺失/NONE（如服务器中途强退留下的
    // "半初始化"存档——game 已写但状态机未跑）视为无进行中游戏——否则 continue
    // 恢复出"有对局但状态机 NONE"的僵尸态，客户端既不能移动也不能放弃。
    const st = this.current.player as
      | PlayerRoguelikeV2.CurrentData.PlayerStatus
      | undefined;
    const hasRunning =
      !!this.current.game?.theme && !!st?.state && st.state !== "NONE";
    if (!hasRunning) {
      this.current.game = {
        mode: "NONE",
        // 未指定预置剧本（predefined）时用 null 而非 ""（Game.predefined 类型为 string|null，
        // 空串会让客户端按"有预置剧本"解析，与官服线格式不符）
        predefined: null,
        theme: "",
        outer: {
          support: false,
        },
        start: -1,
        modeGrade: 0,
        equivalentGrade: 0,
      };
      this.current.buff = {
        tmpHP: 0,
        capsule: null,
        squadBuff: [],
      };
      this.current.record = { brief: null };
    }

    // 组合子模块：默认工厂按原顺序构造 8 个子管理器；deps.modules 覆写个别模块。
    // 构造顺序即事件订阅顺序，必须与迁移前完全一致（见 rlv2-composition.ts）。
    const composed = composeRlv2ChildModules(this, this._trigger);
    const m = { ...composed, ...deps?.modules };
    this.troop = m.troop;
    this._status = m.status;
    this.inventory = m.inventory;
    this._buff = m.buff;
    this._map = m.map;
    this._module = m.module;
    this._battle = m.battle;
    this._pool = m.pool;
    // 进行中的对局：走 rlv2:continue 恢复（grid_zone/weather/scrap/chaos/buff/
    // events 等从存档 current 恢复；status 单独恢复，避免 rlv2:init 重置为 NONE）
    if (hasRunning) {
      this._trigger.emit("rlv2:continue", []);
      this._status.continue();
    } else {
      this._trigger.emit("rlv2:init", [this]);
    }
  }

  get initConfig(): RoguelikeGameInitData {
    const game = this.current.game!;
    return excel.RoguelikeTopicTable.details[game.theme].init.find(
      (i) =>
        // FBO 对默认值 0 的 int 字段（modeGrade 等）编码为缺省 → undefined，按 0 处理
        (i.modeGrade ?? 0) == (game.modeGrade ?? 0) &&
        i.predefinedId == game.predefined &&
        i.modeId == game.mode,
    )!;
  }

  async update<T>(
    recipe: (draft: Draft<PlayerRoguelikeV2>) => Promise<T>,
  ): Promise<T> {
    // finishDraft 后 PlayerStatus 已把 rlv2 子树替换为深可变副本（autoFreeze 兼容）；
    // this.outer/current/pinned 为 live getter，每次读取 _playerdata.rlv2，天然与持久态
    // 同步，无需在此手动刷新（避免持有对旧冻结对象的陈旧引用）。
    return await this._player.update(async (draft) => {
      return await recipe(draft.rlv2 as unknown as Draft<PlayerRoguelikeV2>);
    });
  }

  /**
   * 收集一条 rlv2 推送消息（官服对齐新增）。
   * 仅当主题为 rogue_6（黑流树海，本次对齐范围）时累积；其余主题静默跳过，
   * 保证 pushMessage 字段在非范围内主题响应中不被下发（rlv2Response 仅非空时合并）。
   * @param path         官服 pushMessage.path（如 rlv2ScrapLimit / rlv2NodeArrive）
   * @param payload      官服 pushMessage.payload（如 {} / { nodeType } / { nodeList }）
   * @param themeOverride 主题覆盖：createGame 在 update() 写库前调用时，当前game.theme 仍是
   *                       旧主题，需显式传入本次要创建的主题；其余端点（进行中对局）可不传，
   *                       自动取 this.current.game.theme。
   */
  pushMessage(path: string, payload: unknown, themeOverride?: string): void {
    const theme = themeOverride ?? this.current.game?.theme;
    if (theme !== "rogue_6") return;
    this._pushMessages.push({ path, payload });
  }

  /** 读取并清空本次请求累积的 pushMessage（由 router 端点在 res.send 前调用） */
  takePushMessages(): RoguelikePushMessage[] {
    const out = this._pushMessages;
    this._pushMessages = [];
    return out;
  }

  /**
   * 规范化 rlv2 持久态为可写（autoFreeze 兼容）
   *
   * Immer finishDraft 在 autoFreeze=true 下会冻结整个 _playerdata（含 rlv2 子树的
   * current/outer）。JS 无法解冻已冻结对象 → 用深可变副本替换 _playerdata.rlv2 并重建
   * 顶层 _playerdata（其余子树保持 finishDraft 冻结，仅 rlv2 可写孤岛解锁，与
   * AccountManager.deepFreezeExcept 排除 rlv2 的约定一致）。
   *
   * autoFreeze=false 下 rlv2 未冻结，原样返回（零开销，且维持 this.outer/current 与
   * _playerdata.rlv2 的引用别名——rlv2-ref-sync 测试依赖该别名）。
   *
   * @returns 规范化后的 _playerdata（rlv2 子树可写）
   */
  private _normalizeMutablePlayerdata(): PlayerDataModel {
    const st = this._player.playerStatus;
    const pd = st._playerdata;
    const rlv2 = pd.rlv2;
    // 未冻结（autoFreeze=false 或构造期首帧）：保持引用别名，零开销
    if (!rlv2 || !Object.isFrozen(rlv2)) return pd;
    // 已冻结：深可变副本替换 rlv2 子树并重建顶层 _playerdata
    const mutableRlv2 = JSON.parse(JSON.stringify(rlv2)) as typeof rlv2;
    const newPd = { ...pd, rlv2: mutableRlv2 };
    st._playerdata = newPd;
    return newPd;
  }

  async setPinned(args: { id: string }): Promise<void> {
    const { id } = args;
    await this.update(async (draft) => {
      draft.pinned = id;
    });
  }

  /**
   * 清空 pending 全部事件，准备生成唯一的结算事件（GAME_SETTLE）。
   * 官服 giveUpGame/gameSettle 后 pending 只有 1 个 GAME_SETTLE——若放弃/结算时
   * 残留进行中的其他事件（RECRUIT/SCENE/BATTLE_REWARD 等），会与结算页并列下发，
   * 客户端状态机无法推进 → 报"系统发生未知故障"/卡死。同时覆盖幂等场景：
   * 重登恢复的"放弃结算中间态"存档已带 GAME_SETTLE，直接清空避免重复追加。
   */
  private clearPending(): void {
    this._status._pending._pending = [];
  }

  async giveUpGame(): Promise<void> {
    // 放弃结算：清空进行中残留事件，生成唯一 GAME_SETTLE（展示放弃结算页），保留游戏态直至 gameSettle 确认
    this.clearPending();
    this._status.runResult = "giveup";
    const { brief, record, buffBankPut } = this.buildSettlement(true, 0, "");
    // current.record 为 _playerdata.rlv2 引用（update() 后冻结），写入须放入配方
    await this.update(async (draft) => {
      draft.current.record = { brief, record };
    });
    await this._trigger.emit("rlv2:event:create", [
      "GAME_SETTLE",
      {
        success: 0,
        result: { brief, record, buffBankPut },
        detailStr: this.buildDetailStr(brief),
        popReport: false,
      },
    ]);
    this._status.state = "PENDING";
  }

  async createGame(args: {
    theme: string;
    mode: string;
    modeGrade: number;
    predefinedId: string | null;
  }): Promise<void> {
    const theme = args.theme;
    // 开新局：清除上一把结算的置空标志（否则 toJSON 继续输出 current 全空）
    this._settled = false;
    // 清空上一请求的残留推送（控制器为持久实例），并收集本局创建的入场推送。
    // 官服 createGame 必带 {path:"rlv2ScrapLimit",payload:{}}（黑流树海抓包 2026-08-11）。
    this._pushMessages = [];
    if (theme === "rogue_6") {
      this.pushMessage("rlv2ScrapLimit", {}, theme);
    }
    // 迁移：current.* 与 outer[theme] 都是 _playerdata.rlv2 的引用，update() 后会被
    // Immer autoFreeze 冻结，配方外原地写会抛错 → 全部放入 update() 配方内，经 finishDraft
    // 统一刷新 this.outer/this.current 引用（后续代码用 this.xxx 读安全）。
    await this.update(async (draft) => {
      draft.current.game = {
        // 模式：MONTH_TEAM（实践者列表）保留原模式——init 表有专属条目
        // （month_team_1/2，初始招募组 recruit_group_m1/m2）；仅 CHALLENGE 无专属
        // init 条目，强制走 NORMAL 规则（此前 MONTH_TEAM 也被转 NORMAL 但 predefinedId
        // 保留 month_team_N → status.create 的 init.find 无匹配崩溃 → 开局血 0/流程卡死）
        mode: args.mode === "CHALLENGE" ? "NORMAL" : args.mode,
        // 预置剧本 id：客户端未传/传空串（NORMAL 等无预置剧本）时归一为 null，
        // 避免 game.predefined=""（Game.predefined 类型为 string|null）
        predefined: args.predefinedId ?? null,
        theme: theme,
        outer: {
          // 支援选项（GAME_INIT_SUPPORT/startbuff 3 选 1）：仅当"上一把至少通过两层"（到达过第 3 层）才出现。
          // 官方判定依据 record.stageCnt 中存在 2 层（兼容 3 层）关卡通关记录（prts.wiki
          // 「至少通过两层」；8-11/8-18 官服 createGame 抓包对照：record 无 lastZone 键，
          // 有 3 层 stageCnt 且 support=true）。原实现用自定义 lastZone>=3 字段（官服 record 无此键）。
          support: this.hasReachedZone3((draft.outer?.[theme]?.record as any)?.stageCnt),
          // 上局遗留襁褓预告：官服 game.outer = { support, legacy } 结构（8-18 抓包 legacy 可含
          // 襁褓 id），但与 record.legacy/GIFT 内容不同源——8-11 抓包 legacy=[] 而 GIFT=gold10。
          // 数据不足精确复现，先输出空数组对齐 8-11 结构（GIFT 内容由 record.legacy 驱动）。
          legacy: [],
        },
        start: now(),
        modeGrade: args.modeGrade,
        equivalentGrade: args.modeGrade,
      };
      draft.current.buff = {
        tmpHP: 0,
        capsule: null,
        squadBuff: [],
      };
      draft.current.record = { brief: null };
      draft.current.map = { zones: {} };
      draft.current.troop = {
        chars: {},
        expedition: [],
        expeditionDetails: {},
        expeditionReturn: null,
        hasExpeditionReturn: false,
      };
      // 首次游玩该主题：初始化 outer[theme] 基础结构（bank/bp/buff/collect/mission 等）
      this.ensureOuterTheme(theme, draft.outer, draft.current.game);
    });

    // 供 rlv2:create 事件处理器读取（其内部经 update() 写，正常）
    this._player.markDirty();
    await this._trigger.emit("rlv2:create", [this]);

    // 开局 legacy 襁褓藏品：
    // - 特勤任务影像（难度 0 失败补偿）：开局直接获得该收藏品
    // - 襁褓猫/狗等 init_gift 效果：由 GAME_INIT_GIFT 事件统一发放（events.create 按
    //   legacy 的 init_gift buff 数据驱动生成事件与内容）——此处不再直接加金/希望，避免双发
    const legacyList: string[] = (this.outer?.[theme]?.record as any)?.legacy || [];
    for (const legacyId of legacyList) {
      if (legacyId === "rogue_6_relic_fight_29") {
        await this._trigger.emit("rlv2:relic:gain", [
          { id: legacyId, count: 1 },
        ]);
      }
    }

    // "让探索走向不同的结局"藏品：改变结局走向（附加层由 maxZone 处理，此处切换 toEnding 为 2 号结局）。
    // 官方此类藏品（残破的玩偶/恍悟/初幕、决心/观望/犹疑/深蓝之心 等）触发 2 结局路线。
    const detail2 = excel.RoguelikeTopicTable.details[theme] as any;
    const hasEndingChangeRelic = Object.values(this.inventory?.relic || {}).some(
      (r) => {
        const id = (r as any).id;
        const usage = detail2?.items?.[id]?.usage || "";
        return usage.includes("让探索走向不同的结局") || usage.includes("不同结局");
      },
    );
    if (hasEndingChangeRelic) {
      this._status.toEnding = `ro${theme.slice(-1)}_ending_2`;
      this._status.chgEnding = true;
      // 结局变更推送（rlv2ChangeEnding，触发类 RoguelikeCheckOnlyEndingChangeNotifyTrigger）
      this.pushMessage("rlv2ChangeEnding", {});
    }

    // 难度 buff（进阶式累积）在 rlv2:create（模块初始化完成）之后应用——
    // scrap_limit_add 等需要 SCRAP 模块实例已创建，buff.create 阶段模块可能未就绪
    await this._buff.applyBuffs([
      this._buff.difficultyBuffs(theme, this.current.game!.modeGrade),
    ]);
  }

  /**
   * 初始化主题局外数据（首次游玩）：collect.band 分队解锁状态等
   * 客户端按 collect.band[id].state 决定开局分队可选性
   * @param outerMap 局外数据字典（配方内传 draft.outer；配方外传 this.outer）
   * @param game     当前游戏态（配方内传 draft.current.game；配方外传 this.current.game）
   */
  private ensureOuterTheme(theme: string, outerMap?: any, game?: any): void {
    const map = outerMap ?? this.outer;
    const gameRef = game ?? this.current.game;
    if (!map[theme]) {
      map[theme] = {} as any;
    }
    const target = map[theme] as any;
    if (!target.collect) {
      const detail = excel.RoguelikeTopicTable.details[theme];
      // 分队全集：init.initialBandRelic（开局可选）+ bandRef 全部条目（含等级变体）
      const init = detail.init.find(
        (i: any) =>
          i.modeGrade == gameRef!.modeGrade &&
          i.predefinedId == gameRef!.predefined &&
          i.modeId == gameRef!.mode,
      );
      const initialBandIds: string[] = init?.initialBandRelic || [];
      const bandRef = (detail.bandRef || {}) as Record<
        string,
        { bandLevel?: number; normalBandId?: string }
      >;
      const allBandIds = [
        ...new Set([...initialBandIds, ...Object.keys(bandRef)]),
      ];
      target.collect = {
        // 分队解锁状态：基础分队（bandLevel 0）state 1 可开局选择；
        // 升级变体（bandLevel > 0）state 0 隐藏（按科技树/进度解锁，避免开局直接出高级分队）
        band: Object.fromEntries(
          allBandIds.map((id) => {
            const lv = bandRef[id]?.bandLevel ?? 0;
            return [id, { state: lv === 0 ? 1 : 0, progress: null }];
          }),
        ),
        relic: {},
        capsule: {},
        activeTool: {},
        mode: {},
        modeGrade: this.initModeGradeStates(theme, map, gameRef),
        recruitSet: {},
        buff: {},
        bgm: {},
        pic: {},
        chat: {},
        endBook: {},
        chatV2: {},
      };
    }
    // 历史存档缺失 modeGrade 时补齐（难度解锁状态）
    if (!target.collect?.modeGrade) {
      target.collect.modeGrade = this.initModeGradeStates(theme, map, gameRef);
    }
    if (!target.bank) target.bank = { show: false, current: 0, record: 0, reward: {} };
    if (!target.bp) target.bp = { point: 0, reward: {} };
    if (!target.buff) target.buff = { pointOwned: 0, pointCost: 0, unlocked: {}, score: 0 };
    if (!target.mission) target.mission = { updateId: "", refresh: 0, list: [] };
    if (!target.record) {
      target.record = { last: 0, stageCnt: {}, bandCnt: {}, bandGrade: {} };
    }
    // 旧存档兼容：record.lastZone 是私服历史自定义字段（官服 record 无此键，
    // 8-11/8-18 抓包对照），保留读取兼容但不新增写入；新数据不再初始化。
    if (!Array.isArray(target.record.legacy)) target.record.legacy = [];
    // 分队升级可见性对齐：已有科技树解锁（如 分裂→指挥分队 band_2）时升级分队 state 1、
    // 旧分队隐藏（修复历史存档升级后旧分队未隐藏）
    const band = target.collect?.band;
    const unlocked = target.buff?.unlocked || {};
    if (band && typeof band === "object") {
      for (const buffId of Object.keys(unlocked)) {
        this.applyBandUpgradeVisibility(theme, buffId, band);
      }
      // 调查者增益（生灵的溯游）：难度 ≥3/6/9 时若已点亮 分裂/卵生/胎生 节点（科技树解锁），
      // 对应分队升级（指挥/后勤/矛头分队）自动生效
      const grade = gameRef?.modeGrade ?? 0;
      const lit = new Set(Object.keys(unlocked));
      const THRESHOLDS: { node: string; minGrade: number }[] = [
        { node: "rogue_6_difficulty_1", minGrade: 3 }, // 分裂（指挥分队升级）
        { node: "rogue_6_difficulty_2", minGrade: 6 }, // 卵生（后勤分队升级）
        { node: "rogue_6_difficulty_3", minGrade: 9 }, // 胎生（矛头分队升级）
      ];
      for (const { node, minGrade } of THRESHOLDS) {
        if (grade >= minGrade && lit.has(node)) {
          this.applyBandUpgradeVisibility(theme, node, band);
        }
      }
    }
  }

  /**
   * 月度任务刷新（官方 POST /rlv2/normal/refreshMission，body { theme, index }）：
   * 按更新期（updates[index]）从 monthMission 任务池随机抽取 4 个（1A+1B+2C），
   * 写入 outer[theme].mission.list，响应并入 modified.rlv2（客户端 topic 页读取）。
   */
  async refreshMission(args: { theme?: string; index?: number }): Promise<void> {
    const theme = args.theme || this.current.game?.theme || "";
    if (!theme) return;
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const monthMission: any[] = detail?.monthMission || [];
    if (monthMission.length === 0) return;

    // 更新期（index 指向 updates 数组；缺省取最后一个）
    const updates: any[] = detail?.updates || [];
    const idx = args.index ?? Math.max(0, updates.length - 1);
    const update = updates[idx] || updates[updates.length - 1];
    const updateId = update?.updateId || "";

    // 任务池按 class 分组（A/B/C），每组随机抽；tmpl 即 excel template
    const poolByClass: { [key: string]: any[] } = { A: [], B: [], C: [] };
    for (const t of monthMission) {
      const cls = (t.taskClass || "C") as string;
      if (poolByClass[cls]) poolByClass[cls].push(t);
    }
    // 每类抽取数量：A×1、B×1、C×2（官方月度任务 4 槽位）
    const picks: { cls: string; task: any }[] = [];
    for (const cls of ["A", "B", "C"]) {
      const count = cls === "C" ? 2 : 1;
      const copy = [...(poolByClass[cls] || [])];
      for (let i = 0; i < count && copy.length > 0; i++) {
        const task = copy.splice(Math.floor(Math.random() * copy.length), 1)[0];
        picks.push({ cls, task });
      }
    }
    // 保底：C 类不足时从 A/B 补足到 4 槽
    while (picks.length < 4 && poolByClass.C.length > 0) {
      const task = poolByClass.C[Math.floor(Math.random() * poolByClass.C.length)];
      picks.push({ cls: "C", task });
    }

    const list = picks.map(({ cls, task }) => {
      const target = parseInt(task.paramList?.[0] ?? "0", 10) || 1;
      return {
        type: cls,
        mission: {
          type: cls,
          tmpl: task.template,
          id: task.id,
          state: 0,
          target,
          value: 0,
        },
      };
    });

    // outer[theme] 为 _playerdata.rlv2 引用（update() 后冻结），写入须放入配方
    await this.update(async (draft) => {
      this.ensureOuterTheme(theme, draft.outer, draft.current.game);
      const outer = draft.outer[theme] as any;
      outer.mission = {
        updateId,
        refresh: (outer.mission?.refresh ?? 0) + 1,
        list,
      };
    });
  }

  async chooseInitialRelic(args: { select: string }) {
    // 防御：RELIC 事件可能已被消费（客户端重复调用/乱序）——按类型查找而非盲目 shift
    const event = this._status.pending.find(
      (e) => e.type === "GAME_INIT_RELIC",
    );
    if (!event) return;
    const relic = event.content.initRelic?.items?.[args.select];
    if (!relic) return;
    // 记录所选分队（结算 brief.band）
    this._bandId = relic.id;
    await this.inventory!._relic.gain([relic]);
    this._status.pending.splice(this._status.pending.indexOf(event), 1);
  }

  async chooseInitialRecruitSet(args: { select: string }) {
    const theme = this.current.game!.theme;
    // RECRUIT_SET 可能已被 finishEvent 消费（部分客户端流程）→ 按索引查找移除
    const recSetIdx = this._status.pending.findIndex(
      (e) => e.type === "GAME_INIT_RECRUIT_SET",
    );
    if (recSetIdx >= 0) this._status.pending.splice(recSetIdx, 1);
    const recruitEvt = this._status.pending.find(
      (e) => e.type === "GAME_INIT_RECRUIT",
    );

    // 招募组 → 具体职业券映射（官方 recruitGrps 仅带 desc 文本"XX、YY、ZZ招募券各一张"，
    // 按 desc 中职业顺序映射到标准职业券；group_random 抽 3 张随机标准票）
    const PROFESSIONS = [
      "pioneer",
      "warrior",
      "tank",
      "sniper",
      "caster",
      "support",
      "medic",
      "special",
    ];
    const roNum = theme.slice(-1);
    const GROUP_PROFESSIONS: { [key: string]: string[] } = {
      recruit_group_1: ["pioneer", "sniper", "special"], // 先手必胜：先锋、狙击、特种
      recruit_group_2: ["tank", "caster", "sniper"], // 稳扎稳打：重装、术师、狙击
      recruit_group_3: ["warrior", "support", "medic"], // 取长补短：近卫、辅助、医疗
      recruit_group_4: ["pioneer", "support", "special"], // 灵活部署：先锋、辅助、特种
      recruit_group_5: ["tank", "caster", "medic"], // 坚不可摧：重装、术师、医疗
    };
    // 随心所欲：第 1 张 5 星临时招募券（含 5 星）、第 2 张近战四职业（近卫/先锋/重装/特种）、
    // 第 3 张远程四职业（狙击/术师/医疗/辅助）
    const GROUP_TICKETS: { [key: string]: string[] } = {
      recruit_group_random: [
        `${theme}_recruit_ticket_5star`,
        `${theme}_recruit_ticket_quad_melee`,
        `${theme}_recruit_ticket_quad_ranged`,
      ],
    };
    const pool = PROFESSIONS.map((p) => `rogue_${roNum}_recruit_ticket_${p}`).filter(
      (t) => (excel.RoguelikeTopicTable.details[theme] as any)?.recruitTickets?.[t],
    );
    let picked: string[];
    const groupTickets = GROUP_TICKETS[args.select] || [];
    if (/^recruit_group_m[12]$/.test(args.select)) {
      // 实践者列表（recruit_group_m1/m2 "支援作战"）：两张随机的招募券
      const shuffled = [...pool].sort(() => Math.random() - 0.5);
      picked = shuffled.slice(0, 2);
    } else if (groupTickets.length > 0) {
      // 随心所欲专用券（5star/quad_melee/quad_ranged）——校验存在，缺失回退随机
      const valid = groupTickets.filter(
        (t) => (excel.RoguelikeTopicTable.details[theme] as any)?.recruitTickets?.[t],
      );
      if (valid.length === 3) {
        picked = valid;
      } else {
        const shuffled = [...pool].sort(() => Math.random() - 0.5);
        picked = shuffled.slice(0, 3);
      }
    } else {
      const groupProfs =
        GROUP_PROFESSIONS[args.select] || GROUP_PROFESSIONS["recruit_group_random"];
      if (args.select === "recruit_group_random" || !groupProfs) {
        const shuffled = [...pool].sort(() => Math.random() - 0.5);
        picked = shuffled.slice(0, 3);
      } else {
        // 按组合职业顺序取对应标准券（"先锋、狙击、特种招募券各一张"）
        picked = groupProfs
          .map((p) => `rogue_${roNum}_recruit_ticket_${p}`)
          .filter((t) => pool.includes(t));
        // 保底：组合职业券缺失时用随机补足 3 张
        while (picked.length < 3) {
          const rest = pool.filter((t) => !picked.includes(t));
          if (rest.length === 0) break;
          picked.push(rest[Math.floor(Math.random() * rest.length)]);
        }
      }
    }
    for (const r of picked) {
      await this._trigger.emit("rlv2:recruit:gain", [r, "initial", 0]);
    }
    if (recruitEvt) {
      recruitEvt.content.initRecruit!.tickets = Object.values(
        this.inventory!.recruit,
      )
        .filter((r) => r.from == "initial")
        .map((r) => r.index);
    }
  }

  async activeRecruitTicket(args: { id: string }) {
    // 官方抓包：activeRecruitTicket 激活票并生成 RECRUIT pending 事件（客户端据此弹招募 UI），
    // 未生成事件 → 客户端无招募界面（"没有初始招募"）。激活后递归剩票无需再触发——客户端逐张激活。
    await this._trigger.emit("rlv2:recruit:active", [args.id]);
    const ticket = this.inventory?.recruit?.[args.id];
    if (ticket) {
      // 候选列表已生成（recruit.active 填充 list）→ 创建 RECRUIT 事件供客户端展示
      await this._trigger.emit("rlv2:event:create", [
        "RECRUIT",
        {
          tickets: args.id,
        },
      ]);
    }
  }

  async recruitChar(args: {
    ticketIndex: string;
    optionId: string;
  }): Promise<PlayerRoguelikeV2.CurrentData.RecruitChar[]> {
    const { ticketIndex, optionId } = args;
    const ticket = this.inventory!.recruit[ticketIndex];
    // 一张票只能招募一次（官方语义）：票不存在 / 未打开(state=0) / 已放弃(state=3)
    // → 不可招募；已招募(state=2) 的票重复调用 → 幂等返回首次 result（非空，
    // 客户端不卡死）；仅 state=1（active）执行招募
    if (!ticket) return [];
    if (ticket.state !== 1) {
      return ticket.result ? [ticket.result] : [];
    }
    await this._trigger.emit("rlv2:recruit:done", [ticketIndex, optionId]);
    // 消费该票对应的 RECRUIT 事件（官服：招募完成后事件移除——
    // 否则残留 RECRUIT 进入 WAIT_MOVE，客户端报"系统发生未知故障"）
    const evIdx = this._status.pending.findIndex(
      (e) =>
        e.type === "RECRUIT" &&
        (e.content as any)?.recruit?.ticket === ticketIndex,
    );
    if (evIdx >= 0) this._status.pending.splice(evIdx, 1);
    // 票保留（state=2 终态）；inventory.recruit 由 finishEvent 初始阶段统一清空
    const result = this.inventory!.recruit[ticketIndex]?.result;
    return result ? [result] : [];
  }

  async finishEvent() {
    if (this._status.cursor.zone === 0) {
      // 初始阶段：按官服语义消费事件——finishEvent 每次只推进一个"确认型"事件
      // （GIFT 发礼物 / RECRUIT 招募完成），其余留给客户端专用接口：
      // RELIC→chooseInitialRelic、SUPPORT→selectChoice、RECRUIT_SET→chooseInitialRecruitSet。
      // 8-11 官服抓包对照：finishEvent#1 消费 GIFT（pending 剩 SUPPORT/RECRUIT_SET/RECRUIT），
      // finishEvent#2 消费 RECRUIT 进入 WAIT_MOVE。原实现循环消费会把 SUPPORT 代选
      // （跳过客户端 selectChoice 步骤，且代选选项可能误改属性——hp 4→6 差异）。
      // 仅当 GIFT/RECRUIT 不存在时才兜底清空（防客户端异常跳步卡死）。
      const top = this._status.pending[0];
      if (top?.type === "GAME_INIT_GIFT") {
        const items = top.content.initGift?.items || [];
        if (items.length > 0) {
          await this._trigger.emit("rlv2:get:items", [items]);
        }
        this._status.pending.shift();
      } else if (top?.type === "GAME_INIT_RECRUIT") {
        this._status.pending.shift();
        // 清空初始招募残留的 RECRUIT 事件（放弃票/候选为空未招募场景——
        // 官服进入第一层 WAIT_MOVE 时 pending 为空，残留会导致客户端"系统发生未知故障"）
        this._status._pending._pending =
          this._status._pending._pending.filter((e) => e.type !== "RECRUIT");
      } else if (top && top.type.startsWith("GAME_INIT_")) {
        // 其余 GAME_INIT_*（SUPPORT/RECRUIT_SET）需专用接口，不消费
        this._status.state = "INIT";
        return;
      } else if (top?.type === "RECRUIT") {
        // 非初始 RECRUIT 事件（商店/战斗获得招募券后）：消费
        this._status.pending.shift();
      }
      const hasInit = this._status.pending.some((e) =>
        (e.type || "").startsWith("GAME_INIT_"),
      );
      if (hasInit) {
        this._status.state = "INIT";
        return;
      }
      // 兜底：清理初始招募残留票（官服进入第一层 WAIT_MOVE 时 inventory.recruit 基本为空）。
      // 仅移除未招募(state=0/1)/放弃(state=3)的票；保留已招募(state=2 且 result 非空)的票，
      // 使玩家在本局内仍能从 inventory.recruit 查看已招募干员（干员同时已在 troop）。
      // 全量清空会让已招募干员从本局 inventory.recruit 直接消失。
      for (const k of Object.keys(this.inventory!.recruit || {})) {
        const t = this.inventory!.recruit[k];
        if (t && t.state === 2 && t.result) continue;
        delete this.inventory!.recruit[k];
      }
      this._status.cursor.zone = 1;
      this._status.cursor.position = null;
      await this._trigger.emit("rlv2:zone:new", [this._status.cursor.zone]);
      // 特勤干员任务：到达区域事件（Rlv2PassZoneSpec）
      await this.emitSpecialOperatorZone(this._status.cursor.zone);
      // 进入第一层后 cursor.position = 起点节点位置（官服 finishEvent#2：
      // position={x:0,y:1} 即 type=268435456 起点；null 会导致客户端无法定位当前
      // 节点 → 地图渲染/步进崩溃）
      // 起点定位见 locateStartNode：起点是 gridZone 唯一 state=2 节点，不能按
      // map.zones 首个 GLADE 推断——林间空地同为填充节点类型（官方数量规则每层
      // 可铺 0..16 个，见 BLACKSTREAM_COUNT_RULES），首次命中可能是填充林间空地。
      const gz = this._module?.gridZone;
      const startPos = this.locateStartNode();
      if (startPos) {
        this._status.cursor.position = { x: startPos.x, y: startPos.y };
        // 进层后自动完成"起点走一步"（官服 finishEvent#2 对齐）：起点标已访问、
        // trace 追加起点、清 needConfirmStepZero（无需再要求玩家确认初始位置）。
        // 进层下发唯一 rlv2NodeChange（官服抓包 R-1786531228496.9993-3674：
        // nodeList 为起点列节点["202","200"]，排除起点；仅 nodeChange 不带 nodeArrive）。
        // 不做 moveTo 揭示——moveTo 会把周边 state0 节点改成 state1，而官服进层后
        // gridZone 节点 state 只取 0/2（平铺无中间态），故仅显式标起点 state=2。
        if (gz) {
          const startId = String(startPos.x * 100 + startPos.y);
          const z = gz.zones?.[gz.currentZoneKey()];
          const sn = z?.nodes?.[startId];
          if (sn && sn.state !== 2) sn.state = 2;
          gz.needConfirmStepZero = false;
          const colNodeIds = Object.keys(z?.nodes || {}).filter(
            (id) =>
              Math.floor(Number(id) / 100) === startPos.x && id !== startId,
          );
          if (colNodeIds.length > 0) {
            this.pushMessage("rlv2NodeChange", { nodeList: colNodeIds });
          }
        }
        this._status.trace.push({
          zone: this._status.cursor.zone,
          position: { x: startPos.x, y: startPos.y },
        });
      }
      this._status.state = "WAIT_MOVE";
      return;
    }
    // 非初始阶段：先检查本层终点（isZoneEnd 依赖当前 position），再清空位置
    this._status.pending.shift();
    const settling = await this.checkZoneEnd();
    this._status.cursor.position = null;
    if (settling) {
      // 最终层结算已触发（gameSettle 为异步，此处同步置 END 保证状态一致）
      this._status.state = "END";
      return;
    }
    this._status.state = "WAIT_MOVE";
  }

  /**
   * 支援选项（行动奖励）判定：上一把是否至少通过两层（到达过第 3 层）。
   * prts.wiki「若上一次行动至少通过两层，则触发本阶段」；官方依据 record.stageCnt
   * 中存在 2 层关卡通关记录（8-11/8-18 官服 createGame 抓包对照：support=true 的账号
   * stageCnt 含 3 层关卡——通过 3 层必已通过 2 层，两类匹配都保留；record 无 lastZone 键）。
   * 兼容旧存档的 lastZone 字段（>=3 也视为到过）。
   */
  private hasReachedZone3(stageCnt?: Record<string, number>): boolean {
    if (stageCnt) {
      for (const stageId of Object.keys(stageCnt)) {
        // 通过 2 层：ro6_[ne]_2_* / ro6_b_2* / ro6_c_2（通关记录）
        if (/^ro\d+_[ne]_2_/.test(stageId)) return true;
        if (/^ro\d+_(b|c)_2/.test(stageId)) return true;
        // 兼容：3 层通关记录（抓包样本形态，通过 3 层必已通过 2 层）
        if (/^ro\d+_[ne]_3_/.test(stageId)) return true;
        if (/^ro\d+_(b|c)_3/.test(stageId)) return true;
      }
    }
    // 兼容旧存档自定义字段（到达层数，>=3 即通过两层）
    const legacy = (this.outer?.[this.current.game?.theme || ""]?.record as any)?.lastZone;
    return typeof legacy === "number" && legacy >= 3;
  }

  /**
   * 定位当前层起点（林间空地/“起点”）的坐标。
   * 起点是 gridZone 当前层内唯一已访问（state=2）的节点（进层生成时只有起点
   * state=2，其余占位格为 0）。不能按 map.zones 的 type===GLADE 查找——林间空地
   * (GLADE) 同为普通填充节点类型（官方数量规则每层可铺 0..16 个，见
   * BLACKSTREAM_COUNT_RULES），首个 GLADE 可能是填充节点而非起点，会令 cursor
   * 定位到错误节点、起点步进/渲染异常。
   * 兜底：老存档/无 gridZone 模块时回退到 map.zones 找任一 GLADE。
   * @returns 起点坐标 {x,y}；找不到返回 undefined
   */
  private locateStartNode(): { x: number; y: number } | undefined {
    const gz = this._module?.gridZone;
    if (gz) {
      const zoneKey = gz.currentZoneKey();
      for (const [id, n] of Object.entries(gz.zones?.[zoneKey]?.nodes || {})) {
        if ((n as any)?.state === 2) {
          return { x: Math.floor(Number(id) / 100), y: Number(id) % 100 };
        }
      }
    }
    const zoneNodes = this._map.zones[
      String(1000 + this._status.cursor.zone - 1)
    ]?.nodes as Record<string, any> | undefined;
    const g = Object.values(zoneNodes || {}).find(
      (n) => n?.type === ROGUE6_NODE.GLADE,
    ) as any;
    return g?.pos ? { x: g.pos.x, y: g.pos.y } : undefined;
  }

  /**
   * 主流程最大层数：所有主题默认 5 层（1 层尾商店、3/5 层尾 boss）。
   * 持有"让探索走向不同的结局"藏品（如 rogue_1 残破的玩偶/恍悟/初幕、rogue_2 决/观望/犹疑/深蓝之心）
   * 时可能出现附加层（6 层结局层），最多到该主题 stages 实际层数。
   */
  get maxZone(): number {
    const theme = this.current.game!.theme;
    const stages = Object.keys(
      (excel.RoguelikeTopicTable as any)?.details?.[theme]?.stages || {},
    );
    let max = 0;
    for (const s of stages) {
      const m = s.match(/^ro\d+_[ne]_(\d+)_/);
      if (m) max = Math.max(max, parseInt(m[1], 10));
    }
    // 附加层条件：持有改变结局走向的藏品 → 允许到 6 层（官方结局层）；否则默认 5 层
    if (max >= 6) {
      const relicIds = Object.values(this.inventory?.relic || {}).map(
        (r) => (r as any).id,
      );
      const detail = excel.RoguelikeTopicTable.details[theme] as any;
      const hasEndingChange = relicIds.some(
        (id) =>
          (detail?.items?.[id]?.usage || "").includes("让探索走向不同的结局") ||
          (detail?.items?.[id]?.usage || "").includes("不同结局"),
      );
      // 三结局·纠缠调和：持有【怦然信标】（rogue_6_relic_final_3，gameConst.expedEndingRelic）
      // → 通过第Ⅴ层后可进入第Ⅵ层（源流交汇处）
      const hasBeacon =
        theme === "rogue_6" && relicIds.includes("rogue_6_relic_final_3");
      if (hasEndingChange || hasBeacon) return max;
    }
    return Math.min(max || 6, 5);
  }

  /**
   * map.zones 键解析：标准主题（rogue_1..5）用层号（1,2,3…）；黑流树海（rogue_6 无相地图）
   * 由 GRID_ZONE 模块按官服格式写入区域索引键（zone_1 → "1000"）。按存在性兼容两种键。
   */
  private zoneKey(zone: number): string | number {
    const zones = this._map.zones;
    // 误入奇境隐藏层（portal active）：地图为 portal zone（键 3000+）
    const gz = this._module?.gridZone;
    if (gz?.portal?.active && gz.portal.zoneKey) return gz.portal.zoneKey;
    if (zones[zone]) return zone;
    if (zones[String(1000 + zone - 1)]) return String(1000 + zone - 1);
    return zone;
  }

  /** 当前节点是否为本层终点（zone_end） */
  private isZoneEnd(): boolean {
    const pos = this._status.cursor.position;
    if (!pos) return false;
    const node = this._map.zones[this.zoneKey(this._status.cursor.zone)]?.nodes[
      pos.x * 100 + pos.y
    ];
    return !!node?.zone_end;
  }

  /** 节点结束后检查：到达本层终点则推进下一层（最终层则结算）。返回是否已触发结算。 */
  private async checkZoneEnd(): Promise<boolean> {
    if (!this.isZoneEnd()) return false;
    const zone = this._status.cursor.zone;
    const theme = this.current.game!.theme;
    if (zone >= this.maxZone) {
      // 三结局·纠缠调和：持有【怦然信标】通过第Ⅵ层 → ending_3
      if (isBlackstream(theme) && this.hasRelic(ROGUE6_END3_RELIC)) {
        this._status.toEnding = "ro6_ending_3";
      } else if (
        isBlackstream(theme) &&
        (this.hasRelic(ROGUE6_END2_RELICS.sandboxAlpha) ||
          this.hasRelic(ROGUE6_END2_RELICS.sandboxBeta))
      ) {
        // 二结局·维度重构：持有沙盘α/β 且不持有怦然信标通过第Ⅴ层 → ending_2
        this._status.toEnding = "ro6_ending_2";
      }
      // 结局切换为二/三号时下发变更推送（rlv2ChangeEnding，触发类 RoguelikeCheckOnlyEndingChangeNotifyTrigger）
      if (this._status.toEnding === "ro6_ending_2" || this._status.toEnding === "ro6_ending_3") {
        this.pushMessage("rlv2ChangeEnding", {});
      }
      // 修复：通关到最终层终点 → 标记成功（原实现 toEnding 恒非 "normal" → 每次通关
      // 结算都显示失败）；放弃路径由 giveUpGame 置 "giveup"
      this._status.runResult = "success";
      // 修复：fire-and-forget 未捕获拒绝会导致 Node 进程终止（gameSettle 内部 game 可能为 null）
      void this.gameSettle().catch((e) =>
        logger.error("rlv2", `gameSettle failed: ${(e as Error).message}`),
      );
      return true;
    }
    // 区域奖励：非最终层通关时填充 zoneReward（confirmZoneReward 发放并清空）
    if (!this._status.zoneReward || Object.keys(this._status.zoneReward).length === 0) {
      const hasRelic = Object.values(this.inventory!.relic || {}).map(
        (r) => (r as any).id,
      );
      const rewardId = this._pool.getRelic("pool_relic_all", hasRelic);
      if (rewardId) {
        this._status.zoneReward = {
          z0: { id: rewardId, count: 1, instId: "" },
        };
      }
    }
    // 难度效果：进入下一区域损失 N% 源石锭（difficulty zone_gold_loss_percent）
    const goldLossPct = this._buff?._zoneGoldLossPercent ?? 0;
    if (goldLossPct > 0) {
      const lost = Math.floor((this._status.property.gold * goldLossPct) / 100);
      this._status.property.gold -= lost;
    }
    this._status.cursor.zone += 1;
    this._status.cursor.position = null;
    // 先行一步：派出的干员返回。
    // - 基础：归来带回 2 希望（先行一步节点"干员将在下一层开始时归来"，官方选树口述）。
    // - 三结局·纠缠调和：持有【怦然信标】的 ending 分支额外发【怦然信标】
    //   （gameConst.expedEndingRelic = rogue_6_relic_final_3）。
    // - 【生命游戏】"喙"节点（rogue_6_outbuff_33，RAW_TEXT_EFFECT"“先行一步”归来时额外获得
    //   随机加工品"）：归来时额外获得 1 个随机加工品——从 excel 该节点 rawDesc 读取判定。
    const expDetails = this.troop.expeditionDetails as any;
    if (this.troop.expedition.length > 0) {
      const detail = excel.RoguelikeTopicTable.details[theme] as any;
      // 基础：2 希望（先行一步派发归来通用奖励）
      await this._trigger.emit("rlv2:get:items", [
        [{ id: `${theme}_population`, count: 2 }],
      ]);
      // «喙»已点亮 → 额外随机加工品（读取 excel 科技树节点 rawDesc 判定，与"翅膀"同模式）
      if (this.isBeakUnlocked()) {
        this.gainRandomScrap();
      }
      // 三结局分支：额外怦然信标
      if (expDetails?.ending) {
        const endingRelic = detail?.gameConst?.expedEndingRelic;
        if (endingRelic) {
          await this._trigger.emit("rlv2:relic:gain", [
            { id: endingRelic, count: 1 },
          ]);
        }
      }
      this.troop.expedition = [];
      delete expDetails.ending;
    }
    await this._trigger.emit("rlv2:zone:new", [this._status.cursor.zone]);
    // 特勤干员任务：到达区域事件（Rlv2PassZoneSpec）
    await this.emitSpecialOperatorZone(this._status.cursor.zone);
    return false;
  }

  /** 是否持有指定收藏品（按 id） */
  private hasRelic(id: string): boolean {
    return Object.values(this.inventory?.relic || {}).some(
      (r) => (r as any).id === id,
    );
  }

  /**
   * 特勤干员任务：到达区域事件（Rlv2PassZoneSpec）。
   * 进入新区域时调用——携带当前主题/模式/难度与区域 id（zone_N）。
   * @param zone 当前区域序号（cursor.zone）
   */
  private async emitSpecialOperatorZone(zone: number): Promise<void> {
    const game = this.current.game;
    if (!game) return;
    await this._trigger.emit("Rlv2PassZoneSpec", [
      {
        theme: game.theme,
        mode: game.mode,
        grade: game.modeGrade ?? 0,
        zoneId: `zone_${zone}`,
      },
    ]);
  }

  /**
   * 本局已通过节点类型计数（trace 轨迹 → 地图节点 type → 次数）。
   * 供特勤干员结算任务统计祸乱/紧急作战节点数。
   * @returns 节点类型数值 → 通过次数
   */
  private nodeTypeCounts(): Map<number, number> {
    const counts = new Map<number, number>();
    for (const t of this._status.trace) {
      const node = this._map.zones[this.zoneKey(t.zone)]?.nodes[
        `${(t.position?.x ?? 0) * 100 + (t.position?.y ?? 0)}`
      ];
      const type = node?.type ?? 0;
      counts.set(type, (counts.get(type) ?? 0) + 1);
    }
    return counts;
  }

  /**
   * 特勤干员任务：结算事件（gameSettle 成功达成结局时调用）。
   *
   * 依据本局轨迹/队伍与累计分队记录，发出 Rlv2* 结算类任务事件：
   * - Rlv2BandGradeCnt / Rlv2EndingBandGradeCnt / Rlv2EndingModeGrade：按累计分队记录
   *   （bandCnt/bandGrade）统计，模板自行按各任务 param 门槛过滤。
   * - Rlv2EndingWithBandChar / EndingWithCharPassSpBattle / EndingWithCandleChar /
   *   EliteBattleWithChar：按本局事实判定（分队、入队干员、节点通过、结局）。
   * @param theme 主题 id
   * @param ending 本局达成结局 id
   */
  private async emitSpecialOperatorSettle(
    theme: string,
    ending: string,
  ): Promise<void> {
    const game = this.current.game;
    if (!game) return;
    const mode = game.mode;
    // 特勤干员任务均针对「常规行动」（NORMAL 模式）——MONTH_TEAM 等特殊模式不计入
    if (mode !== "NORMAL") return;
    const grade = game.modeGrade ?? 0;
    const bandId = this._bandId || "";
    const charIds = Object.keys(this.troop.chars || {});
    const rec = (this.outer?.[theme]?.record as any) || {};
    const bandGrade: Record<string, Record<string, number>> =
      rec.bandGrade || {};
    const bandCnt: Record<string, Record<string, number>> = rec.bandCnt || {};

    // 本局节点通过：祸乱（BATTLE/BATTLE_HARD 近似作战/紧急作战）与紧急作战数
    const nodeCounts = this.nodeTypeCounts();
    const spBattleCount = (nodeCounts.get(1) ?? 0) + (nodeCounts.get(2) ?? 0);
    const eliteCount = nodeCounts.get(2) ?? 0;
    // 岁兽残识：所有入队干员即伺烛客（秉烛）
    const candleCharCount = charIds.length;

    await this._trigger.emit("Rlv2BandGradeCnt", [{ theme, bandGrade }]);
    await this._trigger.emit("Rlv2EndingBandGradeCnt", [
      { theme, bandGrade, bandCnt, ending },
    ]);
    await this._trigger.emit("Rlv2EndingModeGrade", [
      { theme, bandGrade, bandCnt, ending },
    ]);
    await this._trigger.emit("Rlv2EndingWithBandChar", [
      { theme, mode, grade, bandId, charIds, ending },
    ]);
    await this._trigger.emit("Rlv2EndingWithCharPassSpBattle", [
      { theme, mode, grade, charIds, spBattleCount, ending },
    ]);
    await this._trigger.emit("Rlv2EndingWithCandleChar", [
      { theme, mode, grade, charIds, candleCharCount, ending },
    ]);
    await this._trigger.emit("Rlv2EliteBattleWithChar", [
      { theme, mode, grade, charIds, eliteCount, ending },
    ]);
  }

  async selectChoice(args: { choice: string }): Promise<void> {
    const { choice } = args;
    const theme = this.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme];
    const choiceConfig = detail.choices[choice] as any;
    // 效果数据（lose/get/m_lose/m_get/i_get/i_lose 与后续选项）来自 data/rlv2/event_choices.json
    const eventConfig = this._data.eventChoices?.[theme]?.choices?.[choice] as any;

    // GAME_INIT_SUPPORT（开局 buff/行动奖励）：发放 displayData.itemId 奖励并消费 SUPPORT 事件。
    // 客户端抓包（rogue_6）：chooseInitialRelic → finishEvent → selectChoice(choice_roX_startbuff_N)
    // 防御：客户端先 selectChoice 后 finishEvent 时 pending[0] 可能是 GAME_INIT_GIFT（rogue_6
    // 开局礼物）——先消费礼物再处理支援选择（与 finishEvent 的消费逻辑一致）
    let top = this._status.pending[0];
    if (top && top.type === "GAME_INIT_GIFT") {
      const giftItems = top.content.initGift?.items || [];
      this._trigger.emit("rlv2:get:items", [giftItems]);
      this._status.pending.shift();
      top = this._status.pending[0];
    }
    if (top && top.type === "GAME_INIT_SUPPORT") {
      const cfg = choiceConfig as any;
      const desc = (cfg?.description as string) || "";
      const dd = cfg?.displayData || {};
      const prop = this._status.property;
      // 结算描述中的 <lose> 消耗。开局 buff（行动奖励）选项常带“消耗”，此前只发放 get 奖励、
      // 未扣对应资源，导致实际消耗与 UI 描述不符（如 startbuff_3“消耗6源石锭”却未扣 gold）。
      // 依据描述关键字映射资源类型，避免与后续 get 奖励混淆。
      const loseTags = [...desc.matchAll(/<@[^>]*\.lose>([^<]*)<\/>/g)];
      for (const m of loseTags) {
        const raw = m[1].trim();
        const num = parseInt(raw, 10);
        if (desc.includes("源石锭")) {
          // “消耗N源石锭”扣 gold；“消耗所有源石锭”清空
          prop.gold = Number.isNaN(num) ? 0 : Math.max(0, prop.gold - num);
        } else if (desc.includes("目标生命值上限")) {
          // “消耗N目标生命值上限”：扣上限并夹取当前值（startbuff_4 退行补偿）
          prop.hp.max = Math.max(0, prop.hp.max - num);
          prop.hp.current = Math.min(prop.hp.current, prop.hp.max);
        } else if (desc.includes("零件箱容量")) {
          // “零件箱容量-1 / +N”：scrap 零件箱容量上限，值可为负（startbuff_6 巢寄生缩减）
          const sm = this._module.scrap;
          if (!Number.isNaN(num) && sm) sm.setLimit(sm.limit + num);
        } else if (desc.includes("希望")) {
          // “消耗N希望及等量上限”：扣希望（人口）上限（老主题回收战利品）
          prop.population.max = Math.max(0, prop.population.max - num);
        }
      }
      // 官方 displayData.itemID（PascalCase ID）——startbuff_2/3 有 itemID；startbuff_1/4/5/6 无
      const itemId = dd.itemID ?? dd.itemId;
      if (itemId) {
        const itemDef =
          excel.RoguelikeTopicTable.details[theme]?.items?.[itemId];
        // 奖励数量：description 含 <@roX.get>N</>（如"获得<@ro6.get>8</>源石锭"；
        // 带符号的"零件箱容量<@ro6.get>+2</>"也需命中，空间租赁 +2）
        const m = desc.match(/<@ro\d+\.get>([+-]?\d+)<\/>/);
        const count = m ? parseInt(m[1], 10) : 1;
        if (itemDef?.type === "MAX_WEIGHT") {
          // 零件箱容量型（MAX_WEIGHT 无专属结算）：零件箱容量上限+count（startbuff_3“空间租赁”+2）
          const sm = this._module.scrap;
          if (sm) sm.setLimit(sm.limit + (count || 1));
        } else {
          this._trigger.emit("rlv2:get:items", [[{ id: itemId, count }]]);
        }
      } else {
        // 无 itemId：按官方 funcIconId 语义分发（prts.wiki 行动奖励）：
        // 未编号物=1 件普通收藏品（NORMAL 池）；巢寄生=1 件稀有收藏品（RARE 池）；
        // 林间代步=1 件加工品（MOVE 型零件）；其余（退行补偿）=全量池随机藏品。
        const theme = this.current.game!.theme;
        const funcIcon = (dd.funcIconId as string) || "";
        const hasRelic = Object.values(this.inventory!.relic || {}).map(
          (r) => (r as any).id,
        );
        if (funcIcon === "initial_reward_scrap_move" || desc.includes("加工品")) {
          // 林间代步：scrapItemToType 中 MOVE 型零件随机 1 件入零件箱
          const typeMap = (excel.RoguelikeTopicTable.modules[theme]?.scrap as any)
            ?.scrapItemToType || {};
          const moveIds = Object.keys(typeMap).filter(
            (id) => typeMap[id] === "MOVE",
          );
          if (moveIds.length > 0) {
            const scrapId = moveIds[Math.floor(Math.random() * moveIds.length)];
            await this._trigger.emit("rlv2:scrap:gain", [scrapId]);
          }
        } else {
          const poolId =
            funcIcon === "initial_reward_relic" || desc.includes("普通收藏品")
              ? "pool_relic_normal"
              : funcIcon === "initial_reward_unknown_pay_weight" ||
                  desc.includes("稀有收藏品")
                ? "pool_relic_rare"
                : "pool_relic_all";
          const rewardId =
            this._pool.getRelic(poolId, hasRelic) ||
            (poolId !== "pool_relic_all"
              ? this._pool.getRelic("pool_relic_all", hasRelic)
              : "");
          if (rewardId) {
            await this._trigger.emit("rlv2:relic:gain", [
              { id: rewardId, count: 1 },
            ]);
          } else {
            this._trigger.emit("rlv2:get:items", [
              [{ id: `${theme}_gold`, count: 5 }],
            ]);
          }
        }
      }
      this._status.pending.shift();
      // 开局阶段后续仍有 GAME_INIT_RECRUIT_SET/RECRUIT → 保持 INIT（官方 selectChoice 响应 state=INIT），
      // 全部消费完才进入 WAIT_MOVE（finishEvent 消费 GAME_INIT_RECRUIT 时切换）
      const hasInit = this._status.pending.some((e) =>
        (e.type || "").startsWith("GAME_INIT_"),
      );
      this._status.state = hasInit ? "INIT" : "WAIT_MOVE";
      return;
    }

    // 误入奇境（rogue_6 portal 场景）：消耗 1 件加工品进入隐藏层（未萌生的摇篮）
    // _1.._3=消耗加工品进入（无加工品→无加工品场景 _2）、_4=直接进入、_5=无加工品、_6=离开
    const portalM = choice.match(/^choice_ro\d+_portal(\d+[ab]?)_(\d+)$/);
    if (portalM && this.current.game!.theme === "rogue_6") {
      const family = portalM[1];
      const suffix = portalM[2];
      const numFamily = family.replace(/[ab]$/, "");
      const finishPortal = () => {
        this._status.pending.shift();
        this._status.state = "WAIT_MOVE";
      };
      if (suffix === "4") {
        // 进入黑潭（不消耗加工品）
        this.enterPortalZone(numFamily);
        return;
      }
      if (suffix === "1" || suffix === "2" || suffix === "3") {
        if (this.consumePortalScrap()) {
          this.enterPortalZone(numFamily);
        } else {
          // 没有可用的加工品 → 节点结束（客户端展示对应提示）
          finishPortal();
        }
        return;
      }
      // _5 无加工品 / _6 离开 → 节点结束
      finishPortal();
      return;
    }

    // 二结局·维度重构——命运所指（好奇心与死 end1 / 窥视箱中 end2）
    if (theme === "rogue_6" && /^choice_ro6_end2_[14]$/.test(choice)) {
      // 找到传出声音的位置 → 决战场景（仅给"与当前区域首领的决战"选项）
      this._status.pending.shift();
      const c3 = { choice_ro6_end2_3: 1, choice_ro6_end2_4: 1 };
      const ca3 = {
        choice_ro6_end2_3: { rewards: [] },
        choice_ro6_end2_4: { rewards: [] },
      };
      this._trigger.emit("rlv2:event:create", [
        "SCENE",
        {
          scene: { id: "scene_ro6_end2_2", choices: c3, choiceAdditional: ca3 },
          done: false,
          popReport: false,
        },
      ]);
      return;
    }
    if (theme === "rogue_6" && choice === "choice_ro6_end2_3") {
      // 与当前区域首领的决战 → 混沌源阶理论（ro6_b_5，险路恶敌）
      this.startChaosSourceBattle();
      return;
    }
    if (theme === "rogue_6" && /^choice_ro6_end1_[12]$/.test(choice)) {
      // 好奇心与死：消耗 50 源石锭标记（找投影位置）/ 获得 1 件收藏品
      if (choice === "choice_ro6_end1_1") {
        this._status.property.gold = Math.max(
          0,
          this._status.property.gold - 50,
        );
      } else {
        const hasRelic = Object.values(this.inventory!.relic || {}).map(
          (r) => (r as any).id,
        );
        const rid = this._pool.getRelic("pool_relic_all", hasRelic);
        if (rid) {
          this._trigger.emit("rlv2:relic:gain", [{ id: rid, count: 1 }]);
        }
      }
      this._status.pending.shift();
      this._status.state = "WAIT_MOVE";
      return;
    }
    // 二结局·线人（bomb1：不期而遇“线人与线索”）→ 沙盘α / 珍贵加工品 / 离开
    if (theme === "rogue_6" && /^choice_ro6_bomb1_/.test(choice)) {
      if (choice === "choice_ro6_bomb1_1") {
        await this._trigger.emit("rlv2:relic:gain", [
          { id: "rogue_6_relic_final_1", count: 1 },
        ]);
      } else if (choice === "choice_ro6_bomb1_2") {
        this.gainPreciousScrap();
      }
      this._status.pending.shift();
      this._status.state = "WAIT_MOVE";
      return;
    }

    // 不期而遇事件选项（res/relic/normal/bat/bat6b/task/chimera 系列）：
    // 事件引擎统一结算（描述文本解析消耗 / displayData 发放 / 随机分支 / 场景图推进 / 战斗）
    if (
      theme === "rogue_6" &&
      /^choice_ro6_(res\d|relic\d|normal\d|bat\d|task\d|chimera\d)/.test(choice)
    ) {
      if (await this._incident.resolveChoice(choice)) return;
    }

    // 非战斗事件节点选项（安全的角落/得偿所愿/失与得/险路尽头/险路小径/先行一步）：
    // 引擎结算完整效果（区域出口推进/行动力转化/收藏品与零件交换/招募等）
    if (
      theme === "rogue_6" &&
      /^choice_ro6_(rest|wish|sacrifice|final|evacuate|scout)/.test(choice)
    ) {
      if (await this._incident.resolveNodeChoice(choice)) return;
    }

    if (choice === "choice_leave") {
      this._status.pending.shift();
      await this.checkZoneEnd();
      this._status.state = "WAIT_MOVE";
      return;
    }

    const isBattle = choice.includes("bat") || typeof eventConfig?.choices === "string";

    // 构建下一场景 SCENE 事件的选项表（选项列表来自 event_choices 的 choices 数组）
    const buildSceneChoices = (sceneId: string) => {
      const list = Array.isArray(eventConfig?.choices) ? (eventConfig.choices as string[]) : [];
      const choices = list.reduce((acc, key) => ({ ...acc, [key]: 1 }), {});
      const choiceAdditional = list.reduce((acc, key) => ({ ...acc, [key]: { rewards: [] } }), {});
      this._status.pending.shift();
      this._trigger.emit("rlv2:event:create", [
        "SCENE",
        {
          scene: { id: sceneId, choices, choiceAdditional },
          done: false,
          popReport: false,
        },
      ]);
    };

    if (isBattle) {
      const nextSceneId = choiceConfig?.nextSceneId;
      if (nextSceneId) {
        buildSceneChoices(nextSceneId);
      } else {
        const stageKeyword =
          typeof eventConfig?.choices === "string" ? (eventConfig.choices as string) : undefined;
        let stageId = stageKeyword;
        if (stageKeyword && stageKeyword.endsWith("_")) {
          const stageKeys = Object.keys(detail.stages || {}).filter((k) => k.includes(stageKeyword));
          if (stageKeys.length > 0) {
            stageId = stageKeys[Math.floor(Math.random() * stageKeys.length)];
          }
        }

        if (stageId) {
          const nodeId = this._status.cursor.position
            ? this._status.cursor.position.x * 100 + this._status.cursor.position.y
            : 0;
          const zone = this._status.cursor.zone;
          if (this._map.zones[zone]?.nodes[nodeId]) {
            this._map.zones[zone].nodes[nodeId].stage = stageId;
          }

          this._status.pending.shift();
          this._trigger.emit("rlv2:event:create", [
            "BATTLE",
            {
              state: 1,
              chestCnt: 100,
              goldTrapCnt: 100,
              diceRoll: [],
              boxInfo: {},
              tmpChar: [],
              sanity: 0,
              unKeepBuff: [],
            },
          ]);
        }
      }
    } else {
      const nextSceneId = choiceConfig?.nextSceneId;
      if (nextSceneId) {
        // 先行一步（rogue_6 三结局·纠缠调和）：选择"派一名同伴进入/探索"
        // （choice_ro6_scout_1/3 → scene_ro6_scout_2/3）→ 标记三结局远征，
        // 干员下一层返回时带回 2 希望 + 【怦然信标】（gameConst.expedEndingRelic）
        if (theme === "rogue_6" && /^choice_ro6_scout_[13]$/.test(choice)) {
          (this.troop.expeditionDetails as any).ending = true;
        }
        const lose = eventConfig?.lose;
        const get = eventConfig?.get;
        const mLose = eventConfig?.m_lose;
        const mGet = eventConfig?.m_get;
        const iGet = eventConfig?.i_get;
        const iLose = eventConfig?.i_lose;

        if (mLose) {
          this._module.applyModuleDelta(mLose, -1);
        }
        if (mGet) {
          this._module.applyModuleDelta(mGet, 1);
        }
        if (iGet) {
          this.applyInventoryDelta(iGet, 1);
        }
        if (iLose) {
          this.applyInventoryDelta(iLose, -1);
        }
        if (lose && typeof lose === "object") {
          this.applyPropertyDelta(lose, -1);
          if (this._status.property.gold < 0) {
            this._status.property.gold = 0;
          }
        }
        if (get && typeof get === "object") {
          this.applyPropertyDelta(get, 1);
        }
        if (typeof get === "string") {
          const itemKeys = Object.keys(detail.items || {}).filter(
            (k) => k.includes(get) && !k.includes("curse_")
          );
          if (itemKeys.length > 0) {
            const itemId = itemKeys[Math.floor(Math.random() * itemKeys.length)];
            this._trigger.emit("rlv2:get:items", [[{ id: itemId, count: 1 }]]);
          }
        }

        // 官方选项效果：displayData.itemID（PascalCase ID；rogue_6 数据如此）+ 描述 GET 数量
        // （REST 回血/进阶券/希望等节点特有效果；rogue_6 无 event_choices 效果表，由此派生）
        const dd = (choiceConfig?.displayData as any) || {};
        const officialItem = dd.itemID ?? dd.itemId;
        if (officialItem) {
          const m = (choiceConfig?.description || "").match(
            /<@ro\d+\.get>(\d+)<\/>/,
          );
          const count = m ? parseInt(m[1], 10) : 1;
          this._trigger.emit("rlv2:get:items", [
            [{ id: officialItem, count }],
          ]);
        }

        buildSceneChoices(nextSceneId);
      } else {
        this._status.pending.shift();
        this._status.state = "WAIT_MOVE";
      }
    }
  }

  applyPropertyDelta(delta: { [key: string]: any }, sign: number): void {
    Object.entries(delta).forEach(([key, value]) => {
      const target = (this._status.property as any)[key];
      if (target === undefined) return;
      if (typeof value === "object" && value !== null) {
        // 嵌套对象（如 hp: {current: 2}）——事件效果常见格式
        Object.entries(value).forEach(([subKey, subVal]) => {
          if (typeof target?.[subKey] === "number" && typeof subVal === "number") {
            target[subKey] += sign * subVal;
          }
        });
      } else if (typeof target === "number" && typeof value === "number") {
        (this._status.property as any)[key] = target + sign * value;
      }
    });
  }

  applyInventoryDelta(delta: { [key: string]: any }, sign: number): void {
    Object.entries(delta).forEach(([key, value]) => {
      if (key === "consumable" && typeof value === "object") {
        Object.entries(value).forEach(([itemId, count]) => {
          this._trigger.emit("rlv2:get:items", [[{ id: itemId, count: sign * (count as number) }]]);
        });
      }
    });
  }

  /**
   * 生成商店商品（对照官方抓包 2026-08：票/碎片/战术道具/藏品混合，价格按类型+稀有度：
   * 招募票 4、临时票 8、碎片 4、战术道具 8、藏品 NORMAL 8 / RARE 12 / SUPER_RARE 16；
   * 约 25% 商品打折（displayPriceChg=true，价减半，官方抓包确认）。
   */
  generateShopGoods(theme: string): any[] {
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const items = detail?.items || {};
    const priceId = `${theme}_gold`;

    const priceOf = (itemId: string): number => {
      const item = items[itemId];
      if (!item) return 4;
      if (item.type === "RECRUIT_TICKET") return itemId.includes("_temp_") ? 8 : 4;
      if (item.type === "UPGRADE_TICKET") return 6;
      if (item.type === "CUSTOM_TICKET") return 8;
      if (item.type === "FRAGMENT") return 4;
      if (item.type === "ACTIVE_TOOL") return 8;
      if (item.type === "RELIC") {
        if (item.rarity === "RARE") return 12;
        if (item.rarity === "SUPER_RARE") return 16;
        return 8;
      }
      return 8;
    };

    const shuffled = (arr: string[]) => [...arr].sort(() => Math.random() - 0.5);

    // 藏品池过滤已拥有；按稀有度分层各抽 1 件再补齐到 4 件（避免全抽同档）
    const hasRelic = Object.values(this.inventory?.relic || {}).map(
      (r) => (r as any).id,
    );
    const relicPool = Object.keys(items).filter(
      (id) =>
        items[id]?.type === "RELIC" &&
        !hasRelic.includes(id) &&
        // 二结局专属藏品（沙盘α/β）不走随机商店池——仅经线人事件/Ⅰ-Ⅲ 层行商专属渠道获得
        !["rogue_6_relic_final_1", "rogue_6_relic_final_2"].includes(id),
    );
    const tier = (id: string) =>
      items[id]?.rarity === "RARE" ? 1 : items[id]?.rarity === "SUPER_RARE" ? 2 : 0;
    const byTier: string[][] = [[], [], []];
    for (const id of relicPool) byTier[tier(id)].push(id);
    const relicPicks: string[] = [];
    for (const t of [0, 1, 2]) {
      const pool = shuffled(byTier[t]);
      if (pool.length > 0) relicPicks.push(pool[0]);
    }
    while (relicPicks.length < 4) {
      const rest = relicPool.filter((id) => !relicPicks.includes(id));
      if (rest.length === 0) break;
      relicPicks.push(shuffled(rest)[0]);
    }

    const ticketPool = Object.keys(detail?.recruitTickets || {}).filter(
      (id) =>
        !id.endsWith("_all") &&
        !id.includes("_5star") &&
        !id.includes("_quad_") &&
        !id.includes("_special"),
    );
    const fragmentPool = Object.keys(items).filter(
      (id) => items[id]?.type === "FRAGMENT",
    );
    const toolPool = Object.keys(items).filter(
      (id) => items[id]?.type === "ACTIVE_TOOL",
    );

    const goods: any[] = [];
    let i = 0;
    const pushGood = (itemId: string) => {
      const orig = priceOf(itemId);
      const discount = Math.random() < 0.25;
      const priceCount = discount ? Math.max(1, Math.round(orig * 0.5)) : orig;
      goods.push({
        index: `${i}`,
        itemId,
        count: 1,
        priceId,
        priceCount,
        origCost: orig,
        displayPriceChg: discount,
        _retainDiscount: discount ? priceCount / orig : 1,
      });
      i++;
    };

    const tPool = shuffled(ticketPool);
    if (tPool.length > 0) pushGood(tPool[0]);
    if (fragmentPool.length > 0) pushGood(shuffled(fragmentPool)[0]);
    if (toolPool.length > 0) pushGood(shuffled(toolPool)[0]);
    for (const id of relicPicks) pushGood(id);

    return goods;
  }

  /**
   * 构建商店内容（battleShop，官方 pending BATTLE_SHOP 线格式）：
   * bank/id/goods/canBattle/hasBoss/refreshCnt/showRefresh/withdrawMethod/refreshMethod；
   * FRAGMENT 模块主题附 recycleGoods（碎片回收 1 金币/件，官方抓包确认）。
   */
  buildShopContent(theme: string): any {
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const zone = this._status.cursor.zone;
    // 官服商店 id 用层号（cursor.zone 1000 起为网格区域索引——减 999 还原层号）
    const layer = zone > 999 ? zone - 999 : zone;
    const goods = this.generateShopGoods(theme);
    // 二结局·维度重构：沙盘β 大概率在 Ⅰ-Ⅲ 层诡意行商以 1 源石锭出售（未持有才出现）
    if (theme === "rogue_6" && layer >= 1 && layer <= 3) {
      const hasRelic = Object.values(this.inventory?.relic || {}).map(
        (r) => (r as any).id,
      );
      if (!hasRelic.includes("rogue_6_relic_final_2")) {
        goods.push({
          index: String(goods.length),
          itemId: "rogue_6_relic_final_2",
          count: 1,
          priceId: `${theme}_gold`,
          priceCount: 1,
          origCost: 1,
          displayPriceChg: false,
          _retainDiscount: 1,
        });
      }
    }
    const content: any = {
      bank: {
        open: true,
        canPut: true,
        canWithdraw: true,
        withdraw: 0,
        cost: 1,
        withdrawLimit: 20,
      },
      id: `zone_${layer}_shop`,
      goods,
      canBattle: true,
      hasBoss: true,
      refreshCnt: 2,
      showRefresh: true,
      withdrawMethod: "fee_add",
      refreshMethod: "direct",
      _done: false,
    };
    const fragments = Object.keys(detail?.items || {}).filter(
      (id) => detail.items[id]?.type === "FRAGMENT",
    );
    if (fragments.length > 0) {
      content.recycleGoods = fragments.slice(0, 6).map((id, idx) => ({
        index: `f_${idx + 1}`,
        itemId: id,
        count: 1,
        priceId: `${theme}_gold`,
        priceCount: 1,
        origCost: 1,
        displayPriceChg: false,
      }));
      content.recycleCount = content.recycleGoods.length;
    }
    return content;
  }

  async buyGoods(args: { select: number }): Promise<void> {
    const { select } = args;
    // 兼容 BATTLE_SHOP（官方，content.battleShop）与旧格式 SHOP（content.shop）
    const shopEvent = this._status.pending.find(
      (e) => e.type === "BATTLE_SHOP" || e.type === "SHOP",
    );
    if (!shopEvent) return;
    const shop = shopEvent.content.battleShop ?? shopEvent.content.shop;
    if (!shop) return;

    const goods = shop.goods || [];
    const selectedGood = goods[select];
    if (!selectedGood || selectedGood.count <= 0) return;

    const priceCount = selectedGood.priceCount || 0;
    if (priceCount > 0 && this._status.property.gold < priceCount) {
      return;
    }

    if (priceCount > 0) {
      this._status.property.gold -= priceCount;
    }

    const itemId = selectedGood.itemId;
    if (itemId.includes("_recruit_ticket_")) {
      this._trigger.emit("rlv2:recruit:gain", [itemId, "shop", 0]);
      const tickets = Object.values(this.inventory!.recruit);
      const ticketIndex = tickets[tickets.length - 1]?.index;
      if (ticketIndex) {
        this._trigger.emit("rlv2:recruit:active", [ticketIndex]);
        // 参数键名与 events.ts RECRUIT 构造一致（tickets）——原传 {ticket} 导致 undefined
        this._trigger.emit("rlv2:event:create", ["RECRUIT", { tickets: ticketIndex }]);
      }
    } else if (itemId.includes("_relic_")) {
      this._trigger.emit("rlv2:relic:gain", [{ id: itemId, count: 1 }]);
    } else if (
      itemId.includes("_active_tool_") ||
      itemId.includes("_explore_tool_")
    ) {
      this._trigger.emit("rlv2:get:items", [[{ id: itemId, count: 1 }]]);
    } else {
      // 碎片/其他物品：通用发放（inventory.getItem 按类型分发）
      this._trigger.emit("rlv2:get:items", [[{ id: itemId, count: 1 }]]);
    }

    // 官方：售出商品保留在列表但 count 置 0（已售罄标记，非移除）
    selectedGood.count = 0;
  }

  /** 商店刷新：重生成当前商店商品并扣除刷新次数 */
  async refreshShop(): Promise<void> {
    const shopEvent = this._status.pending.find(
      (e) => e.type === "BATTLE_SHOP" || e.type === "SHOP",
    );
    if (!shopEvent) return;
    const shop = shopEvent.content.battleShop ?? shopEvent.content.shop;
    if (!shop || (shop.refreshCnt ?? 0) <= 0) return;
    shop.goods = this.generateShopGoods(this.current.game!.theme);
    shop.refreshCnt -= 1;
  }

  /** 离开商店：填充 traderReturn（商人返回礼物，confirmTraderReturn 发放）并清空 pending */
  async leaveShop(): Promise<void> {
    // 商人返回：离开商店时填充（部分主题/商店类型有商人礼物）
    if (!this._status.traderReturn) {
      const theme = this.current.game!.theme;
      const hasRelic = Object.values(this.inventory!.relic || {}).map(
        (r) => (r as any).id,
      );
      const rewardId = this._pool.getRelic("pool_relic_all", hasRelic);
      if (rewardId) {
        this._status.traderReturn = {
          t0: { id: rewardId, count: 1, instId: "" },
        };
      }
    }
    this._status._pending._pending.length = 0;
    await this.checkZoneEnd();
    this._status.state = "WAIT_MOVE";
  }

  /** 确认预兆（rogue_3 独有）：清理 pending 回到等待移动状态 */
  async confirmPredict(): Promise<void> {
    this._status._pending._pending.length = 0;
    await this.checkZoneEnd();
    this._status.state = "WAIT_MOVE";
  }

  /** 使用图腾：接线图腾管理器 use（上下板效果） */
  async useTotem(args: {
    totemIndex: [string, string];
    nodeIndex: string[];
  }): Promise<void> {
    this._module.totem.use(args.totemIndex, args.nodeIndex);
  }

  /** 关闭招募票：标记关闭（state=3）并清空候选列表 */
  async closeRecruitTicket(args: { id: string }): Promise<void> {
    const ticket = this.inventory!.recruit[args.id];
    if (!ticket) return;
    ticket.state = 3;
    ticket.list = [];
    // 票保留（state=3 终态）；inventory.recruit 由 finishEvent 初始阶段统一清空
    // （官服进入第一层 WAIT_MOVE 时 recruit={}）——若在此删除，客户端重复
    // close/后续请求读到空票会异常
  }

  async moveAndBattleStart(args: {
    to: RoguelikeNodePosition;
    stageId: string;
    squad: PlayerSquad;
  }): Promise<string> {
    await this.moveTo(args);
    const nodeId = args.to.x * 100 + args.to.y;
    const stageId =
      this._map.zones[this._status.cursor.zone].nodes[nodeId].stage!;
    await this._trigger.emit("rlv2:battle:start", [stageId]);
    return "";
  }

  async moveTo(args: { to: RoguelikeNodePosition }): Promise<void> {
    const theme = this.current.game!.theme;
    // 清空上一请求的残留推送（控制器为持久实例）
    this._pushMessages = [];
    const detail = excel.RoguelikeTopicTable.details[theme].gameConst;
    const pos = this._status.cursor.position;
    this._status.state = "PENDING";
    if (pos) {
      const nodeId = pos.x * 100 + pos.y;
      const node = this._map.zones[this._status.cursor.zone].nodes[nodeId];
      if (node.next.find((n) => n.x === args.to.x && n.y === args.to.y)?.key) {
        await this._trigger.emit("rlv2:get:items", [
          [
            {
              id: detail.unlockRouteItemId!,
              count: -detail.unlockRouteItemCount,
            },
          ],
        ]);
      }
    }
    this._buff.filterBuffs("overweight_move_cost").forEach((b) => {
      this._trigger.emit("rlv2:get:items", [
        [{ id: b.blackboard[0].valueStr!, count: -b.blackboard[1].value! }],
      ]);
    });
    await this._trigger.emit("rlv2:move", []);
    this._status.trace.push({
      zone: this._status.cursor.zone,
      position: args.to,
    });
    const next = this._map.findNode(this._status.cursor.zone, args.to);
    switch (next.type) {
      case TorappuRoguelikeEventType.INCIDENT: {
        // 不期而遇：从 event_choices 的 enter 场景池随机抽一个，生成 SCENE 事件
        const enterScenes = this._data.eventChoices?.[theme]?.enter;
        if (enterScenes) {
          const sceneIds = Object.keys(enterScenes);
          if (sceneIds.length > 0) {
            const sceneId = sceneIds[Math.floor(Math.random() * sceneIds.length)];
            const choicesList = enterScenes[sceneId] || [];
            const choices = choicesList.reduce((acc, cid) => ({ ...acc, [cid]: 1 }), {});
            const choiceAdditional = choicesList.reduce(
              (acc, cid) => ({ ...acc, [cid]: { rewards: [] } }),
              {},
            );
            this._status.state = "PENDING";
            this._trigger.emit("rlv2:event:create", [
              "SCENE",
              {
                scene: { id: sceneId, choices, choiceAdditional },
                done: false,
                popReport: false,
              },
            ]);
          }
        }
        break;
      }
      case TorappuRoguelikeEventType.SHOP:
      case 4096:
        this._status.state = "PENDING";
        this._trigger.emit("rlv2:event:create", [
          "BATTLE_SHOP",
          this.buildShopContent(theme),
        ]);
        break;
      default: {
        // 非战斗节点效果：按节点类型从官方 choiceScenes 抽 enter 场景，生成 SCENE
        // （REST 安全的角落 / WISH 得偿所愿 / TREASURE 古堡馈赠 / SACRIFICE 失与得 /
        //   ENTERTAINMENT 兴致盎然 / EXPEDITION 先行一步 / UNKNOWN 迷雾重重）
        this.createNodeScene(theme, next.type);
        break;
      }
    }
    this._status.cursor.position = args.to;
    // 节点到达推送（官服对齐）：rlv2NodeArrive 携节点类型，rlv2NodeChange 携当前 zone 节点列表。
    // 仅 rogue_6（黑流树海）范围内下发；其余主题静默跳过（pushMessage 仅在 rogue_6 累积）。
    if (theme === "rogue_6" && next) {
      const zoneNodes =
        this._map.zones[this._status.cursor.zone]?.nodes ?? {};
      this.pushMessage("rlv2NodeArrive", { nodeType: next.type });
      this.pushMessage("rlv2NodeChange", {
        nodeList: Object.keys(zoneNodes),
      });
    }
    // 特勤干员任务：节点通过事件（Rlv2PassNodeSpec）+ 岁兽残识移动消耗烛火（Rlv2SpZoneSteps 近似，
    // 每移动一步计 1 点烛火——后端未实现烛火机制，以步进近似）。
    const rlv2Game = this.current.game!;
    const rlv2Ctx = {
      theme: rlv2Game.theme,
      mode: rlv2Game.mode,
      grade: rlv2Game.modeGrade ?? 0,
    };
    await this._trigger.emit("Rlv2PassNodeSpec", [
      { ...rlv2Ctx, nodeType: next.type },
    ]);
    if (rlv2Game.theme === "rogue_5") {
      await this._trigger.emit("Rlv2SpZoneSteps", [
        { ...rlv2Ctx, cost: 1 },
      ]);
    }
  }

  /**
   * 节点类型 → 官方 enter 场景前缀映射
   * 场景前缀关联：scene_roX_{prefix}*_enter 与 choice_roX_{prefix}_*（选项）同前缀
   */
  private static readonly NODE_SCENE_PREFIX: {
    [type: number]: string[];
  } = {
    [TorappuRoguelikeEventType.REST]: ["rest"],
    [TorappuRoguelikeEventType.WISH]: ["relic"],
    [TorappuRoguelikeEventType.TREASURE]: ["chest"],
    [TorappuRoguelikeEventType.SACRIFICE]: ["sacrifice"],
    [TorappuRoguelikeEventType.ENTERTAINMENT]: ["ent"],
    [TorappuRoguelikeEventType.EXPEDITION]: ["scout"],
    [TorappuRoguelikeEventType.UNKNOWN]: ["nportal", "eportal"],
  };

  /**
   * 生成节点进入场景（SCENE 事件）
   * 从官方 choiceScenes 按节点类型前缀抽 enter 场景，选项取自官方 choices 同前缀列表
   * 效果：选项 displayData.itemId 在 selectChoice 时发放（官方配置）
   */
  private createNodeScene(theme: string, nodeType: number): void {
    const prefixes =
      RoguelikeV2Controller.NODE_SCENE_PREFIX[nodeType];
    if (!prefixes) return;
    const detail = excel.RoguelikeTopicTable.details[theme];
    const sceneIds = Object.keys(detail.choiceScenes || {}).filter(
      (id) =>
        id.endsWith("_enter") &&
        prefixes.some((p) => id.includes(`_${p}`)),
    );
    if (sceneIds.length === 0) return;
    const sceneId =
      sceneIds[Math.floor(Math.random() * sceneIds.length)];
    const roNum = theme.slice(-1);
    const prefix = prefixes.find((p) => sceneId.includes(`_${p}`))!;
    const choiceIds = Object.keys(detail.choices || {}).filter(
      (k) =>
        k.startsWith(`choice_ro${roNum}_${prefix}`) && !k.endsWith("_enter"),
    );
    if (choiceIds.length === 0) return;
    const choices = choiceIds.reduce(
      (acc, cid) => ({ ...acc, [cid]: 1 }),
      {},
    );
    const choiceAdditional = choiceIds.reduce(
      (acc, cid) => ({ ...acc, [cid]: { rewards: [] } }),
      {},
    );
    this._status.state = "PENDING";
    this._trigger.emit("rlv2:event:create", [
      "SCENE",
      {
        scene: { id: sceneId, choices, choiceAdditional },
        done: false,
        popReport: false,
      },
    ]);
  }

  async battleFinish(args: {
    battleLog: string;
    data: string;
    battleData: BattleData;
  }) {
    await this._trigger.emit("rlv2:battle:finish", [args]);
    // "流窜居民"驱逐结算：本次若为驱逐战（进入被占领节点 / "居民"据点），战斗胜利后
    // 驱逐目标——被占领节点被毁为林间空地；居民据点战胜则驱逐该层全部流窜居民。
    this._module.gridZone?.finishClearing();
    // 标准地图节点 fts 标记（网格区域用 gridZone 节点——标准地图可能无此节点，容错跳过）
    const pos = this._status.cursor.position;
    if (pos) {
      const node = this._map.zones[this._status.cursor.zone]?.nodes[
        `${pos.x * 100 + pos.y}`
      ];
      if (node) node.fts = now();
    }
  }

  async chooseBattleReward(args: { index: number; sub: number }) {
    const rewardGrp =
      this._status.pending[0]?.content?.battleReward?.rewards.find(
        (r) => r.index == args.index,
      );
    // 防御：未知奖励组不 500
    if (!rewardGrp) return;
    // 修复：done 未校验 → 同一奖励组的每个 sub 都能领一遍（boss 双遗物全拿）；
    // 已选择过则拒绝
    if (rewardGrp.done) return;
    const reward = rewardGrp.items.find((r) => r.sub == args.sub);
    if (!reward) return;
    // 招募券奖励：reward 无 type 字段，getItem 落 POOL 不触发招募（"拿到券不能招"）——
    // 招募券定义在 details[theme].recruitTickets（非 items），据此识别并显式标记 RECRUIT_TICKET。
    const theme = this.current.game!.theme;
    const item: any = { ...reward };
    if (excel.RoguelikeTopicTable.details[theme]?.recruitTickets?.[item.id]) {
      item.type = "RECRUIT_TICKET";
    }
    // await：getItem 为异步（gold/希望/招募券实时入账），不 await 会先序列化旧状态（奖励不实时）
    await this._trigger.emit("rlv2:get:items", [[item]]);

    rewardGrp.done = 1;
  }

  async finishBattleReward(args: {}) {
    // 指挥等级经验结算（文档：战斗胜利后结算战斗经验——earn.exp 从战斗结果带入）
    const rewardEvent = this._status.pending[0];
    const earnExp = rewardEvent?.content?.battleReward?.earn?.exp;
    if (earnExp) {
      const theme = this.current.game!.theme;
      // await：经验发放为异步，需在响应序列化前入账（否则 exp/升希望不实时）
      await this._trigger.emit("rlv2:get:items", [
        [{ id: `${theme}_exp`, count: earnExp }],
      ]);
    }
    this._status.pending.shift();
    await this.checkZoneEnd();
    this._status.state = "WAIT_MOVE";
  }

  /* ===== 完整机制实现（2026-08-10，对照官方抓包响应补全）===== */

  /** 读取结局变更（CS: RoguelikeReadEndingChangeRequest）：chgEnding → false 回到 WAIT_MOVE */
  async readEndingChange(): Promise<void> {
    this._status.chgEnding = false;
    this._status.state = "WAIT_MOVE";
  }

  /** 确认区域奖励（CS: RoguelikeZoneRewardRequest { itemType }）：发放 zoneReward 物品并清空 */
  async confirmZoneReward(): Promise<void> {
    const zoneReward = this._status.zoneReward;
    if (zoneReward && Object.keys(zoneReward).length > 0) {
      const items = Object.values(zoneReward).map((r) => ({
        id: r.id,
        count: r.count,
      }));
      await this._trigger.emit("rlv2:get:items", [items]);
      this._status.zoneReward = undefined;
    }
    this._status.state = "WAIT_MOVE";
  }

  /** 确认商人返回（CS: RoguelikeTraderReturnRequest）：发放 traderReturn 物品并清空 */
  async confirmTraderReturn(): Promise<void> {
    const traderReturn = this._status.traderReturn;
    if (traderReturn && Object.keys(traderReturn).length > 0) {
      const items = Object.values(traderReturn).map((r) => ({
        id: r.id,
        count: r.count,
      }));
      await this._trigger.emit("rlv2:get:items", [items]);
      this._status.traderReturn = undefined;
    }
    this._status.state = "WAIT_MOVE";
  }

  /** 离开特殊区域（CS: RoguelikeSpecialZoneLeaveRequest）：清空 pending 回到 WAIT_MOVE */
  async specialZoneLeave(): Promise<void> {
    this._status._pending._pending.length = 0;
    await this.checkZoneEnd();
    this._status.state = "WAIT_MOVE";
  }

  /**
   * 战令领奖（抓包请求 { theme, rewards: ["bp_level_N"] }）
   * 发放里程碑 itemID/itemCount 到主背包，outer[theme].bp.reward 标记已领
   * 官方响应抓包：items + modified.rlv2.outer.bp.reward（不含 point 变化）
   */
  async battlePassGetReward(
    theme: string,
    rewards: string[],
  ): Promise<{ items: ItemBundle[] }> {
    const milestones = excel.RoguelikeTopicTable.details[theme].milestones;
    if (!this.outer[theme]?.bp) return { items: [] };
    const items: ItemBundle[] = [];
    await this.update(async (draft) => {
      const bp = draft.outer[theme].bp;
      if (!bp.reward) bp.reward = {};
      for (const rewardId of rewards ?? []) {
        const milestone = milestones.find((m) => m.id === rewardId);
        if (!milestone || bp.reward[rewardId]) continue;
        bp.reward[rewardId] = 1;
        if (milestone.itemCount > 0) {
          items.push({
            type: milestone.itemType,
            id: milestone.itemID,
            count: milestone.itemCount,
          });
        }
      }
    });
    await this._trigger.emit("items:get", [items]);
    return { items };
  }

  /** 银行存钱（CS: RoguelikeBankInvestRequest）：bank.current/totalPut +1，record 取历史最高 */
  async bankPut(): Promise<void> {
    const theme = this.current.game!.theme;
    if (!this.outer[theme]?.bank) return;
    // 修复：存钱应扣 1 金币——原实现不扣任何资源，可 put→withdraw 循环无限刷金币
    if ((this._status.property.gold ?? 0) < 1) return;
    this._status.property.gold -= 1;
    await this.update(async (draft) => {
      const bank = draft.outer[theme].bank;
      bank.current = (bank.current || 0) + 1;
      bank.totalPut = (bank.totalPut || 0) + 1;
      bank.record = Math.max(bank.record || 0, bank.current);
      bank.show = true;
    });
    this._status.status.bankPut += 1;
    await this._trigger.emit("rlv2:bankPut", [true]);
  }

  /** 银行取钱（CS: RoguelikeBankWithdrawRequest { count }）：bank.current 减少，金币增加 */
  async bankWithdraw(args: { count?: number }): Promise<void> {
    const theme = this.current.game!.theme;
    const bank = this.outer[theme]?.bank;
    if (!bank) return;
    const count = Math.max(0, Math.min(args.count ?? 1, bank.current || 0));
    if (count <= 0) return;
    await this.update(async (draft) => {
      draft.outer[theme].bank.current -= count;
    });
    this._status.property.gold += count;
  }

  /** 确认节点任务（CS: RoguelikeConfirmNodeMissionRequest）：state=2 + 生成任务奖励 SCENE */
  async nodeMissionConfirm(): Promise<void> {
    const nm = this._status.nodeMission;
    if (!nm) return;
    nm.state = 2;
    const theme = this.current.game!.theme;
    const task = (excel.RoguelikeTopicTable.details[theme] as any)?.taskData?.[
      nm.id
    ];
    const sceneId = task?.rewardSceneId;
    if (sceneId) {
      const prefix = sceneId.replace(/^scene_/, "").replace(/_enter$/, "");
      const choiceIds = Object.keys(
        (excel.RoguelikeTopicTable.details[theme] as any)?.choices || {},
      ).filter((k) => k.startsWith(`choice_${prefix}_`) && !k.endsWith("_enter"));
      const choices = choiceIds.reduce((acc, cid) => ({ ...acc, [cid]: 1 }), {});
      const choiceAdditional = choiceIds.reduce(
        (acc, cid) => ({ ...acc, [cid]: { rewards: [] } }),
        {},
      );
      this._trigger.emit("rlv2:event:create", [
        "SCENE",
        {
          scene: {
            id: sceneId,
            choices,
            choiceAdditional,
            independent: true,
          },
          done: false,
          popReport: false,
        },
      ]);
    }
    this._status.state = "PENDING";
  }

  /** 放弃节点任务（CS: RoguelikeGiveUpNodeMissionRequest）：state=3 回到 WAIT_MOVE */
  async nodeMissionGiveUp(): Promise<void> {
    const nm = this._status.nodeMission;
    if (nm) nm.state = 3;
    this._status.state = "WAIT_MOVE";
  }

  /** 关闭节点任务提示（CS: RoguelikeReadMissionTipRequest）：tip → false */
  async nodeMissionCloseTip(): Promise<void> {
    const nm = this._status.nodeMission;
    if (nm) nm.tip = false;
  }

  /** 获取招募票助战列表（CS: RoguelikeGetTicketAssistListRequest）——单账号私服无好友，置空助战 */
  async getTicketAssistList(args: {
    ticketIndex: string;
    profession: string;
  }): Promise<void> {
    const ticket = this.inventory!.recruit[args.ticketIndex];
    if (!ticket) return;
    ticket.needAssist = false;
    ticket.assistList = ticket.assistList || {};
  }

  /** 招募助战干员（CS: RoguelikeRecruitAssistCharRequest）——无真实好友数据，静默关闭助战标记 */
  async recruitAssistChar(args: {
    ticketIndex: string;
    profession: string;
    assistUid: string;
    assistCharId: string;
  }): Promise<void> {
    const ticket = this.inventory!.recruit[args.ticketIndex];
    if (!ticket) return;
    ticket.needAssist = false;
  }

  /**
   * 远征选择（CS: RoguelikeExpeditionRequest { choice, leave }）
   * choice 为干员 instId（抓包 "8"）；写入 troop.expedition，回到 WAIT_MOVE
   * 官方响应：{ result: 1 } + troop.expedition + pending SCENE
   */
  async expeditionChoice(args: {
    choice?: string;
    leave?: number;
  }): Promise<{ result: number }> {
    if (args.leave) {
      this._status._pending._pending.length = 0;
      this._status.state = "WAIT_MOVE";
      return { result: 1 };
    }
    const ids = (args.choice || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    for (const id of ids) {
      if (!this.troop.expedition.includes(id)) {
        this.troop.expedition.push(id);
      }
    }
    this._status.state = "WAIT_MOVE";
    return { result: 1 };
  }

  /** 确认远征返回（CS: RoguelikeExpedReturnRequest）：清空远征列表回到 WAIT_MOVE */
  async confirmExpeditonReturn(): Promise<void> {
    this.troop.expedition = [];
    this.troop.expeditionReturn = null;
    this._status._pending._pending.length = 0;
    this._status.state = "WAIT_MOVE";
  }

  /** 骰子选择（CS: RoguelikeDiceChoiceRequest { choice: REROLL|LEAVE }）——rogue_2 DICE 模块真实结算 */
  async diceChoice(args: { choice?: string | number }): Promise<{ result: number }> {
    const choice = String(args.choice ?? "LEAVE").toUpperCase();
    const dm = this._module.dice;
    const theme = this.current.game!.theme;
    const diceEvent = this._status.pending.find((e) => e.type === "DICE");
    // 无 DICE 事件（非骰子流程）→ 直接回到 WAIT_MOVE
    if (!diceEvent) {
      this._status.state = "WAIT_MOVE";
      return { result: 1 };
    }
    if (choice === "REROLL") {
      // 重掷：重新生成骰子结果（重掷次数 +1）
      const result = this.rollDice(theme, dm);
      (diceEvent.content as any).dice = {
        result,
        rerollCount: ((diceEvent.content as any).dice?.rerollCount ?? 0) + 1,
      };
      this._status.state = "PENDING";
      return { result: 1 };
    }
    // LEAVE：接受结果，发放骰子事件奖励并消费 DICE 事件
    const dice = (diceEvent.content as any).dice as
      | { result?: { diceEventId: string } }
      | undefined;
    const diceEventId = dice?.result?.diceEventId || "";
    const detail = excel.RoguelikeTopicTable.details[theme];
    const eventData = (
      (excel.RoguelikeTopicTable.modules[theme] as any)?.dice?.diceEvents ||
      {}
    )[diceEventId];
    const showType = eventData?.showType;
    // 按结果类型发放简化奖励（启示/美德/钥匙等——官方通过 ruleGroup 黑板驱动）
    if (showType === "VIRTUE") {
      this._trigger.emit("rlv2:get:items", [[{ id: "rogue_2_gold", count: 3 }]]);
    } else if (showType === "KEY") {
      this._trigger.emit("rlv2:get:items", [[{ id: "rogue_2_gold", count: 5 }]]);
    } else {
      this._trigger.emit("rlv2:get:items", [[{ id: "rogue_2_gold", count: 2 }]]);
    }
    void detail;
    this._status._pending._pending.splice(
      this._status._pending._pending.indexOf(diceEvent),
      1,
    );
    this._status.state = "WAIT_MOVE";
    return { result: 1 };
  }

  /** 生成骰子结果（DICE 事件结算）：随机骰子事件 + 掷点 */
  private rollDice(theme: string, dm: any): any {
    const faceCount = dm?.faceCount ?? 6;
    const diceRoll = Math.floor(Math.random() * faceCount) + 1;
    const diceEvents = (
      excel.RoguelikeTopicTable.modules[theme] as any
    )?.dice?.diceEvents;
    const eventIds = diceEvents ? Object.keys(diceEvents) : [];
    const diceEventId =
      eventIds.length > 0
        ? eventIds[Math.floor(Math.random() * eventIds.length)]
        : "";
    return {
      diceEventId,
      diceRoll,
      mutation: { id: "", chars: [] },
      virtue: [],
    };
  }

  /** 献祭选择（CS: RoguelikeSacrificeRequest { choice, leave }）——失与得：献祭藏品换随机奖励 */
  async sacrificeChoice(args: {
    choice?: string;
    leave?: number;
  }): Promise<void> {
    const theme = this.current.game!.theme;
    const sacrificeEvent = this._status.pending.find(
      (e) => e.type === "SACRIFICE" || (e.type === "SCENE" && e.content?.sacrifice),
    );
    if (args.leave) {
      if (sacrificeEvent) {
        this._status._pending._pending.splice(
          this._status._pending._pending.indexOf(sacrificeEvent),
          1,
        );
      }
      this._status.state = "WAIT_MOVE";
      return;
    }
    // 可献祭藏品：玩家拥有的、官方 canSacrifice 且 value 8/12 的遗物（pool_sacrifice_n/r）
    const detail = excel.RoguelikeTopicTable.details[theme];
    const relicMap = this.inventory!.relic || {};
    const sacrificable = Object.values(relicMap).filter((r) => {
      const item = (detail.items as any)?.[(r as any).id];
      return item?.canSacrifice && (item?.value === 8 || item?.value === 12);
    });
    // 扣除献祭代价（choice 为选项序号；默认第一个可献祭藏品）
    const choiceIdx = parseInt(args.choice ?? "0", 10) || 0;
    const offered = sacrificable[choiceIdx] || sacrificable[0];
    if (offered) {
      // relic 库存以 index（r_N）为键，按条目键删除
      delete relicMap[(offered as any).index];
    }
    // 发放回报：随机未拥有藏品（池空回退金币）
    const hasRelic = Object.values(relicMap).map((r) => (r as any).id);
    const rewardId = this._pool.getRelic("pool_relic_all", hasRelic);
    if (rewardId) {
      this._trigger.emit("rlv2:relic:gain", [{ id: rewardId, count: 1 }]);
    } else {
      this._trigger.emit("rlv2:get:items", [
        [{ id: `${theme}_gold`, count: 8 }],
      ]);
    }
    if (sacrificeEvent) {
      this._status._pending._pending.splice(
        this._status._pending._pending.indexOf(sacrificeEvent),
        1,
      );
    }
    await this.checkZoneEnd();
    this._status.state = "WAIT_MOVE";
  }

  /** 炼金（CS: RoguelikeAlchemy 类，抓包 { leave, index: [f1, f2] }）——接线 fragment 合成 */
  async alchemy(args: { leave?: number; index?: string[] }): Promise<void> {
    if (args.leave) {
      this._status._pending._pending.length = 0;
      this._status.state = "WAIT_MOVE";
      return;
    }
    const fragmentMgr = this._module._modules["FRAGMENT"];
    if (fragmentMgr && args.index && args.index.length >= 2) {
      fragmentMgr.alchemy([args.index[0], args.index[1]]);
    }
    this._status.state = "WAIT_MOVE";
  }

  /** 炼金奖励（抓包 { index }）——发放合成奖励 */
  async alchemyReward(args: { index?: number }): Promise<void> {
    // 简化：炼金合成奖励已由 fragment.alchemy 发放；此处确认结算并关闭界面
    this._status._pending._pending.length = 0;
    this._status.state = "WAIT_MOVE";
  }

  /** 铜币镀金（CS: RoguelikeGildRequest { choice, leave }）——rogue_5 COPPER */
  async copperGild(args: { choice?: string; leave?: number }): Promise<void> {
    if (args.leave) {
      this._status._pending._pending.length = 0;
      this._status.state = "WAIT_MOVE";
      return;
    }
    const cm = this._module.copper;
    // 镀金当前已抽铜币（choice 为袋键）
    cm?.gild(args.choice || "");
    this._status.state = "WAIT_MOVE";
  }

  /** 铜币重抽（COPPER 模块）：重置已抽标记重新抽 3 枚 */
  async copperRedraw(): Promise<{ copper: string[]; divineEventId: string }> {
    const cm = this._module.copper;
    const ret = cm?.redraw() || { copper: [], divineEventId: "" };
    this._status.state = "WAIT_MOVE";
    return ret;
  }

  /** 商店战斗开始（CS: RoguelikeShopBattleRequest）：生成 BATTLE 事件（state 0 + addExcludeList） */
  async shopBattleStart(): Promise<void> {
    const theme = this.current.game!.theme;
    const exclude: string[] = [];
    const tickets =
      (excel.RoguelikeTopicTable.details[theme] as any)?.recruitTickets || {};
    for (const [id] of Object.entries(tickets)) {
      if ((id as string).includes("_special") || (id as string).includes("_sniper")) {
        exclude.push(id as string);
      }
    }
    const relics = this.inventory!.relic || {};
    for (const relic of Object.values(relics) as any[]) {
      if ((relic.id || "").includes("grace")) exclude.push(relic.id);
    }
    this._trigger.emit("rlv2:event:create", [
      "BATTLE",
      { state: 0, addExcludeList: exclude },
    ]);
    this._status.state = "PENDING";
  }

  /** 重掷节点（CS: RoguelikeRollNodeRequest { nodeIndex }）：消耗次数并按 rollNodeData 重生成节点 */
  async rerollNode(args: { nodeIndex: string }): Promise<void> {
    const { nodeIndex } = args;
    const zone = this._status.cursor.zone;
    // 键兼容：标准主题为层号，黑流树海为区域索引（1000+）/隐藏层（3000+）——
    // 原实现直写 zones[zone]，rogue_6 恒取不到节点 → 重掷静默失效
    const mapZone = this._map.zones[this.zoneKey(zone)];
    const node = mapZone?.nodes[nodeIndex];
    if (!node) return;
    const refresh = node.refresh;
    if (refresh && refresh.usedCount >= refresh.count) return;
    if (refresh) refresh.usedCount += 1;
    // 官方 rollNodeData 按 zoneId 分组（rogue_6 为隐藏层 zone_portal_normal_5_*）
    const theme = this.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme];
    const rollNodeData = detail?.rollNodeData;
    const zoneId = mapZone.id;
    const group = rollNodeData?.[zoneId]?.groups;
    const stageKeys = Object.keys(detail?.stages || {});
    const roNum = theme.slice(-1);
    if (group) {
      const types = Object.values(group) as { nodeType: string }[];
      const pick = types[Math.floor(Math.random() * types.length)];
      // 节点类型名 → 数值统一走 theme-rules 表（原 typeMap 缺 rogue_6 的
      // 命运所指/狭路相逢/秘境行商等 11 类 → 一律退化为普通作战）
      node.type = ROLL_NODE_TYPE_VALUES[pick.nodeType] ?? ROGUE6_NODE.BATTLE_NORMAL;
    } else {
      node.type = ROGUE6_NODE.BATTLE_NORMAL;
    }
    // 战斗类节点补关卡（非战斗类不需要 stage）
    if (ROGUE6_BATTLE_NODES.includes(node.type)) {
      const candidates = stageKeys.filter((s) =>
        s.startsWith(`ro${roNum}_n_${zone}_`),
      );
      if (candidates.length > 0) {
        node.stage = candidates[Math.floor(Math.random() * candidates.length)];
      }
    }
  }

  /** 升级节点（CS: RoguelikeUpgradeNodeRequest { nodeType }）：接线 nodeUpgrade 模块 */
  async upgradeNode(args: { nodeType: string }): Promise<void> {
    await this._trigger.emit("rlv2:node:upgrade", [args.nodeType]);
  }

  /** 暂存招募票（CS: RoguelikeStashTicketRequest { index }）——黑流树海"放弃招募券"= 留存 */
  async stashRecruitTicket(args: { index: string }): Promise<void> {
    const ticket = this.inventory!.recruit[args.index];
    if (!ticket) return;
    const inv = this.inventory! as any;
    // 留存上限（官方 stashRecruitLimit=3）
    if ((inv.stashRecruit || []).length >= (inv.stashRecruitLimit ?? 3)) return;
    // 转 _candle 变体（stashableTickets 映射），留存列表记录 id（官方 inventory.stashRecruit）
    const theme = this.current.game!.theme;
    const stashable = (excel.RoguelikeTopicTable.details[theme] as any)?.stashableTickets || {};
    const stashedId = stashable[ticket.id]?.stashedTicketId || `${ticket.id}_candle`;
    inv.stashRecruit = [...new Set([...(inv.stashRecruit || []), stashedId])];
    ticket.state = 3;
    ticket.list = [];
  }

  /** 使用暂存票（CS: RoguelikeStashedTicketUseRequest { id }）——从留存列表取回 */
  async useStashedTicket(args: { id: string }): Promise<void> {
    const ticket = this.inventory!.recruit[args.id];
    const inv = this.inventory! as any;
    // 从留存列表移除（取回）
    if (inv.stashRecruit) {
      inv.stashRecruit = (inv.stashRecruit as string[]).filter(
        (sid) => !sid.includes(ticket?.id ?? "") && sid !== args.id,
      );
    }
    if (!ticket) return;
    ticket.state = 0;
    this._trigger.emit("rlv2:recruit:active", [args.id]);
    this._trigger.emit("rlv2:event:create", ["RECRUIT", { tickets: args.id }]);
  }

  /** 选择初始探索工具（CS: RoguelikeSelectInitialExploreToolRequest { select }） */
  async chooseInitialExploreTool(args: { select: string }): Promise<void> {
    const event = this._status.pending.find(
      (e) => e.type === "GAME_INIT_EXPLORE_TOOL",
    );
    if (!event) return;
    const item = event.content.initExploreTool?.items[args.select];
    if (!item) return;
    this._status.pending.splice(
      this._status.pending.indexOf(event),
      1,
    );
    await this._trigger.emit("rlv2:get:items", [[item]]);
    this._status.state = "WAIT_MOVE";
  }

  setTroopCarry(args: { troopCarry: string[] }) {
    this._trigger.emit("rlv2:fragment:set_troop_carry", [args.troopCarry]);
  }

  loseFragment(args: { fragmentIndex: string }) {
    this._trigger.emit("rlv2:fragment:lose", [args.fragmentIndex]);
  }

  useInspiration(args: { fragmentIndex: string }) {
    this._trigger.emit("rlv2:fragment:use_inspiration", [args.fragmentIndex]);
  }

  /* ===== rogue_6 GRID_ZONE / SCRAP 模块（真实机制）===== */

  /** 网格区域移动（抓包 { route: [nodeIndex] }）：沿 route 路径逐节点移动并消耗行动力 */
  async gridZoneMoveTo(args: { route: string[] }): Promise<void> {
    let route = args.route || [];
    if (route.length === 0) return;
    // 清空上一请求的残留推送（控制器为持久实例，与标准 moveTo 一致）
    this._pushMessages = [];
    const gz = this._module.gridZone;
    const zone = this._status.cursor.zone;
    const gzZoneKey = `zone_${zone}`;
    // 阻碍徒步：流窜居民被占领的节点无法徒步越过——若路径中途含被占领节点，将路径截断
    // 到第一个被占领节点（玩家被迫停在被占领节点，进入驱逐战）。
    const barricadeIdx = route.findIndex(
      (nid, i) => i < route.length - 1 && !!gz?.banditAt(gzZoneKey, nid),
    );
    if (barricadeIdx !== -1) {
      route = route.slice(0, barricadeIdx + 1);
    }
    // 界定本次移动请求的变化节点收集范围（rlv2NodeChange.nodeList 只下发发生变化的节点）
    gz?.beginMove();
    // 路径中每个节点消耗一步（含末节点）
    for (const _nodeId of route) {
      this._trigger.emit("rlv2:grid:step", []);
    }
    // 沿路径标记各节点已访问
    const last = route[route.length - 1];
    for (const nodeId of route) {
      gz?.moveTo([nodeId]);
    }
    const node = gz?.moveTo([last]);
    const mapZoneKey = this.zoneKey(zone);
    let lastX = Math.floor(Number(last) / 100);
    let lastY = Number(last) % 100;
    // 曲折密道传送（服务端记录成对 + 送声）：抵达密道节点且存在配对密道时，玩家位置
    // 直接位移到另一密道坐标；官服"行动力只在进入时被消耗、可重复进入、立即揭示"。
    // 密道为通路节点（无 scene），落位到配对处继续走。服务端只改位置，动画由客户端
    // （RL06DoorAnimDialog）表现。
    const tunnelTarget = gz?.tunnelPairTarget(gzZoneKey, last);
    if (tunnelTarget) {
      lastX = Math.floor(Number(tunnelTarget) / 100);
      lastY = Number(tunnelTarget) % 100;
      this.pushMessage("rlv2NodeTeleport", { nodeId: tunnelTarget });
    }
    // 被经过的节点衰减为林间空地：玩家移走的上一个位置 + 路径中途节点（不含末节点，
    // 消费者为玩家当前所在，保留事件；商店/林间空地/尽头/小径/密道等可反复进入类保留）。
    const passed = new Set<string>(route.slice(0, -1));
    const prev = this._status.cursor.position;
    if (prev) passed.add(String(prev.x * 100 + prev.y));
    passed.delete(last); // 玩家当前所在不衰减
    for (const pid of passed) {
      gz?.decayPassed(mapZoneKey, gzZoneKey, pid);
    }
    this._status.trace.push({ zone, position: { x: lastX, y: lastY } });
    this._status.cursor.position = { x: lastX, y: lastY };
    // 节点类型/关卡判定来源（gridZone vs map.zones 双轨）：
    // - 会话内（未落盘）：gridZone 节点 content.kind/savage 是最新语义的权威来源
    //   （含手动变更/事件改写，与 map.zones 可能不同步）。
    // - 重登"继续探索"恢复后：gridZone.toJSON 为客户端线格式精简会剥除 savage/kind，
    //   content 丢失战斗/特殊节点判定 → 必须回退到完整持久化的 map.zones（type/stage
    //   完整保留），否则续局移动进作战节点既不触发战斗、也不下发 rlv2NodeArrive
    //   （kind 恒 undefined）→ 客户端卡死（2026-08-20 复现）。
    const mapNode = this._map.zones[this.zoneKey(zone)]?.nodes?.[last];
    const kind =
      typeof node?.content?.kind === "number"
        ? node.content.kind
        : typeof (mapNode as any)?.type === "number"
          ? (mapNode as any).type
          : undefined;
    // 战斗判定与节点类型绑定，避免误开战：
    // - 会话内 content.kind 存在时以 content.savage 为准（含被改写成非战斗节点，如林间
    //   空地/羽瞰点，map.zones 里可能残留生成期灌入的 stage——不能据此误判战斗）。
    // - 仅当 content.kind 缺失（重登"继续探索"恢复后被剥除）才回退 map.zones 的 stage，
    //   保证续局移动进作战节点仍能触发战斗。
    const battleStage =
      node?.content?.savage?.stageId ||
      (node?.content?.kind === undefined ? (mapNode as any)?.stage : undefined);
    // 节点到达推送（官服对齐）：rlv2NodeArrive 携节点类型、rlv2NodeChange 携本次发生
    // 状态/视野变化的节点列表（官服抓包 R-1786531228496.9993-3674：nodeList=["202","200"]
    // 为到达节点+新揭示邻居，非整层全量）。
    // 原实现只在标准 moveTo 中累积，而黑流树海走本方法 → 推送永不下发。
    // 流窜居民移动：每次玩家移动后，各流窜居民沿连通路径移动 1 格。若末节点本就是
    // 被流窜占领节点（本次为驱逐战，战斗胜利后由 finishClearing 驱逐），则不步进该节点。
    if (!gz?.banditAt(gzZoneKey, last)) {
      gz?.stepBandits(gzZoneKey);
    }
    const changedMoveNodes = gz?.takeChangedNodes() ?? [];
    if (typeof kind === "number") {
      this.pushMessage("rlv2NodeArrive", { nodeType: kind });
      this.pushMessage("rlv2NodeChange", { nodeList: changedMoveNodes });
      // 特勤干员任务：黑流树海节点通过 + "居民"恶意节点（Rlv2PassNodeSpec / Rlv2MeetBandit）
      const gzGame = this.current.game!;
      const gzCtx = {
        theme: gzGame.theme,
        mode: gzGame.mode,
        grade: gzGame.modeGrade ?? 0,
      };
      await this._trigger.emit("Rlv2PassNodeSpec", [
        { ...gzCtx, nodeType: kind },
      ]);
      if (kind === ROGUE6_NODE.RESIDENT) {
        await this._trigger.emit("Rlv2MeetBandit", [gzCtx]);
      }
    }
    // 特勤干员任务：累计消耗行动力（Rlv2MoveCostAp，路径每节点 1 步）
    if (route.length > 0) {
      const apGame = this.current.game!;
      await this._trigger.emit("Rlv2MoveCostAp", [
        {
          theme: apGame.theme,
          mode: apGame.mode,
          grade: apGame.modeGrade ?? 0,
          cost: route.length,
        },
      ]);
    }
    // 自然物（GOODS）估价动态：移动后 → G_05 随机 -6~+8、G_10 -2；本次移动揭示节点 →
    // G_03 每次揭示 +1（按本次变化节点数计）。
    const goodsScrap = this._module.scrap;
    goodsScrap?.applyGoodsEffect("move");
    if (changedMoveNodes.length > 0) {
      goodsScrap?.applyGoodsEffect("node_reveal", changedMoveNodes.length);
    }
    if (battleStage) {
      // 战斗节点（作战/紧急作战/险路恶敌/“居民”据点）→ 战斗
      // 记录驱逐战目标（被流窜占领节点 / "居民"据点）：战斗胜利由 battleFinish →
      // grid_zone.finishClearing 驱逐（被占节点毁为林间空地 / 居民据点驱逐全层流窜）。
      gz?.startClearing(gzZoneKey, last);
      this._status.state = "PENDING";
      await this._trigger.emit("rlv2:battle:start", [battleStage]);
      return;
    }
    // 商店节点判定：会话内以 content.shop 为准；续局恢复后 content 被精简剥除
    // （kind/shop 可能丢失）时回退 map.zones 节点类型判定（与战斗判定同模式）——
    // 否则续局后抵达商店节点不开商店（诡意行商/秘境行商/应急助力全部失效）。
    const isShopNode =
      !!node?.content?.shop ||
      (typeof kind === "number" && ROGUE6_SHOP_NODES.includes(kind));
    if (isShopNode) {
      // 进入行商节点：重置卖零件计数（多边贸易"同一个行商节点"语义）
      this._shopSellCount = 0;
      // 多边贸易升级（band_20）：每次进入行商节点获得 1 个<枯苔藓球>
      if (
        isBlackstream(this.current.game!.theme) &&
        this.hasRelic("rogue_6_band_20")
      ) {
        this._trigger.emit("rlv2:scrap:gain", ["rogue_6_scrap_G_08"]);
      }
      this._status.state = "PENDING";
      this._trigger.emit("rlv2:event:create", [
        "BATTLE_SHOP",
        this.buildShopContent(this.current.game!.theme),
      ]);
      return;
    }
    // 误入奇境（MIRAGE）：进入黑潭场景（消耗加工品 → 隐藏层 未萌生的摇篮）
    if (kind === ROGUE6_NODE.MIRAGE) {
      this.createPortalScene();
      return;
    }
    // 命运所指（PROPHECY，V 层二结局 / VI 层调谐仪式入口）：好奇心与死 / 窥视箱中
    if (kind === ROGUE6_NODE.PROPHECY || kind === ROGUE6_NODE.PROPHECY_HIDDEN) {
      this.createFateScene();
      return;
    }
    // 不期而遇（INCIDENT）：优先二结局线人事件，否则交回事件引擎完整事件池
    if (kind === ROGUE6_NODE.INCIDENT && (await this.createIncidentScene())) {
      return;
    }
    // 非战斗事件节点（安全的角落/得偿所愿/失与得/险路尽头/险路小径）：
    // 事件引擎按 nodeEnters 表下发完整效果（随机 3 选项/出口进区等）；
    // 无配置时回退下方前缀场景分发。
    if (typeof kind === "number" && (await this._incident.createNodeScene(kind))) {
      return;
    }
    // 其余事件节点（安全的角落/得偿所愿/失与得/先行一步/狭路相逢/应急助力/险路小径/险路尽头）：
    // 按节点类型从官方 choiceScenes 抽 enter 场景生成 SCENE 事件。
    // 原实现缺此分发（triggerNodeEvent 零调用）→ 这些节点全部退化为空节点，
    // 三结局入口（先行一步 → scene_ro6_scout_enter）也因此不可达。
    if (typeof kind === "number" && this.createRogue6NodeScene(kind)) {
      return;
    }
    // 空节点（林间空地/曲折密道/羽瞰点）：网格区域自由移动，回到 WAIT_MOVE（客户端继续走）
    this._status.state = "WAIT_MOVE";
  }

  /**
   * 生成黑流树海节点事件场景（SCENE）。
   * 按节点类型取官方 enter 场景前缀（ROGUE6_NODE_SCENE_PREFIX），随机抽一幕，
   * 选项取该幕同前缀的 choices（如 scene_ro6_rest_enter → choice_ro6_rest_1..6）。
   * @param nodeType 节点类型数值（ROGUE6_NODE）
   * @returns 已生成场景返回 true；该类型无场景映射或数据缺失返回 false
   */
  private createRogue6NodeScene(nodeType: number): boolean {
    const theme = this.current.game!.theme;
    const prefixes = ROGUE6_NODE_SCENE_PREFIX[nodeType];
    if (!prefixes || prefixes.length === 0) return false;
    const detail = excel.RoguelikeTopicTable.details[theme];
    // enter 场景：scene_ro6_{prefix}{N}_enter（N 可空，如 scene_ro6_rest_enter）
    const sceneIds = Object.keys(detail?.choiceScenes || {}).filter((id) =>
      prefixes.some((p) => new RegExp(`^scene_ro\\d+_${p}\\d*_enter$`).test(id)),
    );
    if (sceneIds.length === 0) return false;
    const sceneId = sceneIds[Math.floor(Math.random() * sceneIds.length)];
    // 该幕的选项：与场景同名前缀（scene_ro6_bat1_enter → choice_ro6_bat1_*）
    const stem = sceneId.replace(/^scene_/, "").replace(/_enter$/, "");
    const choiceIds = Object.keys(detail?.choices || {}).filter((k) =>
      k.startsWith(`choice_${stem}_`),
    );
    if (choiceIds.length === 0) return false;
    this._status.state = "PENDING";
    this._trigger.emit("rlv2:event:create", [
      "SCENE",
      {
        scene: {
          id: sceneId,
          choices: choiceIds.reduce((acc, cid) => ({ ...acc, [cid]: 1 }), {}),
          choiceAdditional: choiceIds.reduce(
            (acc, cid) => ({ ...acc, [cid]: { rewards: [] } }),
            {},
          ),
        },
        done: false,
        popReport: false,
      },
    ]);
    return true;
  }

  /**
   * 误入奇境（MIRAGE 节点）入口场景：随机选一个雾色场景族（scene_ro6_portalX*_enter），
   * 选项为该族全部 choice（_1.._3 消耗 1 件加工品进入 / _4 直接进入 / _5 无加工品 / _6 离开）。
   * 选项效果由 selectChoice 的 portal 分支处理（进入隐藏层或结束节点）。
   */
  private createPortalScene(): void {
    const theme = this.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const sceneIds = Object.keys(detail?.choiceScenes || {}).filter(
      (id) => id.startsWith(`scene_ro6_portal`) && id.endsWith("_enter"),
    );
    if (sceneIds.length === 0) {
      this._status.state = "WAIT_MOVE";
      return;
    }
    const sceneId = sceneIds[Math.floor(Math.random() * sceneIds.length)];
    // 场景族：scene_ro6_portal1a_enter → "1a"
    const family =
      sceneId.match(/scene_ro\d+_portal(\d+[ab]?)_enter/)?.[1] ?? "1a";
    const prefix = `choice_ro6_portal${family}`;
    const choiceIds = Object.keys(detail.choices || {}).filter((k) =>
      k.startsWith(prefix),
    );
    if (choiceIds.length === 0) {
      this._status.state = "WAIT_MOVE";
      return;
    }
    const choices = choiceIds.reduce(
      (acc, cid) => ({ ...acc, [cid]: 1 }),
      {},
    );
    const choiceAdditional = choiceIds.reduce(
      (acc, cid) => ({ ...acc, [cid]: { rewards: [] } }),
      {},
    );
    this._status.state = "PENDING";
    this._trigger.emit("rlv2:event:create", [
      "SCENE",
      {
        scene: { id: sceneId, choices, choiceAdditional },
        done: false,
        popReport: false,
      },
    ]);
  }

  /**
   * 进入误入奇境隐藏层（未萌生的摇篮）：记录返回点，生成 portal zone（乌托邦模板 + 本层专用行动力）。
   * @param family 雾色场景族数字（1..9，字母变体已剥离）
   */
  private enterPortalZone(family: string): void {
    const gz = this._module.gridZone;
    if (!gz) {
      this._status.state = "WAIT_MOVE";
      return;
    }
    const pos = this._status.cursor.position;
    const returnNode = pos ? String(pos.x * 100 + pos.y) : "0";
    const returnZone = this._status.cursor.zone;
    this._status.pending.shift();
    gz.generatePortal(family, returnZone, returnNode);
    this._status.state = "PENDING";
  }

  /**
   * 消耗 1 件加工品（零件箱 MOVE 型废品）进入黑潭；无可用加工品返回 false。
   * 官方 scrapTypeData：MOVE = "加工品"（可用于地图移动），GOODS = "自然物"，
   * PASSIVE = "概念体"——误入奇境选项文本"消耗零件箱里的 1件 加工品"即 MOVE 型。
   * 扣估价（sellPrice）最低者。
   */
  private consumePortalScrap(): boolean {
    const scrap = this._module.scrap;
    if (!scrap) return false;
    const theme = this.current.game!.theme;
    const typeMap = excel.RoguelikeTopicTable.modules[theme]?.scrap;
    const candidates = Object.values(scrap.inventory || {}).filter((it: any) => {
      return typeMap?.scrapItemToType?.[it.id] === "MOVE";
    }) as { instId: string; value: number }[];
    if (candidates.length === 0) return false;
    // 优先扣估价最低的加工品
    candidates.sort((a, b) => a.value - b.value);
    const consumed = candidates[0];
    delete scrap.inventory[consumed.instId];
    // 扣掉的若是当前载具，切回步行（否则 activeVehicle 指向已删除的 instId）
    if (scrap.activeVehicle?.instId === consumed.instId) {
      scrap.activeVehicle = { isWalk: true };
    }
    return true;
  }

  /**
   * 二结局·维度重构：与"窥视箱中"的首领决战 → 混沌源阶理论（ro6_b_5，险路恶敌）。
   * 将当前节点标记为混沌源阶理论并创建 BATTLE 事件（客户端随后 moveAndBattleStart）。
   */
  private startChaosSourceBattle(): void {
    const stageId = ROGUE6_END2_BOSS_STAGE; // 混沌源阶理论（stages 表实锤 ro6_b_5）
    // 当前节点标记为混沌源阶理论（客户端地图显示险路恶敌）
    const pos = this._status.cursor.position;
    if (pos) {
      const node = this._map.zones[this.zoneKey(this._status.cursor.zone)]?.nodes[
        pos.x * 100 + pos.y
      ];
      if (node) {
        node.stage = stageId;
        node.type = TorappuRoguelikeEventType.BATTLE_BOSS;
        (node as any).zone_end = true; // 首领战可推进结算
      }
    }
    this._status.pending.shift();
    this._trigger.emit("rlv2:event:create", [
      "BATTLE",
      {
        state: 1,
        chestCnt: 100,
        goldTrapCnt: 100,
        diceRoll: [],
        boxInfo: {},
        tmpChar: [],
        sanity: 0,
        unKeepBuff: [],
      },
    ]);
    this._status.state = "PENDING";
  }

  /** 线人事件：获得 1 件珍贵的加工品（零件池随机 1 件入零件箱） */
  private gainPreciousScrap(): void {
    this.gainRandomScrap();
  }

  /**
   * 获得 1 件随机加工品（零件池随机 1 件入零件箱）。
   * 「先行一步 归来」与线人事件共用；零件源 = 官方 modules[theme].scrap.scrapItemToType 键。
   */
  private gainRandomScrap(): void {
    const theme = this.current.game!.theme;
    const pool = Object.keys(
      excel.RoguelikeTopicTable.modules[theme]?.scrap?.scrapItemToType || {},
    );
    if (pool.length === 0) return;
    const id = pool[Math.floor(Math.random() * pool.length)];
    this._trigger.emit("rlv2:scrap:gain", [id]);
  }

  /**
   * 【生命游戏】"喙"节点是否已点亮（"先行一步"归来时额外获得随机加工品）。
   * 判定依据：科技树节点（customizeData.commonDevelopment.developments[rogue_6_outbuff_33]）
   * 已捕获（outer.buff.unlocked）且其 RAW_TEXT_EFFECT 的 rawDesc 存在并描述"加工品"。
   * 与"翅膀"（rogue_6_outbuff_37）同模式，但显式校验 rawDesc 指向"归来带加工品"。
   * @returns 已点亮返回 true
   */
  private isBeakUnlocked(): boolean {
    const theme = (this.current.game?.theme as string) || "";
    if (!isBlackstream(theme)) return false;
    const outer = this.outer?.[theme];
    if (!outer?.buff?.unlocked?.[ROGUE6_BEAK_OUTBUFF]) return false;
    const dev = (excel.RoguelikeTopicTable as any)?.customizeData?.[theme]
      ?.commonDevelopment?.developments?.[ROGUE6_BEAK_OUTBUFF];
    const rawDesc = Array.isArray(dev?.rawDesc) ? dev.rawDesc.join("") : "";
    // rawDesc 描述"归来时……随机加工品"，据此确认该节点为"先行一步归来带加工品"
    return rawDesc.includes("加工品") && rawDesc.includes("归来");
  }

  /**
   * 命运所指（PROPHECY 节点）入口场景：持有双沙盘 → 窥视箱中（end2，谜题与谜底）；
   * 否则随机 1/3 概率窥视箱中、2/3 好奇心与死（V 层 3 个命运所指中 1 个为窥视箱中）。
   */
  private createFateScene(): void {
    const theme = this.current.game!.theme;
    if (!isBlackstream(theme)) {
      this._status.state = "WAIT_MOVE";
      return;
    }
    const hasBoth =
      this.hasRelic(ROGUE6_END2_RELICS.sandboxAlpha) &&
      this.hasRelic(ROGUE6_END2_RELICS.sandboxBeta);
    const isBox = hasBoth || Math.random() < 1 / 3;
    const sceneId = isBox ? "scene_ro6_end2_enter" : "scene_ro6_end1_enter";
    const prefix = isBox ? "choice_ro6_end2_" : "choice_ro6_end1_";
    const detail = excel.RoguelikeTopicTable.details[theme];
    const choiceIds = Object.keys(detail.choices || {}).filter((k) =>
      k.startsWith(prefix),
    );
    if (choiceIds.length === 0) {
      this._status.state = "WAIT_MOVE";
      return;
    }
    const choices = choiceIds.reduce(
      (acc, cid) => ({ ...acc, [cid]: 1 }),
      {},
    );
    const choiceAdditional = choiceIds.reduce(
      (acc, cid) => ({ ...acc, [cid]: { rewards: [] } }),
      {},
    );
    this._status.state = "PENDING";
    this._trigger.emit("rlv2:event:create", [
      "SCENE",
      {
        scene: { id: sceneId, choices, choiceAdditional },
        done: false,
        popReport: false,
      },
    ]);
  }

  /**
   * 二结局·线人事件（bomb1"线人与线索"）：不期而遇节点上的专属分支。
   * 仅 Ⅱ-Ⅳ 层、未持有沙盘α时按 40% 概率触发；不触发（或线人数据缺失）时交回
   * 不期而遇事件引擎（_incident）从完整事件池随机一幕。
   * @returns 已生成场景返回 true，数据缺失无法生成返回 false
   */
  private async createIncidentScene(): Promise<boolean> {
    const theme = this.current.game!.theme;
    // 线人（二结局前置）：Ⅱ-Ⅳ 层、未持有沙盘α时按 40% 概率优先触发；
    // 未命中则交回不期而遇事件引擎从完整事件池（res*/relic*/normal*/bat*/task*/
    // chimera*，含层数限制/重复规则/前置条件）随机一幕。
    if (!isBlackstream(theme) || this.hasRelic(ROGUE6_END2_RELICS.sandboxAlpha)) {
      return await this._incident.createIncident();
    }
    const zone = this._status.cursor.zone;
    // 线人仅 Ⅱ-Ⅳ 层出现；概率触发（40%）
    if (zone < 2 || zone > 4 || Math.random() >= 0.4) {
      return await this._incident.createIncident();
    }
    const detail = excel.RoguelikeTopicTable.details[theme];
    const choiceIds = Object.keys(detail.choices || {}).filter((k) =>
      k.startsWith("choice_ro6_bomb1_"),
    );
    if (choiceIds.length === 0) {
      return await this._incident.createIncident();
    }
    const choices = choiceIds.reduce(
      (acc, cid) => ({ ...acc, [cid]: 1 }),
      {},
    );
    const choiceAdditional = choiceIds.reduce(
      (acc, cid) => ({ ...acc, [cid]: { rewards: [] } }),
      {},
    );
    this._status.state = "PENDING";
    this._trigger.emit("rlv2:event:create", [
      "SCENE",
      {
        scene: { id: "scene_ro6_bomb1_enter", choices, choiceAdditional },
        done: false,
        popReport: false,
      },
    ]);
    return true;
  }

  /**
   * 网格区域移动并开始战斗（抓包 { route, stageId, squad }）。
   * 复用 gridZoneMoveTo 的完整移动逻辑（beginMove/takeChangedNodes 变化节点、被经过节点
   * 衰减 decayPassed、流窜居民 stepBandits、驱逐战 startClearing、节点类型判定与推送、
   * 特勤干员任务/goodsScrap 效果等）——若此处走旧简化实现会与 gridZoneMoveTo 行为分叉：
   * 变化节点不收集（rlv2NodeChange 永不下发）、被经过节点不衰减为林间空地、流窜居民/
   * 驱逐战机制缺失，导致续局存档网格结构异常。战斗节点由 gridZoneMoveTo 内部触发
   * battle:start；续局等场景判定失败时用客户端 stageId 兜底开战。
   */
  async gridZoneMoveAndBattleStart(args: {
    route: string[];
    stageId: string;
    squad: PlayerSquad;
  }): Promise<void> {
    // 复用 gridZoneMoveTo 完整移动逻辑；战斗节点内部已触发 battle:start。
    // 仅当移动未进入任何节点事件（空节点/续局判定失败）时才按客户端 stageId 兜底开战，
    // 避免对商店/事件节点重复触发双事件。
    const pendingBefore = this._status.pending.length;
    await this.gridZoneMoveTo({ route: args.route });
    if (this._status.pending.length > pendingBefore) {
      return;
    }
    this._status.state = "PENDING";
    await this._trigger.emit("rlv2:battle:start", [args.stageId]);
  }

  /** 网格区域空步：消耗一步行动力（不移动） */
  async gridZoneEmptyStep(): Promise<void> {
    this._trigger.emit("rlv2:grid:step", []);
    // 特勤干员任务：空步同样消耗 1 行动力（Rlv2MoveCostAp）
    const game = this.current.game;
    if (game) {
      await this._trigger.emit("Rlv2MoveCostAp", [
        {
          theme: game.theme,
          mode: game.mode,
          grade: game.modeGrade ?? 0,
          cost: 1,
        },
      ]);
    }
    this._status.state = "WAIT_MOVE";
  }

  /** 网格区域读取第 0 步：确认初始位置 */
  async gridZoneReadStepZero(): Promise<void> {
    const gz = this._module.gridZone;
    if (gz) gz.needConfirmStepZero = false;
    this._status.state = "PENDING";
  }

  /** 废品操作（rogue_6 SCRAP 模块）：切换当前载具或保持步行 */
  async scrap(): Promise<void> {
    this._status.state = "WAIT_MOVE";
  }

  /** 废品换乘（SCRAP MOVE 型）：切换载具（客户端 body { scrapInstId, toWalk }） */
  async scrapChangeVehicle(args: {
    scrapId?: string;
    scrapInstId?: string;
    toWalk?: number;
  }): Promise<void> {
    const sm = this._module.scrap;
    const instId = args.scrapInstId || args.scrapId || "";
    if (args.toWalk || instId === "") {
      sm?.changeVehicle("");
    } else {
      sm?.changeVehicle(instId);
    }
    this._status.state = "WAIT_MOVE";
  }

  /** 丢弃废品（SCRAP 模块，客户端 body { instId }）：从库存移除 */
  async loseScrap(args: { instId: string }): Promise<void> {
    const sm = this._module.scrap;
    if (!sm) {
      this._status.state = "WAIT_MOVE";
      return;
    }
    const inventory = sm.inventory;
    const item = inventory[args.instId];
    if (!item) {
      this._status.state = "WAIT_MOVE";
      return;
    }
    const isVehicle = sm.activeVehicle?.instId === args.instId;
    // 先移除废品，再处理行商侧副作用——行商卖出/任务推送均为 await 异步，若提前 await
    // 侧副作用抛错会跳过 delete，导致"丢弃后废品仍留在包里"（客户端零件箱不更新）。
    // 置顶 delete 保证丢弃必生效，副作用放移除之后即便异常也不影响槽位清空。
    delete inventory[args.instId];
    if (isVehicle) {
      // 若丢弃的是当前载具，切回步行（模型无耐久度机制，载具被移除即视为"破除"）
      sm.activeVehicle = { isWalk: true };
      // 散件破除推送（rlv2ScrapBreak，触发类 RoguelikeScrapBreakTrigger）：携带破除散件 id
      this.pushMessage("rlv2ScrapBreak", { idList: [item.id] });
    } else if (this.isInShopNode()) {
      // 多边贸易（shop_recycle_reward）：在行商节点卖出零件（非载具）计数
      await this.sellScrapAtShop();
      // 特勤干员任务：行商卖出零件（Rlv2ShopRecycle，每件 1 计）
      await this._trigger.emit("Rlv2ShopRecycle", [
        { itemType: "SCRAP", count: 1 },
      ]);
    }
    this._status.state = "WAIT_MOVE";
  }

  /** 当前节点是否为行商节点（诡意行商 / 秘境行商 / 应急助力，官方 subName=商店） */
  private isInShopNode(): boolean {
    const pos = this._status.cursor.position;
    if (!pos) return false;
    const node = this._map.zones[this.zoneKey(this._status.cursor.zone)]?.nodes[
      pos.x * 100 + pos.y
    ];
    return typeof node?.type === "number" && ROGUE6_SHOP_NODES.includes(node.type);
  }

  /**
   * 多边贸易分队（shop_recycle_reward）：同一行商节点中卖出 sell_count 件零件 → +8 源石锭。
   * 官方 buff：blackboard = [id: 源石锭, count: 8, sell_count: 3, limit: 1]；
   * 计数在进入行商节点时重置（每节点限 1 次，limit 语义由重置实现）。
   */
  private async sellScrapAtShop(): Promise<void> {
    const recycle = this._buff.filterBuffs("shop_recycle_reward");
    if (recycle.length === 0) return;
    const buff = recycle[0];
    const sellCount = buff.blackboard[2]?.value ?? 3;
    if ((this._shopSellCount ?? 0) >= sellCount) return; // 本节点已达卖出上限
    this._shopSellCount = (this._shopSellCount ?? 0) + 1;
    if (this._shopSellCount >= sellCount) {
      const goldId =
        buff.blackboard[0]?.valueStr ||
        `${this.current.game!.theme}_gold`;
      const count = buff.blackboard[1]?.value ?? 8;
      await this._trigger.emit("rlv2:get:items", [[{ id: goldId, count }]]);
    }
  }

  /**
   * 废品鉴定（rogue_6 SCRAP，官方 POST /rlv2/scrap/identify，body { count }）：
   * 从废品池抽 count 件废品入零件箱（响应顶层 scrap），并附 legacy 部件（响应顶层 legacy）。
   * 官方响应（抓包 2026-08-11）：{ scrap: [{id,count}], legacy: [{id,count}], playerDataDelta }。
   */
  async scrapIdentify(args: { count?: number }): Promise<{
    scrap: RoguelikeItemBundle[];
    legacy: RoguelikeItemBundle[];
  }> {
    const theme = this.current.game?.theme ?? "";
    const pool = Object.keys(
      excel.RoguelikeTopicTable.modules[theme]?.scrap?.scrapItemToType || {},
    );
    const count = Math.max(1, Math.min(args.count ?? 1, 3));
    const scrap: RoguelikeItemBundle[] = [];
    for (let i = 0; i < count && pool.length > 0; i++) {
      const id = pool[Math.floor(Math.random() * pool.length)];
      scrap.push({ id, count: 1 });
      this._trigger.emit("rlv2:scrap:gain", [id]);
    }
    // legacy 部件：LEGACY 型物品（下次探索开局加成，本局无持续效果）
    const items = (excel.RoguelikeTopicTable.details[theme] as any)?.items || {};
    const legacyPool = Object.keys(items).filter(
      (id) => items[id]?.type === "LEGACY",
    );
    const legacy: RoguelikeItemBundle[] = [];
    const legacyCount = Math.floor(count / 2);
    for (let i = 0; i < legacyCount && legacyPool.length > 0; i++) {
      const id = legacyPool[Math.floor(Math.random() * legacyPool.length)];
      legacy.push({ id, count: 1 });
      this._trigger.emit("rlv2:get:items", [[{ id, count: 1 }]]);
    }
    this._status.state = "PENDING";
    return { scrap, legacy };
  }

  toJSON(): PlayerRoguelikeV2 {
    // 结算完成后（gameSettle / _settled），本局运行态已结束，不再保留可"继续探索"的
    // current——输出全空（各节 null）。结算内容经 gameSettle 响应的顶层 extra
    // （buildSettleResponse 的 game/outer）下发，current 为空不影响结算页。
    // 也经 persistCurrent 落到存档，重登时 hasRunning=false → 不再提示"继续探索"。
    const current = this._settled
      ? {
          player: null,
          map: null,
          troop: null,
          inventory: null,
          game: null,
          buff: null,
          module: null,
          record: null,
        }
      : {
          player: this._status,
          record: this.current.record,
          map: this._map,
          inventory: this.inventory,
          game: this.current.game,
          troop: this.troop,
          buff: this.current.buff,
          module: this._module,
        };
    return {
      outer: this.outer,
      current,
      pinned: this.pinned,
    } as unknown as PlayerRoguelikeV2;
  }

  /**
   * 内存态写回存档（rlv2Response 调用）：status/map/module/troop 等 manager 为
   * 内存态（不经 Immer patch），响应时把 toJSON 快照写回 _playerdata.rlv2.current，
   * 供重登"继续探索"（controller 重建走 rlv2:continue 恢复）使用——
   * 否则存档 current.player 等为空，重登后无法继续。
   */
  persistCurrent(): void {
    const pd = this._player._playerdata;
    if (!pd.rlv2?.current) return;
    const j = this.toJSON();
    const cur = pd.rlv2.current as any;
    cur.player = j.current.player;
    cur.map = j.current.map;
    cur.inventory = j.current.inventory;
    cur.troop = j.current.troop;
    cur.buff = j.current.buff;
    cur.module = j.current.module;
    cur.record = j.current.record;
    cur.game = j.current.game;
    this._player.markDirty();
  }

  /**
   * 解锁增益树（科技树）节点
   * 校验：节点存在、未解锁、前置节点全部解锁、增益点足够
   * 成功：扣 pointOwned、加 pointCost、写 unlocked[buffId]=1
   * @param theme 主题（rogue_1..6）
   * @param buffId 节点 id（developments.buffId，如 outbuff_1 / rogue_2_outbuff_1）
   * @returns { success: boolean; reason?: string }
   */
  async unlockBuff(
    theme: string,
    buffId: string,
  ): Promise<{ success: boolean; reason?: string }> {
    const customize = (excel.RoguelikeTopicTable.customizeData as any)?.[theme];
    const devs =
      customize?.developments && !Array.isArray(customize.developments)
        ? customize.developments
        : customize?.commonDevelopment?.developments;
    const dev = devs?.[buffId];
    if (!dev) return { success: false, reason: "NODE_NOT_FOUND" };

    const buff = this.outer[theme]?.buff;
    if (!buff) return { success: false, reason: "THEME_NOT_READY" };
    const unlocked = buff.unlocked || {};
    if (unlocked[buffId]) return { success: false, reason: "ALREADY_UNLOCKED" };
    const fronts = dev.frontNodeId || [];
    for (const f of fronts) {
      if (!unlocked[f]) return { success: false, reason: "FRONT_NOT_UNLOCKED" };
    }
    if (buff.pointOwned < dev.tokenCost)
      return { success: false, reason: "POINT_NOT_ENOUGH" };

    await this.update(async (draft) => {
      const db = draft.outer[theme].buff;
      db.pointOwned -= dev.tokenCost;
      db.pointCost = (db.pointCost || 0) + dev.tokenCost;
      db.unlocked = { ...(db.unlocked || {}), [buffId]: 1 };
      // 分队升级隐藏：解锁科技树节点后，若该节点对应分队升级（bandRef bandLevel>0
      // 的升级变体，如 分裂→指挥分队 band_2），升级分队 state 1、旧分队（normalBandId）state 0。
      // 官方机制：升级分队解锁后旧分队隐藏（同分队只显示最高等级）。
      const collectBand = (draft.outer[theme] as any)?.collect?.band;
      if (collectBand && typeof collectBand === "object") {
        this.applyBandUpgradeVisibility(theme, buffId, collectBand);
      }
    });
    return { success: true };
  }

  /**
   * 分队升级可见性同步（科技树解锁 → collect.band state）。
   * 规则：bandRef 中 bandLevel>0 的升级变体（unlockCondDesc 提到科技树节点名，
   * 如"激活分裂/卵生/胎生/顶冠/角/鳍"）解锁时，升级变体 state 1、其 normalBandId 旧分队 state 0。
   * @param theme 主题
   * @param buffId 刚解锁的科技树节点（buffId 或 buffName 匹配）
   * @param collectBand collect.band 引用（原地修改）
   */
  private applyBandUpgradeVisibility(
    theme: string,
    buffId: string,
    collectBand: { [key: string]: { state: number } },
  ): void {
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const bandRef = (detail?.bandRef || {}) as Record<
      string,
      { bandLevel?: number; normalBandId?: string; itemID?: string }
    >;
    // 刚解锁节点名（buffName，用于匹配 unlockCondDesc 中的"激活XXX"）
    const customize = (excel.RoguelikeTopicTable.customizeData as any)?.[theme];
    const devs =
      customize?.developments && !Array.isArray(customize.developments)
        ? customize.developments
        : customize?.commonDevelopment?.developments;
    const devName = devs?.[buffId]?.buffName || "";
    const upgradeVariants = Object.entries(bandRef).filter(
      ([, r]) => (r.bandLevel ?? 0) > 0,
    );
    for (const [upgradeId, ref] of upgradeVariants) {
      const cond = detail?.items?.[upgradeId]?.unlockCondDesc || "";
      // 升级条件提到该节点名（分裂/卵生/胎生/顶冠/角/鳍）→ 该升级已解锁
      const matched = devName !== "" && cond.includes(`“${devName}”`);
      if (!matched) continue;
      collectBand[upgradeId] = { state: 1, progress: null as any } as any;
      const baseId = ref.normalBandId || ref.itemID;
      if (baseId && baseId !== upgradeId && collectBand[baseId]) {
        collectBand[baseId].state = 0;
      }
    }
  }

  /**
   * 构建结算数据（GAME_SETTLE 事件 + current.record）
   * 线格式对照官方抓包（giveUpGame_res / gameSettle_res）：
   *   brief = { level, over, success, ending, theme, mode, predefined, band,
   *             startTs, endTs, endZoneId, endProperty, innerMission,
   *             innerMissionProcess, modeGrade }
   *   record = { cntZone, cntBattleNormal/Elite/Boss, cntArrivedNode, cntRecruitChar,
   *              cntUpgradeChar, cntKillEnemy, cntShopBuy, cntPerfectBattle, ...
   *              relicList, capsuleList, activeToolList, zones, squadBuff, charBuff }
   */

  /**
   * 难度解锁状态（collect.modeGrade）：进阶式扩展难度——通关 grade N 解锁 grade N+1。
   * grade 0 默认解锁（state 2）；grade N（>=1）仅当上一级已通关（record.modeGrade 含 N-1 通关记录）才 state 2，
   * 否则 state 1（可见未解锁）。客户端按 state 决定难度可选性。
   */
  private initModeGradeStates(
    theme: string,
    map?: any,
    game?: any,
  ): {
    [mode: string]: { [grade: string]: { state: number; progress: number[] | null } };
  } {
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const difficulties: any[] = (detail?.difficulties || []).filter(
      (x: any) => (x.modeDifficulty ?? "NORMAL") === "NORMAL",
    );
    const states: {
      [grade: string]: { state: number; progress: number[] | null };
    } = {};
    // 已通关难度（record.modeGrade[mode] 各难度通关计数 > 0）
    const rec = ((map ?? this.outer)?.[theme]?.record as any) || {};
    const cleared = new Set<number>();
    const mode = (game ?? this.current.game)?.mode || "NORMAL";
    const clearedGrades = (rec.modeGrade?.[mode] || {}) as { [g: string]: number };
    for (const [g, cnt] of Object.entries(clearedGrades)) {
      if (cnt > 0) cleared.add(parseInt(g, 10));
    }
    for (const diff of difficulties) {
      const g = diff.grade ?? 0;
      const isCleared = g === 0 || cleared.has(g) || cleared.has(g - 1) || g <= this.maxClearedGrade(cleared);
      states[String(g)] = {
        state: isCleared ? 2 : 1,
        progress: null,
      };
    }
    return { [mode]: states };
  }

  /** 已通关的最高连续难度（进阶式：通关 N-1 才解锁 N） */
  private maxClearedGrade(cleared: Set<number>): number {
    let max = 0;
    for (let g = 1; ; g++) {
      if (cleared.has(g)) max = g;
      else break;
    }
    return max;
  }
  /**
   * 战报种子（brief.seed，官服格式 "{随机},{theme},{modeGrade}"，客户端分享/复现用）。
   * 同实例首按需生成并缓存——giveUpGame 与其后 gameSettle 的 brief.seed 保持一致；
   * 重登恢复（controller 重建）会重新生成，仅影响展示。
   */
  private _gameSeed: string | null = null;
  private gameSeed(): string {
    if (!this._gameSeed) {
      const theme = this.current.game?.theme ?? "";
      const grade = this.current.game?.modeGrade ?? 0;
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      const rand = Array.from(
        { length: 18 },
        () => chars[Math.floor(Math.random() * chars.length)],
      ).join("");
      this._gameSeed = `${rand},${theme},${grade}`;
    }
    return this._gameSeed;
  }

  /**
   * 构建结算明细序列化（GAME_SETTLE.detailStr，官方 giveUpGame/gameSettle 携带）。
   * 官服格式：detailStr = base64(zlib-deflate(JSON))（解压见抓包，键集：
   * { brief, troopChars, initial, zones }）。私服无官方"开局快照/逐层 per-step 获取"
   * 采集，故 initial.recruits / zones.steps 用当前可得数据近似——键结构对齐官服，
   * 客户端可解析不崩，内容为近似值。
   * @param brief - 本次结算的 brief 摘要（含 seed/innerMissionProcessAddition）
   * @returns base64 编码的结算明细；无游戏态时返回 null（不携带该字段）
   */
  private buildDetailStr(brief: any): string | null {
    const game = this.current.game as any;
    if (!game) return null;
    // troopChars：当前队伍干员（官方 detailStr 每干员仅 6 字段，无 potentialRank/mainSkillLvl）
    const troopChars = Object.values(this.troop.chars).map((c: any) => ({
      instId: String(c.instId),
      charId: c.charId,
      type: c.type || "NORMAL",
      upgradePhase: c.upgradePhase ?? 0,
      evolvePhase: c.evolvePhase ?? 0,
      level: c.level ?? 1,
    }));
    // initial：开局配置。私服未单独采集开局快照，relics 用当前藏品、
    // recruits 用当前队伍近似（官方此处为开局确定的 3 名初始干员）。
    const initial = {
      mode: game.mode ?? "NORMAL",
      band: this._bandId || "",
      relics: Object.keys(this.inventory?.relic || {}),
      support: "",
      supportMulti: [],
      recruitSet: "",
      recruits: troopChars.map((t) => ({
        charId: t.charId,
        type: t.type,
        cost: 0,
      })),
      upgrades: [],
    };
    // zones：每层区域。私服无 per-step 物品获取记录，steps 留空（键结构对齐）。
    const zones = Object.values(this._map.zones || {}).map((z: any) => ({
      index: z.index,
      zoneId: z.id,
      variation: Array.isArray(z.variation) ? z.variation : [],
      type: 0,
      pass: false,
      steps: [],
      snapRecruits: [],
      snapSettleCover: {},
      expeditionReturn: { chars: [] },
    }));
    const payload = { brief, troopChars, initial, zones };
    // deflateSync 默认 level 6 → zlib 头 0x78 0x9c → base64 前缀 "eJ"（与官服一致）
    return zlib.deflateSync(Buffer.from(JSON.stringify(payload))).toString("base64");
  }

  private buildSettlement(
    over: boolean,
    success: number,
    ending: string,
  ): { brief: any; record: any; buffBankPut: number } {
    const game = this.current.game!;
    const theme = game.theme;
    // endTs 用秒（now() 秒级），与 game.start（now() 秒级）保持一致
    //（原实现 Date.now() 为毫秒 → 响应里 endTs 13 位而 startTs 10 位，长度/t 值域不一致）
    const endTs = now();
    const startTs = game.start || endTs;
    const property = this._status.property;

    // 战斗/招募计数（trace 节点类型统计）
    let cntBattleNormal = 0;
    let cntBattleElite = 0;
    let cntBattleBoss = 0;
    let cntArrivedNode = this._status.trace.length;
    const cntArrivedNodeType: { [key: number]: number } = {};
    for (const t of this._status.trace) {
      const node = this._map.zones[this.zoneKey(t.zone)]?.nodes[
        `${(t.position?.x ?? 0) * 100 + (t.position?.y ?? 0)}`
      ];
      const type = node?.type ?? 0;
      cntArrivedNodeType[type] = (cntArrivedNodeType[type] ?? 0) + 1;
      if (type === 1) cntBattleNormal++;
      else if (type === 2) cntBattleElite++;
      else if (type === 4) cntBattleBoss++;
    }
    const recruitChars = Object.values(this.inventory!.recruit || {}).filter(
      (t) => (t as any).result,
    );
    const cntRecruitChar = recruitChars.length;
    const troopChars = Object.values(this.troop.chars).map((c) => {
      const char: any = { ...(c as any) };
      return {
        instId: String(char.instId),
        charId: char.charId,
        type: char.type || "NORMAL",
        upgradePhase: char.upgradePhase ?? 0,
        evolvePhase: char.evolvePhase ?? 0,
        level: char.level ?? 1,
        potentialRank: char.potentialRank ?? 0,
        mainSkillLvl: char.mainSkillLvl ?? 1,
      };
    });

    const brief = {
      level: property.level,
      over,
      success,
      ending,
      theme,
      mode: game.mode,
      // 预置剧本 id：无预置剧本（NORMAL 等）时为 null 而非 ""——official brief.predefined 为 null
      //（原实现 `|| ""` 会把 null 强转成空串，客户端按"有预置剧本"解析）
      predefined: game.predefined ?? null,
      band: this._bandId || "",
      startTs,
      endTs,
      endZoneId: `zone_${this._status.cursor.zone}`,
      endProperty: {
        hp: property.hp?.current ?? 0,
        gold: property.gold ?? 0,
        populationCost: property.population?.cost ?? 0,
        populationMax: property.population?.max ?? 0,
        san: 0,
      },
      innerMission: false,
      innerMissionProcess: null,
      // 官服 brief 恒定携带这两个键（innerMissionProcessAddition 恒 null；
      // seed 为 "{随机},{theme},{modeGrade}" 战报种子，客户端据此分享/复现）
      innerMissionProcessAddition: null,
      modeGrade: game.modeGrade,
      seed: this.gameSeed(),
    };

    // 招募干员职业分布（record.cntRecruitProfession）：按当前队伍干员职业统计。
    // 官方键为职业名（TANK/CASTER/SNIPER…），值 = 该职业干员数。
    const cntRecruitProfession: { [key: string]: number } = {};
    for (const t of troopChars) {
      const prof = (excel.CharacterTable as any)?.[t.charId]?.profession;
      if (prof) cntRecruitProfession[prof] = (cntRecruitProfession[prof] ?? 0) + 1;
    }
    // 废品/零件箱各 id 持有数（黑流树海 record.scrapCounter）
    const scrapCounter: { [key: string]: number } = {};
    const scrapInv = (this._module as any)?.scrap?.inventory;
    if (scrapInv) {
      for (const it of Object.values(scrapInv)) {
        const id = (it as any)?.id;
        if (id) scrapCounter[id] = (scrapCounter[id] ?? 0) + 1;
      }
    }

    const record = {
      cntZone: Object.keys(this._map.zones).length,
      cntBattleNormal,
      cntBattleElite,
      cntBattleBoss,
      cntArrivedNode,
      cntRecruitChar,
      cntUpgradeChar: 0,
      cntKillEnemy: 0,
      cntShopBuy: 0,
      cntPerfectBattle: property.conPerfectBattle ?? 0,
      cntProtectBox: 0,
      cntRecruitFree: 0,
      cntRecruitAssist: 0,
      cntRecruitNpc: 0,
      cntRecruitProfession,
      troopChars,
      cntArrivedNodeType,
      relicList: Object.values(this.inventory!.relic || {}).map(
        (r) => (r as any).id,
      ),
      capsuleList: [],
      activeToolList: Object.values(this.inventory?.exploreTool || {}).map(
        (t) => (t as any).id,
      ),
      exploreToolList: Object.values(this.inventory?.exploreTool || {}).map(
        (t) => (t as any).id,
      ),
      // 官服 record.zones 为区域数组 [{index, zoneId, variation}]（黑流树海无相地图，
      // 由 grid_zone 模块生成）；原实现误写为层数数字 → 客户端合并结构错误。改从
      // _map.zones 值构造（每个值即含 id/index/variation）。
      zones: Object.values(this._map.zones).map((z: any) => ({
        index: z.index,
        zoneId: z.id, // 形如 "zone_1"
        variation: Array.isArray(z.variation) ? z.variation : [],
      })),
      legacyList: [],
      scrapCounter,
      cntExpedition: {},
      cntWeatherMainGain: {},
      cntWeatherSubGain: {},
      cntWeatherMainClear: {},
      cntScrapIdentify: 0,
      cntShopRecycleCount: {},
      cntShopRecycleProfit: {},
      cntEndZoneBattle: {},
      cntSettleSavage: 0,
      cntSettleBandit: 0,
      cntNodePassBattle: 0,
      nodeMission: [],
      squadBuff: this.current.buff?.squadBuff || [],
      charBuff: [],
    };

    // 本局银行余额（GAME_SETTLE.result.buffBankPut，官服 giveUpGame/gameSettle 结算携带）
    const buffBankPut = (this.outer as any)?.[theme]?.bank?.current ?? 0;
    return { brief, record, buffBankPut };
  }

  /**
   * 探索分数逐项明细（dorothinights gameSettle 参考：官方结算页逐行列出贡献项）。
   * 每行固定为 [count, score] 二元组，顺序 = 层数档位 / 步数×1 / 普通战×10 / 精英战×20 /
   * 领袖战×30 / 物品×5（收藏品+战术道具，不含思绪）/ 招募×2（难度倍率前 raw 贡献）。
   * @returns detail 明细对 + raw 未乘难度倍率的原始分数
   */
  private exploreBreakdown(): { detail: number[][]; raw: number } {
    // 层数档位 0/30/80/150/270/400/550/650（>7 按 7）
    const ZONE_SCORES = [0, 30, 80, 150, 270, 400, 550, 650];
    const zoneCount = Math.min(this._status.cursor.zone, 7);
    const zoneScore = ZONE_SCORES[zoneCount] ?? 0;
    const stepCount = this._status.trace.length;
    let normalCount = 0;
    let eliteCount = 0;
    let bossCount = 0;
    for (const t of this._status.trace) {
      const node = this._map.zones[this.zoneKey(t.zone)]?.nodes[
        `${(t.position?.x ?? 0) * 100 + (t.position?.y ?? 0)}`
      ];
      const type = node?.type ?? 0;
      if (type === 1) normalCount++;
      else if (type === 2) eliteCount++;
      else if (type === 4) bossCount++;
    }
    const recruitCount = Object.values(this.inventory!.recruit || {}).filter(
      (t) => (t as any).result,
    ).length;
    const itemCount =
      Object.keys(this.inventory!.relic || {}).length +
      Object.keys(this.inventory?.exploreTool || {}).length;
    const detail: number[][] = [
      [zoneCount, zoneScore], // 通过层数（档位）
      [stepCount, stepCount * 1], // 通过步数 ×1
      [normalCount, normalCount * 10], // 普通战斗 ×10
      [eliteCount, eliteCount * 20], // 精英战斗 ×20
      [bossCount, bossCount * 30], // 领袖战斗 ×30
      [itemCount, itemCount * 5], // 获得物品 ×5
      [recruitCount, recruitCount * 2], // 招募干员 ×2
    ];
    const raw = detail.reduce((sum, [, score]) => sum + score, 0);
    return { detail, raw };
  }

  /** 当前难度对应的探索分数倍率（difficulty.scoreFactor，无则默认 1） */
  private exploreScoreFactor(): number {
    const theme = this.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const difficulty = detail?.difficulties?.find(
      (d: any) => d.modeDifficulty === this.current.game!.mode && d.grade === this.current.game!.modeGrade,
    );
    return difficulty?.scoreFactor ?? 1;
  }

  /**
   * 探索分数 = 明细求和 × 难度倍率（dorothinights 对齐：仅按难度单次放大，
   * 生命游戏/难度 bump 的「源流样本」效率走 buff/bp，不放大 score 本体）。
   */
  private exploreScore(): number {
    return Math.floor(this.exploreBreakdown().raw * this.exploreScoreFactor());
  }

  /**
   * 黑流树海（rogue_6）「生命游戏」增益树节点集合。
   * 来源：customizeData[theme].developments / commonDevelopment.developments（upgradeBuff 同源）。
   * 仅统计 outbuff 型生长节点（`rogue_6_outbuff_*`），难度解锁节点（`rogue_6_difficulty_*`）不计入——
   * 演化算子只用于升级【生命游戏】（生长树）节点。
   * @returns 节点 id 数组
   */
  private lifeGameNodes(theme: string): string[] {
    const customize = (excel.RoguelikeTopicTable.customizeData as any)?.[theme];
    const devs =
      customize?.developments && !Array.isArray(customize.developments)
        ? customize.developments
        : customize?.commonDevelopment?.developments;
    const all = devs ? Object.keys(devs) : [];
    return all.filter(
      (id) =>
        isBlackstream(theme) ? id.includes("rogue_6_outbuff_") : true,
    );
  }

  /**
   * 黑流树海分数→源流样本转换效率。
   * 默认 1:1；【生命游戏】科技树按已解锁生长节点占比 ×10% 累加（封顶 +10%）；
   * 难度等级 ≥3/≥6/≥9 时各额外 +2% → 1:1.1 / 1.12 / 1.14 / 1.16（生命游戏满级基准）。
   * 非黑流树海主题恒为 1（保持 1:1，不启用效率加成）。
   * @param theme 主题
   * @param grade 难度等级（modeGrade）
   */
  private blackstreamEfficiency(theme: string, grade: number): number {
    if (!isBlackstream(theme)) return 1;
    const nodes = this.lifeGameNodes(theme);
    const unlocked = Object.keys(this.outer?.[theme]?.buff?.unlocked || {}).filter(
      (id) => id.includes("rogue_6_outbuff_"),
    ).length;
    let efficiency = 1;
    // 生命游戏：按已解锁生长节点占比累加，封顶 +10%
    if (nodes.length > 0) {
      efficiency += 0.1 * Math.min(1, unlocked / nodes.length);
    }
    // 难度等级 3+/6+/9+ 各额外提升 2%
    if (grade >= 3) efficiency += 0.02;
    if (grade >= 6) efficiency += 0.02;
    if (grade >= 9) efficiency += 0.02;
    return efficiency;
  }

  /**
   * 是否仍可获得演化算子（黑流树海）。
   * 官方说明：当获得的演化算子能够升级所有【生命游戏】节点时停止获得。
   * 这里以「还有未解锁的生长节点」近似判定——全部解锁即不再发放，
   * 否则跨局累计的源流堆栈满 200 点得分的演化算子继续发放。
   * @param theme 主题
   */
  private canEvolveOperators(theme: string): boolean {
    if (!isBlackstream(theme)) return false;
    const nodes = this.lifeGameNodes(theme);
    if (nodes.length === 0) return true;
    const unlocked = Object.keys(this.outer?.[theme]?.buff?.unlocked || {}).filter(
      (id) => id.includes("rogue_6_outbuff_"),
    ).length;
    return unlocked < nodes.length;
  }

  /**
   * 黑流树海结算奖励统计算法（源流样本 + 演化算子）。
   * 源流样本得分 = floor(探索分数 × 转换效率)；
   * 跨局源流堆栈（buff.sourceStack）累计该得分，每满 200 点 → 1 点演化算子（pointOwned），
   * 不满 200 的余数保留到后续探索继续累加。非黑流树海满 1:1（源流得分=探索分数、无算子）。
   * @returns 当局源流样本得分与转换效率
   */
  private blackstreamAwards(): { sourceScore: number; efficiency: number } {
    const theme = this.current.game!.theme;
    const exploreScore = this.exploreScore();
    const efficiency = this.blackstreamEfficiency(
      theme,
      this.current.game?.modeGrade ?? 0,
    );
    const sourceScore = Math.floor(exploreScore * efficiency);
    return { sourceScore, efficiency };
  }

  async gameSettle(): Promise<void> {
    // 幂等：清空 pending，保证结算事件唯一（重登恢复的"放弃结算中间态"存档可能已带 GAME_SETTLE）
    this.clearPending();
    const theme = this.current.game!.theme;
    const ending = this._status.toEnding || "";
    // 修复：原实现 toEnding 恒为 "roX_ending_1/2"（非 "normal"）且 chgEnding 仅持有
    // 结局变更藏品时为 true → 通关结算恒显示失败；改按本局结果标记判定
    const success =
      this._status.runResult === "success" || this._status.chgEnding ? 1 : 0;
    const { brief, record, buffBankPut } = this.buildSettlement(true, success, ending);
    // current.record 为 _playerdata.rlv2 引用（update() 后冻结），写入放入下方 update() 配方
    const exploreScore = this.exploreScore();
    // 黑流树海（rogue_6）启用「源流样本 + 演化算子」多币种结算；其余主题保持分数→科技树点数 1:1。
    const themeBlackstream = isBlackstream(theme);
    const { sourceScore } = this.blackstreamAwards();
    await this.update(async (draft) => {
      draft.current.record = { brief, record };
      const outerTheme = draft.outer[theme] ?? (draft.outer[theme] = {} as any);
      const buff: any =
        outerTheme.buff ??
        (outerTheme.buff = {
          pointOwned: 0,
          pointCost: 0,
          unlocked: {},
          score: 0,
          sourceStack: 0,
        } as any);
      // 累计探索分数 = 探索分数（dorothinights 对齐：不放大；生命游戏加成走演化算子）
      buff.score = (buff.score || 0) + exploreScore;
      if (themeBlackstream && this.canEvolveOperators(theme)) {
        // 演化算子：跨局累计源流堆栈（每满 200 点源流得分 → 1 点演化算子），
        // 不足 200 的余数保留到后续探索继续累加；演化算子即科技树货币 pointOwned。
        const stack = (buff.sourceStack || 0) + sourceScore;
        const operators = Math.floor(stack / 200);
        buff.sourceStack = stack - operators * 200;
        buff.pointOwned = (buff.pointOwned || 0) + operators;
      } else {
        // 非黑流树海 / 生命游戏节点已全部解锁：分数直接 1:1 计入科技树点数
        buff.pointOwned = (buff.pointOwned || 0) + exploreScore;
      }

      // 记录本把到达的最深层——官服 record 无 lastZone 键（8-11/8-18 抓包对照），
      // 支援选项判定改由 stageCnt 3 层关卡存在性承载；lastZone 仅为旧存档兼容读取。
      const rec = (outerTheme.record ?? (outerTheme.record = {} as any)) as any;
      // 上次结束时间用秒（now()）——原实现 Date.now() 为毫秒（13 位），与本局
      // startTs/endTs（秒、10 位）与 record 其余时间字段值域不一致。
      rec.last = now();
      // 难度通关记录（进阶式解锁：通关 grade N 解锁 N+1）——record.modeGrade[mode][grade]++
      const mode = this.current.game?.mode || "NORMAL";
      const grade = this.current.game?.modeGrade ?? 0;
      const recMode = (rec.modeGrade ?? (rec.modeGrade = {} as any)) as any;
      const recGrades = (recMode[mode] ?? (recMode[mode] = {} as any)) as any;
      recGrades[grade] = (recGrades[grade] || 0) + 1;
      // 特勤干员任务数据源：成功结算记录「分队×结局」「分队×难度」（Rlv2BandGradeCnt /
      // Rlv2EndingBandGradeCnt / Rlv2EndingModeGrade 模板按此统计累计分队数）。
      // bandCnt[bandId][endingId]++、bandGrade[bandId][gradeId]++。
      // 仅常规行动（NORMAL 模式）计入——MONTH_TEAM 等特殊模式不参与特勤干员任务。
      if (success === 1 && ending && this._bandId && mode === "NORMAL") {
        const soBandCnt = (rec.bandCnt ?? (rec.bandCnt = {} as any)) as any;
        const perEnding =
          (soBandCnt[this._bandId] ?? (soBandCnt[this._bandId] = {} as any)) as any;
        perEnding[ending] = (perEnding[ending] || 0) + 1;
        const soBandGrade = (rec.bandGrade ?? (rec.bandGrade = {} as any)) as any;
        const perGrade =
          (soBandGrade[this._bandId] ?? (soBandGrade[this._bandId] = {} as any)) as any;
        perGrade[String(grade)] = (perGrade[String(grade)] || 0) + 1;
      }
      // 同步 collect.modeGrade 解锁状态（当前难度 + 下一级可解锁）
      const collect = outerTheme.collect as any;
      if (collect?.modeGrade?.[mode]) {
        collect.modeGrade[mode][String(grade)] = { state: 2, progress: null };
        const next = String(grade + 1);
        if (collect.modeGrade[mode][next]) {
          collect.modeGrade[mode][next] = { state: 2, progress: null };
        }
      }
      // 黑流树海襁褓类藏品（LEGACY 型：局内获得 → 下一局增益）持久化到 record.legacy
      const legacy = Object.values(this.inventory?.relic || {})
        .map((r) => (r as any).id)
        .filter((id) => {
          const def = (excel.RoguelikeTopicTable.details[theme] as any)?.items?.[id];
          return def?.type === "LEGACY" || id.includes("legacy");
        });
      if (legacy.length > 0) {
        rec.legacy = [...new Set([...(rec.legacy || []), ...legacy])];
      }
      // 难度 0 失败补偿：本次探索失败 → 下次开局获得收藏品【特勤任务影像】
      // （官方保密等级·0"失败时下次探索获得特勤任务影像"；难度 4+ 起"失败后不再获得"）
      if (success === 0 && (this.current.game?.modeGrade ?? 0) <= 3) {
        rec.legacy = [
          ...new Set([
            ...(rec.legacy || []),
            "rogue_6_relic_fight_29",
          ]),
        ];
      }
      // 分队升级隐藏（使用分队通关解锁其升级变体）：本把所选分队（_bandId）若有升级变体
      // （bandRef bandLevel>0 且 normalBandId == _bandId）→ 升级变体 state 1、旧分队隐藏。
      const usedBand = this._bandId;
      const bandRef = (excel.RoguelikeTopicTable.details[theme] as any)?.bandRef || {};
      const collectBand = outerTheme.collect?.band;
      if (usedBand && collectBand && typeof collectBand === "object") {
        const upgradeVariant = Object.entries(bandRef).find(
          ([, r]: any) =>
            (r.bandLevel ?? 0) > 0 && (r.normalBandId ?? r.itemID) === usedBand,
        );
        if (upgradeVariant) {
          const [upgradeId, ref] = upgradeVariant;
          collectBand[upgradeId] = { state: 1, progress: null } as any;
          const baseId = (ref as any).normalBandId || (ref as any).itemID;
          if (baseId && collectBand[baseId]) collectBand[baseId].state = 0;
        }
      }
    });

    // 特勤干员任务：结算事件（仅成功达成结局时推进——giveup/失败不产生分队×结局记录）
    if (success === 1) {
      await this.emitSpecialOperatorSettle(theme, ending);
    }

    await this._trigger.emit("rlv2:event:create", [
      "GAME_SETTLE",
      {
        success,
        result: { brief, record, buffBankPut },
        detailStr: this.buildDetailStr(brief),
        popReport: false,
      },
    ]);

    this._status.state = "END";
    // 结算完成：令 toJSON/persistCurrent 输出 current 全空（本局结束，不再保留续局运行态）
    this._settled = true;
  }

  /**
   * 结算响应顶层数据（gameSettle_res 官方抓包：{ game, outer }）：
   * game = { brief, record, score }；outer = 局外结算快照（mission before/after、BP、解锁、spOperatorInfo）。
   * 客户端在 gameSettle 响应里读取该结构渲染结算页；缺失即"点了放弃没反应"。
   */
  buildSettleResponse(): { game: any; outer: any } {
    const theme = this.current.game!.theme;
    const { brief, record } = this.current.record as any;
    // dorothinights gameSettle 对齐：score 仅按难度单次放大；生命游戏/难度 bump 的效率
    // （extra_grow_point → buff=1+extra、bp.cnt=floor(score×buff)）不放大 score 本体。
    const efficiency = this.blackstreamEfficiency(theme, this.current.game?.modeGrade ?? 0);
    const scoreFactor = this.exploreScoreFactor();
    const { detail, raw } = this.exploreBreakdown();
    const score = Math.floor(raw * scoreFactor); // 探索分数
    const boosted = Math.floor(score * efficiency); // bp.cnt（源流样本，含生命游戏加成）
    const outerTheme = (this.outer as any)[theme] ?? {};
    const bp = (from: number) => ({ cnt: 0, from, to: from });
    const missionList = Array.isArray(outerTheme.mission?.list)
      ? outerTheme.mission.list
      : [];
    const mission = { before: missionList, after: missionList };
    return {
      game: {
        brief: brief ?? {},
        record: record ?? {},
        score: {
          detail,
          scoreFactor,
          score,
          buff: efficiency,
          bp: { cnt: boosted, from: 55000, to: 55000 },
          gp: 0,
          gpChange: [100, 100],
          accumulation: [20000, 20000],
        },
      },
      outer: {
        mission,
        missionBp: bp(55000),
        relicBp: bp(55000),
        totemBp: bp(55000),
        fragmentBp: bp(55000),
        copperBp: bp(55000),
        scrapBp: bp(55000),
        relicUnlock: [],
        totemUnlock: [],
        fragmentUnlock: [],
        copperUnlock: [],
        scrapUnlock: [],
        gp: 0,
        spOperatorInfo: [],
      },
    };
  }
}
