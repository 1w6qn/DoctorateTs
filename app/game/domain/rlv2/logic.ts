import { PlayerRoguelikeV2, RoguelikeItemBundle, RoguelikeNodePosition, TorappuRoguelikeEventType } from "../../domain/rlv2/rlv2";
import excel from "@excel/excel";
import { readFileSync } from "fs";
import zlib from "node:zlib";
import { RoguelikeInventoryManager } from "./inventory";
import { TroopManager } from "@game/service/player/troop";
import { RoguelikeBuffManager } from "./buff";
import { RoguelikePlayerStatusManager } from "./status";
import { now } from "@utils/time";
import { RoguelikeModuleManager } from "./module";
import { RoguelikeTroopManager } from "./troop";
import { RoguelikeMapManager } from "./map";
import { PlayerSquad } from "@game/domain/character";
import { RoguelikeBattleManager } from "./battle";
import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { PlayerDataModel } from "@game/domain/playerdata";
import { BattleData } from "@game/domain/battle";
import { RoguelikePoolManager } from "./pool";
import { composeRlv2ChildModules, type Rlv2ChildModules } from "./rlv2-composition";
import { RoguelikeGameInitData } from "@excel/roguelike_topic_table";
import { TypedEventEmitter } from "@game/service/events";
import { RoguelikePushMessage } from "../../domain/contracts/common";
import { Draft } from "mutative";
import { ItemBundle } from "@excel/character_table";
import { Rogue6IncidentEngine } from "./incident";

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
  /** 招募组 → 标准职业映射（data/rlv2/recruit-groups.json） */
  recruitGroups: { [key: string]: string[] };

  constructor() {
    this.choiceScenes = JSON.parse(
      readFileSync(`${__dirname}/../../../../data/rlv2/choices.json`, "utf-8"),
    );
    this.eventChoices = JSON.parse(
      readFileSync(`${__dirname}/../../../../data/rlv2/event_choices.json`, "utf-8"),
    );
    this.recruitGroups = JSON.parse(
      readFileSync(`${__dirname}/../../../../data/rlv2/recruit-groups.json`, "utf-8"),
    );
  }
}

import { generateShopGoods, buildShopContent, buyGoods, refreshShop, leaveShop, shopBattleStart, isInShopNode } from "./shop";
import { bankPut, bankWithdraw } from "./bank";
import { applyBandUpgradeVisibility, initModeGradeStates, maxClearedGrade, buildSettlement, exploreBreakdown, exploreScoreFactor, exploreScore, lifeGameNodes, blackstreamEfficiency, canEvolveOperators, blackstreamAwards, gameSettle, buildSettleResponse } from "./settle";
import { rerollNode, upgradeNode, gridZoneMoveTo, createRogue6NodeScene, createPortalScene, enterPortalZone, consumePortalScrap, startChaosSourceBattle, gainPreciousScrap, gainRandomScrap, isBeakUnlocked, createFateScene, createIncidentScene, gridZoneMoveAndBattleStart, gridZoneEmptyStep, gridZoneReadStepZero } from "./grid-nav";
import { _normalizeMutablePlayerdata, setPinned, giveUpGame, createGame, ensureOuterTheme, refreshMission, chooseInitialRelic, chooseInitialRecruitSet, chooseInitialExploreTool } from "./game-init";

import { finishEvent, hasReachedZone3, locateStartNode, zoneKey, isZoneEnd, checkZoneEnd, hasRelic, emitSpecialOperatorZone, nodeTypeCounts, emitSpecialOperatorSettle, selectChoice, readEndingChange } from "./event";
import { moveAndBattleStart, moveTo, createNodeScene, confirmZoneReward, confirmTraderReturn, specialZoneLeave, battlePassGetReward } from "./battle-nav";
import { chooseBattleReward, finishBattleReward } from "./reward";
import { activeRecruitTicket, recruitChar, closeRecruitTicket, getTicketAssistList, recruitAssistChar, stashRecruitTicket, useStashedTicket } from "./recruit-flow";

export class RoguelikeV2Manager implements PlayerRoguelikeV2 {
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

  _troop: TroopManager;

  _pool: RoguelikePoolManager;

  _data: RoguelikeV2Config;

  _player: PlayerDataManager;

  _trigger: TypedEventEmitter;

  _bandId = "";

  _settled = false;

  _pushMessages: RoguelikePushMessage[] = [];
  _shopSellCount?: number;

  _map!: RoguelikeMapManager;
  _status!: RoguelikePlayerStatusManager;
  _buff!: RoguelikeBuffManager;
  _module!: RoguelikeModuleManager;
  _battle!: RoguelikeBattleManager;
  _incident!: Rogue6IncidentEngine;
  inventory!: RoguelikeInventoryManager | null;

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

  pushMessage(path: string, payload: unknown, themeOverride?: string): void {
    const theme = themeOverride ?? this.current.game?.theme;
    if (theme !== "rogue_6") return;
    this._pushMessages.push({ path, payload });
  }

  takePushMessages(): RoguelikePushMessage[] {
    const out = this._pushMessages;
    this._pushMessages = [];
    return out;
  }

  clearPushMessages(): void {
    this._pushMessages = [];
  }

  clearPending(): void {
    this._status._pending._pending = [];
  }

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

  async confirmPredict(): Promise<void> {
    this._status._pending._pending.length = 0;
    await this.checkZoneEnd();
    this._status.state = "WAIT_MOVE";
  }

  async useTotem(args: {
    totemIndex: [string, string];
    nodeIndex: string[];
  }): Promise<void> {
    this._module.totem.use(args.totemIndex, args.nodeIndex);
  }

  static readonly NODE_SCENE_PREFIX: {
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

  async nodeMissionGiveUp(): Promise<void> {
    const nm = this._status.nodeMission;
    if (nm) nm.state = 3;
    this._status.state = "WAIT_MOVE";
  }

  async nodeMissionCloseTip(): Promise<void> {
    const nm = this._status.nodeMission;
    if (nm) nm.tip = false;
  }

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

  async confirmExpeditonReturn(): Promise<void> {
    this.troop.expedition = [];
    this.troop.expeditionReturn = null;
    this._status._pending._pending.length = 0;
    this._status.state = "WAIT_MOVE";
  }

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

  rollDice(theme: string, dm: any): any {
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

  async alchemyReward(args: { index?: number }): Promise<void> {
    // 简化：炼金合成奖励已由 fragment.alchemy 发放；此处确认结算并关闭界面
    this._status._pending._pending.length = 0;
    this._status.state = "WAIT_MOVE";
  }

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

  async copperRedraw(): Promise<{ copper: string[]; divineEventId: string }> {
    const cm = this._module.copper;
    const ret = cm?.redraw() || { copper: [], divineEventId: "" };
    this._status.state = "WAIT_MOVE";
    return ret;
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

  async scrap(): Promise<void> {
    this._status.state = "WAIT_MOVE";
  }

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

  async sellScrapAtShop(): Promise<void> {
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

  snapshotCurrent(): PlayerRoguelikeV2 {
    const j = this.toJSON();
    const pd = this._player._playerdata;
    if (pd.rlv2?.current) {
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
    return j;
  }

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

  _gameSeed: string | null = null;

  gameSeed(): string {
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

  buildDetailStr(brief: any): string | null {
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

  generateShopGoods(theme: string) : any[] {
    return generateShopGoods(this, theme);
  }

  buildShopContent(theme: string) : any {
    return buildShopContent(this, theme);
  }

  async buyGoods(args: { select: number }) : Promise<void> {
    return buyGoods(this, args);
  }

  async refreshShop() : Promise<void> {
    return refreshShop(this);
  }

  async leaveShop() : Promise<void> {
    return leaveShop(this);
  }

  async shopBattleStart() : Promise<void> {
    return shopBattleStart(this);
  }

  isInShopNode() : boolean {
    return isInShopNode(this);
  }

  async bankPut() : Promise<void> {
    return bankPut(this);
  }

  async bankWithdraw(args: { count?: number }) : Promise<void> {
    return bankWithdraw(this, args);
  }

  applyBandUpgradeVisibility(theme: string,
    buffId: string,
    collectBand: { [key: string]: { state: number } },) : void {
    return applyBandUpgradeVisibility(this, theme, buffId, collectBand);
  }

  initModeGradeStates(theme: string,
    map?: any,
    game?: any,) : {
    [mode: string]: { [grade: string]: { state: number; progress: number[] | null } };
  } {
    return initModeGradeStates(this, theme, map, game);
  }

  maxClearedGrade(cleared: Set<number>) : number {
    return maxClearedGrade(this, cleared);
  }

  buildSettlement(over: boolean,
    success: number,
    ending: string,) : { brief: any; record: any; buffBankPut: number } {
    return buildSettlement(this, over, success, ending);
  }

  exploreBreakdown() : { detail: number[][]; raw: number } {
    return exploreBreakdown(this);
  }

  exploreScoreFactor() : number {
    return exploreScoreFactor(this);
  }

  exploreScore() : number {
    return exploreScore(this);
  }

  lifeGameNodes(theme: string) : string[] {
    return lifeGameNodes(this, theme);
  }

  blackstreamEfficiency(theme: string, grade: number) : number {
    return blackstreamEfficiency(this, theme, grade);
  }

  canEvolveOperators(theme: string) : boolean {
    return canEvolveOperators(this, theme);
  }

  blackstreamAwards() : { sourceScore: number; efficiency: number } {
    return blackstreamAwards(this);
  }

  async gameSettle() : Promise<void> {
    return gameSettle(this);
  }

  buildSettleResponse() : { game: any; outer: any } {
    return buildSettleResponse(this);
  }

  async rerollNode(args: { nodeIndex: string }) : Promise<void> {
    return rerollNode(this, args);
  }

  async upgradeNode(args: { nodeType: string }) : Promise<void> {
    return upgradeNode(this, args);
  }

  async gridZoneMoveTo(args: { route: string[] }) : Promise<void> {
    return gridZoneMoveTo(this, args);
  }

  createRogue6NodeScene(nodeType: number) : boolean {
    return createRogue6NodeScene(this, nodeType);
  }

  createPortalScene() : void {
    return createPortalScene(this);
  }

  enterPortalZone(family: string) : void {
    return enterPortalZone(this, family);
  }

  consumePortalScrap() : boolean {
    return consumePortalScrap(this);
  }

  startChaosSourceBattle() : void {
    return startChaosSourceBattle(this);
  }

  gainPreciousScrap() : void {
    return gainPreciousScrap(this);
  }

  gainRandomScrap() : void {
    return gainRandomScrap(this);
  }

  isBeakUnlocked() : boolean {
    return isBeakUnlocked(this);
  }

  createFateScene() : void {
    return createFateScene(this);
  }

  async createIncidentScene() : Promise<boolean> {
    return createIncidentScene(this);
  }

  async gridZoneMoveAndBattleStart(args: {
    route: string[];
    stageId: string;
    squad: PlayerSquad;
  }) : Promise<void> {
    return gridZoneMoveAndBattleStart(this, args);
  }

  async gridZoneEmptyStep() : Promise<void> {
    return gridZoneEmptyStep(this);
  }

  async gridZoneReadStepZero() : Promise<void> {
    return gridZoneReadStepZero(this);
  }

  _normalizeMutablePlayerdata() : PlayerDataModel {
    return _normalizeMutablePlayerdata(this);
  }

  async setPinned(args: { id: string }) : Promise<void> {
    return setPinned(this, args);
  }

  async giveUpGame() : Promise<void> {
    return giveUpGame(this);
  }

  async createGame(args: {
    theme: string;
    mode: string;
    modeGrade: number;
    predefinedId: string | null;
  }) : Promise<void> {
    return createGame(this, args);
  }

  ensureOuterTheme(theme: string, outerMap?: any, game?: any) : void {
    return ensureOuterTheme(this, theme, outerMap, game);
  }

  async refreshMission(args: { theme?: string; index?: number }) : Promise<void> {
    return refreshMission(this, args);
  }

  async chooseInitialRelic(args: { select: string }) {
    return chooseInitialRelic(this, args);
  }

  async chooseInitialRecruitSet(args: { select: string }) {
    return chooseInitialRecruitSet(this, args);
  }

  async chooseInitialExploreTool(args: { select: string }) : Promise<void> {
    return chooseInitialExploreTool(this, args);
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
  /** 委派至 {@link finishEvent}（event.ts） */
  async finishEvent() {
    return finishEvent(this);
  }
  /** 委派至 {@link hasReachedZone3}（event.ts） */
  hasReachedZone3(stageCnt?: Record<string, number>) : boolean {
    return hasReachedZone3(this, stageCnt);
  }
  /** 委派至 {@link locateStartNode}（event.ts） */
  locateStartNode() : { x: number; y: number } | undefined {
    return locateStartNode(this);
  }
  /** 委派至 {@link zoneKey}（event.ts） */
  zoneKey(zone: number) : string | number {
    return zoneKey(this, zone);
  }
  /** 委派至 {@link isZoneEnd}（event.ts） */
  isZoneEnd() : boolean {
    return isZoneEnd(this);
  }
  /** 委派至 {@link checkZoneEnd}（event.ts） */
  async checkZoneEnd() : Promise<boolean> {
    return checkZoneEnd(this);
  }
  /** 委派至 {@link hasRelic}（event.ts） */
  hasRelic(id: string) : boolean {
    return hasRelic(this, id);
  }
  /** 委派至 {@link emitSpecialOperatorZone}（event.ts） */
  async emitSpecialOperatorZone(zone: number) : Promise<void> {
    return emitSpecialOperatorZone(this, zone);
  }
  /** 委派至 {@link nodeTypeCounts}（event.ts） */
  nodeTypeCounts() : Map<number, number> {
    return nodeTypeCounts(this);
  }
  /** 委派至 {@link emitSpecialOperatorSettle}（event.ts） */
  async emitSpecialOperatorSettle(theme: string,
    ending: string,) : Promise<void> {
    return emitSpecialOperatorSettle(this, theme, ending);
  }
  /** 委派至 {@link selectChoice}（event.ts） */
  async selectChoice(args: { choice: string }) : Promise<void> {
    return selectChoice(this, args);
  }
  /** 委派至 {@link readEndingChange}（event.ts） */
  async readEndingChange() : Promise<void> {
    return readEndingChange(this);
  }
  /** 委派至 {@link moveAndBattleStart}（battle-nav.ts） */
  async moveAndBattleStart(args: {
    to: RoguelikeNodePosition;
    stageId: string;
    squad: PlayerSquad;
  }) : Promise<string> {
    return moveAndBattleStart(this, args);
  }
  /** 委派至 {@link moveTo}（battle-nav.ts） */
  async moveTo(args: { to: RoguelikeNodePosition }) : Promise<void> {
    return moveTo(this, args);
  }
  /** 委派至 {@link createNodeScene}（battle-nav.ts） */
  createNodeScene(theme: string, nodeType: number) : void {
    return createNodeScene(this, theme, nodeType);
  }
  /** 委派至 {@link confirmZoneReward}（battle-nav.ts） */
  async confirmZoneReward() : Promise<void> {
    return confirmZoneReward(this);
  }
  /** 委派至 {@link confirmTraderReturn}（battle-nav.ts） */
  async confirmTraderReturn() : Promise<void> {
    return confirmTraderReturn(this);
  }
  /** 委派至 {@link specialZoneLeave}（battle-nav.ts） */
  async specialZoneLeave() : Promise<void> {
    return specialZoneLeave(this);
  }
  /** 委派至 {@link battlePassGetReward}（battle-nav.ts） */
  async battlePassGetReward(theme: string,
    rewards: string[],) : Promise<{ items: ItemBundle[] }> {
    return battlePassGetReward(this, theme, rewards);
  }
  /** 委派至 {@link chooseBattleReward}（reward.ts） */
  async chooseBattleReward(args: { index: number; sub: number }) {
    return chooseBattleReward(this, args);
  }
  /** 委派至 {@link finishBattleReward}（reward.ts） */
  async finishBattleReward(args: {}) {
    return finishBattleReward(this, args);
  }
  /** 委派至 {@link activeRecruitTicket}（recruit-flow.ts） */
  async activeRecruitTicket(args: { id: string }) {
    return activeRecruitTicket(this, args);
  }
  /** 委派至 {@link recruitChar}（recruit-flow.ts） */
  async recruitChar(args: {
    ticketIndex: string;
    optionId: string;
  }) : Promise<PlayerRoguelikeV2.CurrentData.RecruitChar[]> {
    return recruitChar(this, args);
  }
  /** 委派至 {@link closeRecruitTicket}（recruit-flow.ts） */
  async closeRecruitTicket(args: { id: string }) : Promise<void> {
    return closeRecruitTicket(this, args);
  }
  /** 委派至 {@link getTicketAssistList}（recruit-flow.ts） */
  async getTicketAssistList(args: {
    ticketIndex: string;
    profession: string;
  }) : Promise<void> {
    return getTicketAssistList(this, args);
  }
  /** 委派至 {@link recruitAssistChar}（recruit-flow.ts） */
  async recruitAssistChar(args: {
    ticketIndex: string;
    profession: string;
    assistUid: string;
    assistCharId: string;
  }) : Promise<void> {
    return recruitAssistChar(this, args);
  }
  /** 委派至 {@link stashRecruitTicket}（recruit-flow.ts） */
  async stashRecruitTicket(args: { index: string }) : Promise<void> {
    return stashRecruitTicket(this, args);
  }
  /** 委派至 {@link useStashedTicket}（recruit-flow.ts） */
  async useStashedTicket(args: { id: string }) : Promise<void> {
    return useStashedTicket(this, args);
  }
}
