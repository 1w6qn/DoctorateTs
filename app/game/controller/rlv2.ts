import {
  PlayerRoguelikeV2,
  RoguelikeNodePosition,
  TorappuRoguelikeEventType,
} from "../model/rlv2";
import excel from "@excel/excel";
import { readFileSync } from "fs";
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
import { BattleData } from "@game/model/battle";
import { RoguelikePoolManager } from "./rlv2/pool";
import { RoguelikeGameInitData } from "@excel/roguelike_topic_table";
import { TypedEventEmitter } from "@game/model/events";
import { WritableDraft } from "immer";
import { ItemBundle } from "@excel/character_table";

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
  pinned?: string;
  outer: { [key: string]: PlayerRoguelikeV2.OuterData };
  current: PlayerRoguelikeV2.CurrentData;
  troop: RoguelikeTroopManager;
  _map!: RoguelikeMapManager;
  _status!: RoguelikePlayerStatusManager;
  _buff!: RoguelikeBuffManager;
  _module!: RoguelikeModuleManager;
  _battle!: RoguelikeBattleManager;
  _troop: TroopManager;
  _pool: RoguelikePoolManager;
  _data: RoguelikeV2Config;
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;
  inventory!: RoguelikeInventoryManager | null;
  /** 本次对局所选分队（开局 chooseInitialRelic 记录，结算 brief.band 用） */
  _bandId = "";

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    // rlv2 内部模型（model/rlv2.ts）与生成模型（types-playerdata）为同一数据的两种视图：
    // 内部模型为功能实现的类型契约，生成模型为线格式存储视图，边界处做显式桥接
    this.outer = player._playerdata.rlv2.outer as unknown as {
      [key: string]: PlayerRoguelikeV2.OuterData;
    };
    this.current = player._playerdata.rlv2.current as unknown as PlayerRoguelikeV2.CurrentData;
    this.pinned = player._playerdata.rlv2.pinned;
    this._player = player;
    this._trigger = _trigger;
    this._data = new RoguelikeV2Config();
    this._troop = player.troop;
    this.current.game = {
      mode: "NONE",
      predefined: "",
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

    this.troop = new RoguelikeTroopManager(this, this._trigger);
    this._status = new RoguelikePlayerStatusManager(this, this._trigger);
    this.inventory = new RoguelikeInventoryManager(this, this._trigger);
    this._buff = new RoguelikeBuffManager(this, this._trigger);
    this._map = new RoguelikeMapManager(this, this._trigger);
    this._module = new RoguelikeModuleManager(this, this._trigger);
    this._battle = new RoguelikeBattleManager(this, this._trigger);
    this._pool = new RoguelikePoolManager(this, this._trigger);
    this._trigger.emit("rlv2:init", [this]);
  }

  get initConfig(): RoguelikeGameInitData {
    const game = this.current.game!;
    return excel.RoguelikeTopicTable.details[game.theme].init.find(
      (i) =>
        i.modeGrade == game.modeGrade &&
        i.predefinedId == game.predefined &&
        i.modeId == game.mode,
    )!;
  }

  async update<T>(
    recipe: (draft: WritableDraft<PlayerRoguelikeV2>) => Promise<T>,
  ): Promise<T> {
    const result = await this._player.update(async (draft) => {
      return await recipe(draft.rlv2 as unknown as WritableDraft<PlayerRoguelikeV2>);
    });
    // Immer finishDraft 替换 _playerdata：统一刷新本控制器引用。
    // recipe 克隆过的子树（draft.outer/current/pinned 任一被写即整体克隆）会让
    // this.outer/this.current 指向旧对象，后续 createGame/gameSettle 的直接写会落到孤儿对象（重启丢失）。
    // 所有 rlv2 状态写都经本出口（含 disaster 等子管理器），在此统一刷新最稳妥。
    this.outer = this._player._playerdata.rlv2.outer as unknown as {
      [key: string]: PlayerRoguelikeV2.OuterData;
    };
    this.current = this._player._playerdata.rlv2.current as unknown as PlayerRoguelikeV2.CurrentData;
    this.pinned = this._player._playerdata.rlv2.pinned;
    return result;
  }

  async setPinned(args: { id: string }): Promise<void> {
    const { id } = args;
    await this.update(async (draft) => {
      draft.pinned = id;
    });
  }

  async giveUpGame(): Promise<void> {
    // 放弃结算：生成 GAME_SETTLE 事件（客户端展示放弃结算页），保留游戏态直至 gameSettle 确认
    const { brief, record } = this.buildSettlement(true, 0, "");
    this.current.record = { brief, record };
    await this._trigger.emit("rlv2:event:create", [
      "GAME_SETTLE",
      {
        success: 0,
        result: { brief, record },
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
    this.current.game = {
      mode: args.mode === "MONTH_TEAM" || args.mode === "CHALLENGE" ? "NORMAL" : args.mode,
      predefined: args.predefinedId,
      theme: theme,
      outer: {
        // 开局支持阶段（GAME_INIT_SUPPORT/startbuff 选择）——客户端抓包（rogue_6 modeGrade 15）
        // 在 chooseInitialRelic 后调用 finishEvent + selectChoice(choice_roX_startbuff_N)
        support: true,
      },
      start: now(),
      modeGrade: args.modeGrade,
      equivalentGrade: args.modeGrade,
    };
    this.current.buff = {
      tmpHP: 0,
      capsule: null,
      squadBuff: [],
    };
    this.current.record = { brief: null };
    this.current.map = { zones: {} };
    this.current.troop = {
      chars: {},
      expedition: [],
      expeditionDetails: {},
      expeditionReturn: null,
      hasExpeditionReturn: false,
    };
    // 首次游玩该主题：初始化 outer[theme] 基础结构（bank/bp/buff/collect/mission 等）
    this.ensureOuterTheme(theme);

    // 绕过 update() 的原地初始化不产生 Immer 补丁，显式标记脏以触发条件落盘
    this._player.markDirty();
    await this._trigger.emit("rlv2:create", [this]);
  }

  /**
   * 初始化主题局外数据（首次游玩）：collect.band 分队解锁状态等
   * 客户端按 collect.band[id].state 决定开局分队可选性
   */
  private ensureOuterTheme(theme: string): void {
    if (!this.outer[theme]) {
      this.outer[theme] = {} as any;
    }
    const outer = this.outer[theme] as any;
    if (!outer.collect) {
      const detail = excel.RoguelikeTopicTable.details[theme];
      // 分队全集：init.initialBandRelic（开局可选）+ bandRef 全部条目（含等级变体）
      const init = detail.init.find(
        (i: any) =>
          i.modeGrade == this.current.game!.modeGrade &&
          i.predefinedId == this.current.game!.predefined &&
          i.modeId == this.current.game!.mode,
      );
      const initialBandIds: string[] = init?.initialBandRelic || [];
      const bandRef = (detail.bandRef || {}) as Record<string, any>;
      const allBandIds = [
        ...new Set([...initialBandIds, ...Object.keys(bandRef)]),
      ];
      outer.collect = {
        // 分队解锁状态（state 1 = 已解锁，含等级变体；基础分队开局可选）
        band: Object.fromEntries(
          allBandIds.map((id) => [id, { state: 1, progress: null }]),
        ),
        relic: {},
        capsule: {},
        activeTool: {},
        mode: {},
        recruitSet: {},
        buff: {},
        bgm: {},
        pic: {},
        chat: {},
        endBook: {},
        chatV2: {},
      };
    }
    if (!outer.bank) outer.bank = { show: false, current: 0, record: 0, reward: {} };
    if (!outer.bp) outer.bp = { point: 0, reward: {} };
    if (!outer.buff) outer.buff = { pointOwned: 0, pointCost: 0, unlocked: {}, score: 0 };
    if (!outer.mission) outer.mission = { updateId: "", refresh: 0, list: [] };
    if (!outer.record) {
      outer.record = { last: 0, stageCnt: {}, bandCnt: {}, bandGrade: {} };
    }
  }

  async chooseInitialRelic(args: { select: string }) {
    const event = this._status.pending.shift()!;
    const relic = event.content.initRelic!.items[args.select];
    // 记录所选分队（结算 brief.band）
    this._bandId = relic.id;
    await this.inventory!._relic.gain([relic]);
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

    // 招募组数据源：官方 recruitGrps 为元数据对象（id/iconId/name/desc，无 ticket 映射）
    // → 退化为发放 3 张随机职业招募券（参考 ODPY rlv2ChooseInitialRecruitSet addTicket ×3）。
    // 只取 8 大职业标准票（排除 _sp/_vip/_candle/_double 等变体，变体职业列表为空导致空候选）
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
    const tickets = Object.keys(
      (excel.RoguelikeTopicTable.details[theme] as any)?.recruitTickets || {},
    ).filter((t) => {
      const roNum = theme.slice(-1);
      return PROFESSIONS.some(
        (p) => t === `rogue_${roNum}_recruit_ticket_${p}`,
      );
    });
    const shuffled = [...tickets].sort(() => Math.random() - 0.5);
    for (const r of shuffled.slice(0, 3)) {
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
    await this._trigger.emit("rlv2:recruit:active", [args.id]);
  }

  async recruitChar(args: {
    ticketIndex: string;
    optionId: string;
  }): Promise<PlayerRoguelikeV2.CurrentData.RecruitChar[]> {
    const { ticketIndex, optionId } = args;
    await this._trigger.emit("rlv2:recruit:done", [ticketIndex, optionId]);
    return [this.inventory!.recruit[ticketIndex].result!];
  }

  async finishEvent() {
    if (this._status.cursor.zone === 0) {
      // 初始阶段：RELIC/SUPPORT/RECRUIT_SET 由各自专用接口消费
      // （chooseInitialRelic/selectChoice/chooseInitialRecruitSet），finishEvent 仅消费
      // GAME_INIT_RECRUIT（开局招募完成）——客户端抓包：开局招募完成后调 finishEvent 结束初始阶段。
      // 全部 GAME_INIT_* 消费完才生成第一层地图。
      const top = this._status.pending[0];
      if (top && top.type === "GAME_INIT_RECRUIT") {
        this._status.pending.shift();
      }
      const hasInit = this._status.pending.some((e) =>
        (e.type || "").startsWith("GAME_INIT_"),
      );
      if (hasInit) {
        this._status.state = "INIT";
        return;
      }
      this._status.cursor.zone = 1;
      this._status.cursor.position = null;
      await this._trigger.emit("rlv2:zone:new", [this._status.cursor.zone]);
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

  /** 主流程最大层数（取有普通/紧急关卡的 zone 最大值） */
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
    return max || 6;
  }

  /** 当前节点是否为本层终点（zone_end） */
  private isZoneEnd(): boolean {
    const pos = this._status.cursor.position;
    if (!pos) return false;
    const node = this._map.zones[this._status.cursor.zone]?.nodes[
      pos.x * 100 + pos.y
    ];
    return !!node?.zone_end;
  }

  /** 节点结束后检查：到达本层终点则推进下一层（最终层则结算）。返回是否已触发结算。 */
  private async checkZoneEnd(): Promise<boolean> {
    if (!this.isZoneEnd()) return false;
    const zone = this._status.cursor.zone;
    if (zone >= this.maxZone) {
      // 修复：fire-and-forget 未捕获拒绝会导致 Node 进程终止（gameSettle 内部 game 可能为 null）
      void this.gameSettle().catch((e) =>
        logger.error("rlv2", `gameSettle failed: ${(e as Error).message}`),
      );
      return true;
    }
    // 区域奖励：非最终层通关时填充 zoneReward（confirmZoneReward 发放并清空）
    if (!this._status.zoneReward || Object.keys(this._status.zoneReward).length === 0) {
      const theme = this.current.game!.theme;
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
    this._status.cursor.zone += 1;
    this._status.cursor.position = null;
    await this._trigger.emit("rlv2:zone:new", [this._status.cursor.zone]);
    return false;
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
    const top = this._status.pending[0];
    if (top && top.type === "GAME_INIT_SUPPORT") {
      const itemId = (choiceConfig?.displayData as any)?.itemId;
      if (itemId) {
        // 奖励数量：description 含 <@roX.get>N</>（如"获得<@ro6.get>8</>源石锭"）
        const m = (choiceConfig?.description || "").match(
          /<@ro\d+\.get>(\d+)<\/>/,
        );
        const count = m ? parseInt(m[1], 10) : 1;
        this._trigger.emit("rlv2:get:items", [[{ id: itemId, count }]]);
      }
      this._status.pending.shift();
      this._status.state = "WAIT_MOVE";
      return;
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

        // 官方选项效果：displayData.itemId（REST 回血/进阶券/希望等节点特有效果）
        const officialItem = (choiceConfig?.displayData as any)?.itemId;
        if (officialItem) {
          this._trigger.emit("rlv2:get:items", [
            [{ id: officialItem, count: 1 }],
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

  generateShopGoods(theme: string): any[] {
    const detail = excel.RoguelikeTopicTable.details[theme];
    const ticket = `${theme}_recruit_ticket_all`;
    const priceId = `${theme}_gold`;
    
    const goods: any[] = [{
      index: "0",
      itemId: ticket,
      count: 1,
      priceId: priceId,
      priceCount: 0,
      origCost: 0,
      displayPriceChg: false,
      _retainDiscount: 1,
    }];

    let i = 1;
    const relicMap = detail.archiveComp?.relic?.relic || {};
    for (const relicId of Object.keys(relicMap)) {
      goods.push({
        index: `${i}`,
        itemId: relicId,
        count: 1,
        priceId: priceId,
        priceCount: 0,
        origCost: 0,
        displayPriceChg: false,
        _retainDiscount: 1,
      });
      i++;
    }

    const difficultyGroups = detail.difficultyUpgradeRelicGroups || {};
    for (const group of Object.values(difficultyGroups)) {
      const relicData = (group as any).relicData || [];
      for (const relicItem of relicData) {
        goods.push({
          index: `${i}`,
          itemId: relicItem.relicId,
          count: 1,
          priceId: priceId,
          priceCount: 0,
          origCost: 0,
          displayPriceChg: false,
          _retainDiscount: 1,
        });
        i++;
      }
    }

    return goods;
  }

  async buyGoods(args: { select: number }): Promise<void> {
    const { select } = args;
    const shopEvent = this._status.pending[0];
    if (!shopEvent || shopEvent.type !== "SHOP") return;
    
    const goods = shopEvent.content.shop?.goods || [];
    const selectedGood = goods[select];
    if (!selectedGood) return;

    const itemId = selectedGood.itemId;
    const priceCount = selectedGood.priceCount || 0;

    if (priceCount > 0 && this._status.property.gold < priceCount) {
      return;
    }

    if (priceCount > 0) {
      this._status.property.gold -= priceCount;
    }

    if (itemId.includes("_recruit_ticket_")) {
      this._trigger.emit("rlv2:recruit:gain", [itemId, "shop", 0]);
      const tickets = Object.values(this.inventory!.recruit);
      const ticketIndex = tickets[tickets.length - 1]?.index;
      if (ticketIndex) {
        this._trigger.emit("rlv2:recruit:active", [ticketIndex]);
        this._trigger.emit("rlv2:event:create", ["RECRUIT", { ticket: ticketIndex }]);
      }
    } else if (itemId.includes("_relic_")) {
      this._trigger.emit("rlv2:relic:gain", [{ id: itemId, count: 1 }]);
    } else if (itemId.includes("_active_tool_")) {
      this._trigger.emit("rlv2:get:items", [[{ id: itemId, count: 1 }]]);
    } else if (itemId.includes("_explore_tool_")) {
      this._trigger.emit("rlv2:get:items", [[{ id: itemId, count: 1 }]]);
    }

    goods.splice(select, 1);
    for (let idx = select; idx < goods.length; idx++) {
      goods[idx].index = `${idx}`;
    }
  }

  /** 商店刷新：重生成当前商店商品并扣除刷新次数 */
  async refreshShop(): Promise<void> {
    const shopEvent = this._status.pending[0];
    if (!shopEvent || shopEvent.type !== "SHOP") return;
    const shop = shopEvent.content.shop;
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
          {
            bank: {
              open: true,
              canPut: true,
              canWithdraw: true,
              withdraw: 0,
              cost: 1,
              withdrawLimit: 20,
            },
          },
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
    // 标准地图节点 fts 标记（网格区域用 gridZone 节点——标准地图可能无此节点，容错跳过）
    const pos = this._status.cursor.position;
    if (pos) {
      const node = this._map.zones[this._status.cursor.zone]?.nodes[
        `${pos.x * 100 + pos.y}`
      ];
      if (node) node.fts = now();
    }
  }

  chooseBattleReward(args: { index: number; sub: number }) {
    const rewardGrp =
      this._status.pending[0].content.battleReward!.rewards.find(
        (r) => r.index == args.index,
      )!;
    const reward = rewardGrp.items.find((r) => r.sub == args.sub)!;
    this._trigger.emit("rlv2:get:items", [[reward]]);

    rewardGrp.done = 1;
  }

  async finishBattleReward(args: {}) {
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
    const node = this._map.zones[zone]?.nodes[nodeIndex];
    if (!node) return;
    const refresh = node.refresh;
    if (refresh && refresh.usedCount >= refresh.count) return;
    if (refresh) refresh.usedCount += 1;
    // 官方 rollNodeData 按 zoneId 分组（rogue_6 有配置；其余主题为空 → 随机换战斗类型）
    const theme = this.current.game!.theme;
    const rollNodeData = (excel.RoguelikeTopicTable.details[theme] as any)
      ?.rollNodeData;
    const zoneId = this._map.zones[zone].id;
    const group = rollNodeData?.[zoneId]?.groups;
    if (group) {
      const types = Object.values(group) as { nodeType: string }[];
      const typeMap: { [key: string]: number } = {
        BATTLE_NORMAL: 1,
        BATTLE_ELITE: 2,
        BATTLE_BOSS: 4,
        SHOP: 8,
        REST: 16,
        INCIDENT: 32,
        TREASURE: 64,
        ENTERTAINMENT: 128,
        UNKNOWN: 256,
        WISH: 512,
        SACRIFICE: 1024,
        EXPEDITION: 2048,
        BATTLE_SHOP: 4096,
        PORTAL: 8192,
      };
      const pick = types[Math.floor(Math.random() * types.length)];
      node.type = typeMap[pick.nodeType] ?? 1;
      const stageKeys = Object.keys(
        (excel.RoguelikeTopicTable.details[theme] as any)?.stages || {},
      );
      const zoneNum = String(zone);
      const roNum = theme.slice(-1);
      const candidates = stageKeys.filter((s) =>
        s.startsWith(`ro${roNum}_n_${zoneNum}_`),
      );
      if (candidates.length > 0) {
        node.stage = candidates[Math.floor(Math.random() * candidates.length)];
      }
    } else {
      node.type = 1;
      const stageKeys = Object.keys(
        (excel.RoguelikeTopicTable.details[theme] as any)?.stages || {},
      );
      const roNum = theme.slice(-1);
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

  /** 暂存招募票（CS: RoguelikeStashTicketRequest { index }） */
  async stashRecruitTicket(args: { index: string }): Promise<void> {
    const ticket = this.inventory!.recruit[args.index];
    if (!ticket) return;
    // 暂存：state=3 且移出候选（简化——客户端展示暂存票由 stash 数据驱动）
    ticket.state = 3;
    ticket.list = [];
  }

  /** 使用暂存票（CS: RoguelikeStashedTicketUseRequest { id }） */
  async useStashedTicket(args: { id: string }): Promise<void> {
    const ticket = this.inventory!.recruit[args.id];
    if (!ticket) return;
    ticket.state = 0;
    this._trigger.emit("rlv2:recruit:active", [args.id]);
    this._trigger.emit("rlv2:event:create", ["RECRUIT", { ticket: args.id }]);
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

  /** 网格区域移动（抓包 { route: [nodeIndex] }）：沿 route 移动并消耗行动力 */
  async gridZoneMoveTo(args: { route: string[] }): Promise<void> {
    const route = args.route || [];
    if (route.length === 0) return;
    const gz = this._module.gridZone;
    // 消耗行动力；耗尽则回到 WAIT_MOVE（行动力用尽离开网格区域）
    this._trigger.emit("rlv2:grid:step", []);
    const node = gz?.moveTo(route);
    const zone = this._status.cursor.zone;
    const last = route[route.length - 1];
    const lastX = Math.floor(Number(last) / 100);
    const lastY = Number(last) % 100;
    this._status.trace.push({ zone, position: { x: lastX, y: lastY } });
    this._status.cursor.position = { x: lastX, y: lastY };
    if (node?.content?.savage?.stageId) {
      // 战斗节点 → 战斗
      this._status.state = "PENDING";
      await this._trigger.emit("rlv2:battle:start", [
        node.content.savage.stageId,
      ]);
      return;
    }
    if (node?.content?.shop) {
      this._status.state = "PENDING";
      this._trigger.emit("rlv2:event:create", [
        "BATTLE_SHOP",
        {
          bank: {
            open: true,
            canPut: true,
            canWithdraw: true,
            withdraw: 0,
            cost: 1,
            withdrawLimit: 20,
          },
        },
      ]);
      return;
    }
    // 空节点：网格区域自由移动，回到 WAIT_MOVE（客户端继续走）
    this._status.state = "WAIT_MOVE";
  }

  /** 网格区域移动并开始战斗（抓包 { route, stageId, squad }） */
  async gridZoneMoveAndBattleStart(args: {
    route: string[];
    stageId: string;
    squad: PlayerSquad;
  }): Promise<void> {
    const gz = this._module.gridZone;
    this._trigger.emit("rlv2:grid:step", []);
    gz?.moveTo(args.route);
    const zone = this._status.cursor.zone;
    const last = args.route[args.route.length - 1];
    const lastX = Math.floor(Number(last) / 100);
    const lastY = Number(last) % 100;
    this._status.trace.push({ zone, position: { x: lastX, y: lastY } });
    this._status.cursor.position = { x: lastX, y: lastY };
    this._status.state = "PENDING";
    await this._trigger.emit("rlv2:battle:start", [args.stageId]);
  }

  /** 网格区域空步：消耗一步行动力（不移动） */
  async gridZoneEmptyStep(): Promise<void> {
    this._trigger.emit("rlv2:grid:step", []);
    this._status.state = "WAIT_MOVE";
  }

  /** 网格区域读取第 0 步：确认初始位置 */
  async gridZoneReadStepZero(): Promise<void> {
    const gz = this._module.gridZone;
    if (gz) gz.needConfirmStepZero = 0;
    this._status.state = "PENDING";
  }

  /** 废品操作（rogue_6 SCRAP 模块）：切换当前载具或保持步行 */
  async scrap(): Promise<void> {
    this._status.state = "WAIT_MOVE";
  }

  /** 废品换乘（SCRAP MOVE 型）：切换载具 */
  async scrapChangeVehicle(args: { scrapId?: string }): Promise<void> {
    const sm = this._module.scrap;
    sm?.changeVehicle(args.scrapId || "");
    this._status.state = "WAIT_MOVE";
  }

  /**
   * 节点事件触发（gridZone 移动落地）：复用 moveTo 的节点类型分发
   * @param nodeType TorappuRoguelikeEventType
   */
  private triggerNodeEvent(nodeType: number): void {
    const theme = this.current.game!.theme;
    switch (nodeType) {
      case TorappuRoguelikeEventType.INCIDENT: {
        const enterScenes = this._data.eventChoices?.[theme]?.enter;
        if (enterScenes) {
          const sceneIds = Object.keys(enterScenes);
          if (sceneIds.length > 0) {
            const sceneId =
              sceneIds[Math.floor(Math.random() * sceneIds.length)];
            const choicesList = enterScenes[sceneId] || [];
            const choices = choicesList.reduce(
              (acc, cid) => ({ ...acc, [cid]: 1 }),
              {},
            );
            const choiceAdditional = choicesList.reduce(
              (acc, cid) => ({ ...acc, [cid]: { rewards: [] } }),
              {},
            );
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
      case TorappuRoguelikeEventType.BATTLE_SHOP:
        this._trigger.emit("rlv2:event:create", [
          "BATTLE_SHOP",
          {
            bank: {
              open: true,
              canPut: true,
              canWithdraw: true,
              withdraw: 0,
              cost: 1,
              withdrawLimit: 20,
            },
          },
        ]);
        break;
      default:
        this.createNodeScene(theme, nodeType);
        break;
    }
  }

  toJSON(): PlayerRoguelikeV2 {
    return {
      outer: this.outer,
      current: {
        player: this._status,
        record: this.current.record,
        map: this._map,
        inventory: this.inventory,
        game: this.current.game,
        troop: this.troop,
        buff: this.current.buff,
        module: this._module,
      },
      pinned: this.pinned,
    };
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
    });
    return { success: true };
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
  private buildSettlement(
    over: boolean,
    success: number,
    ending: string,
  ): { brief: any; record: any } {
    const game = this.current.game!;
    const theme = game.theme;
    const endTs = Date.now();
    const startTs = game.start || endTs;
    const property = this._status.property;

    // 战斗/招募计数（trace 节点类型统计）
    let cntBattleNormal = 0;
    let cntBattleElite = 0;
    let cntBattleBoss = 0;
    let cntArrivedNode = this._status.trace.length;
    const cntArrivedNodeType: { [key: number]: number } = {};
    for (const t of this._status.trace) {
      const node = this._map.zones[t.zone]?.nodes[
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
      predefined: game.predefined || "",
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
      modeGrade: game.modeGrade,
    };

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
      cntRecruitProfession: {},
      troopChars,
      cntArrivedNodeType,
      relicList: Object.values(this.inventory!.relic || {}).map(
        (r) => (r as any).id,
      ),
      capsuleList: [],
      activeToolList: Object.values(this.inventory?.exploreTool || {}).map(
        (t) => (t as any).id,
      ),
      zones: Object.keys(this._map.zones).length,
      nodeMission: [],
      squadBuff: this.current.buff?.squadBuff || [],
      charBuff: [],
    };

    return { brief, record };
  }

  /** 探索分数（官方公式，用户提供 2026-08：萨卡兹方式，各主题一致） */
  private exploreScore(): number {
    const theme = this.current.game!.theme;
    // 层数档位 0/30/80/150/270/400/550/650（>7 按 7）+ 步数×1 + 普通战×10 + 招募×2
    // + 物品×5（收藏品+战术道具，不含思绪）+ 领袖战×30 + 精英战×20，求和 × 难度倍率
    const ZONE_SCORES = [0, 30, 80, 150, 270, 400, 550, 650];
    const clearedZones = Math.min(this._status.cursor.zone, 7);
    const zoneScore = ZONE_SCORES[clearedZones];
    const steps = this._status.trace.length;
    let normalBattles = 0;
    let eliteBattles = 0;
    let leaderBattles = 0;
    for (const t of this._status.trace) {
      const node = this._map.zones[t.zone]?.nodes[
        `${(t.position?.x ?? 0) * 100 + (t.position?.y ?? 0)}`
      ];
      const type = node?.type ?? 0;
      if (type === 1) normalBattles++;
      else if (type === 2) eliteBattles++;
      else if (type === 4) leaderBattles++;
    }
    const recruitCount = Object.values(this.inventory!.recruit || {}).filter(
      (t) => (t as any).result,
    ).length;
    const itemCount =
      Object.keys(this.inventory!.relic || {}).length +
      Object.keys(this.inventory?.exploreTool || {}).length;
    const raw =
      zoneScore +
      steps +
      normalBattles * 10 +
      recruitCount * 2 +
      itemCount * 5 +
      leaderBattles * 30 +
      eliteBattles * 20;
    const difficulty = excel.RoguelikeTopicTable.details[theme].difficulties?.find(
      (d) => d.modeDifficulty === this.current.game!.mode && d.grade === this.current.game!.modeGrade,
    );
    const scoreFactor = difficulty?.scoreFactor ?? 1;
    return Math.floor(raw * scoreFactor);
  }

  async gameSettle(): Promise<void> {
    const theme = this.current.game!.theme;
    const ending = this._status.toEnding || "";
    const success = ending === "normal" || this._status.chgEnding ? 1 : 0;
    const { brief, record } = this.buildSettlement(true, success, ending);
    this.current.record = { brief, record };

    // 探索分数 → 魂灵书签（1:1）
    const exploreScore = this.exploreScore();
    await this.update(async (draft) => {
      const outerTheme = draft.outer[theme] ?? (draft.outer[theme] = {} as any);
      const buff =
        outerTheme.buff ??
        (outerTheme.buff = {
          pointOwned: 0,
          pointCost: 0,
          unlocked: {},
          score: 0,
        } as any);
      buff.score = (buff.score || 0) + exploreScore;
      buff.pointOwned = (buff.pointOwned || 0) + exploreScore;
    });

    await this._trigger.emit("rlv2:event:create", [
      "GAME_SETTLE",
      {
        success,
        result: { brief, record },
        popReport: false,
      },
    ]);

    this._status.state = "END";
  }
}
