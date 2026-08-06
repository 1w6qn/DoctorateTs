import {
  PlayerRoguelikeV2,
  RoguelikeNodePosition,
  TorappuRoguelikeEventType,
} from "../model/rlv2";
import excel from "@excel/excel";
import { readFileSync } from "fs";
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

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this.outer = player._playerdata.rlv2.outer;
    this.current = player._playerdata.rlv2.current;
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
    return await this._player.update(async (draft) => {
      return await recipe(draft.rlv2);
    });
  }

  async setPinned(args: { id: string }): Promise<void> {
    const { id } = args;
    await this.update(async (draft) => {
      draft.pinned = id;
    });
  }

  async giveUpGame(): Promise<void> {
    await this.update(async (draft) => {
      draft.current.game = {
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
      draft.current.buff = {
        tmpHP: 0,
        capsule: null,
        squadBuff: [],
      };
      draft.current.record = { brief: null };
    });

    await this._trigger.emit("rlv2:init", [this]);
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
        support: false,
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

    await this._trigger.emit("rlv2:create", [this]);
  }

  async chooseInitialRelic(args: { select: string }) {
    const event = this._status.pending.shift()!;
    const relic = event.content.initRelic!.items[args.select];
    await this.inventory!._relic.gain([relic]);
  }

  async chooseInitialRecruitSet(args: { select: string }) {
    const theme = this.current.game!.theme;
    const event = this._status.pending.shift()!;
    const event2 = this._status.pending.find(
      (e) => e.type === "GAME_INIT_RECRUIT",
    )!;

    // 招募组数据源：data/rlv2.json（RoguelikeConsts）优先，缺失回退官方 excel recruitGrps
    const grps =
      excel.RoguelikeConsts?.[theme]?.recruitGrps ??
      (excel.RoguelikeTopicTable as any)?.details?.[theme]?.recruitGrps ??
      {};
    for (const r of grps[args.select] ?? []) {
      await this._trigger.emit("rlv2:recruit:gain", [r, "initial", 0]);
    }

    event2.content.initRecruit!.tickets = Object.values(this.inventory!.recruit)
      .filter((r) => r.from == "initial")
      .map((r) => r.index);
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
    this._status.pending.shift();
    if (this._status.cursor.zone === 0) {
      // 初始阶段结束 → 生成第一层地图
      this._status.cursor.zone = 1;
      this._status.cursor.position = null;
      await this._trigger.emit("rlv2:zone:new", [this._status.cursor.zone]);
      this._status.state = "WAIT_MOVE";
    } else {
      // 先检查本层终点（isZoneEnd 依赖当前 position），再清空位置
      const settling = await this.checkZoneEnd();
      this._status.cursor.position = null;
      if (settling) {
        // 最终层结算已触发（gameSettle 为异步，此处同步置 END 保证状态一致）
        this._status.state = "END";
        return;
      }
      this._status.state = "WAIT_MOVE";
    }
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
      void this.gameSettle();
      return true;
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

  /** 离开商店：清空 pending 回到等待移动状态 */
  async leaveShop(): Promise<void> {
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
    }
    this._status.cursor.position = args.to;
  }

  async battleFinish(args: {
    battleLog: string;
    data: string;
    battleData: BattleData;
  }) {
    await this._trigger.emit("rlv2:battle:finish", [args]);
    const pos = `${this._status.cursor.position!.x * 100 + this._status.cursor.position!.y}`;
    this._map.zones[this._status.cursor.zone].nodes[pos].fts = now();
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

  bankWithdraw(args: {}) {
    const theme = this.current.game!.theme;
    this._trigger.emit("rlv2:bank:withdraw", []);
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

  async gameSettle(): Promise<void> {
    const game = this.current.game!;
    const theme = game.theme;
    const endTs = Date.now();
    const startTs = game.start || Date.now();

    const brief = {
      level: this._status.property.level,
      success: this._status.toEnding === "normal" ? 1 : 0,
      ending: this._status.toEnding,
      theme: theme,
      mode: game.mode,
      predefined: game.predefined || "",
      band: "",
      startTs: startTs,
      endTs: endTs,
      endZoneId: `${this._status.cursor.zone}`,
      modeGrade: game.modeGrade,
    };

    const record = {
      cntZone: Object.keys(this._map.zones).length,
      relicList: Object.values(this.inventory!.relic).map((r) => (r as any).id),
      capsuleList: [],
      activeToolList: [],
      charBuff: [],
      squadBuff: this.current.buff?.squadBuff || [],
      totemList: [],
      exploreToolList: [],
      fragmentList: [],
    };

    this.current.record = {
      brief: brief,
      record: record,
    };

    await this._trigger.emit("rlv2:event:create", [
      "END_RESULT",
      {
        result: {
          brief: brief,
          record: record,
        },
      },
    ]);

    this._status.state = "END";
  }
}
