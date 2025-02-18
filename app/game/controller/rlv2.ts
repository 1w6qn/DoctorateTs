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

export class RoguelikeV2Config {
  choiceScenes: { [key: string]: { choices: { [key: string]: number } } };

  constructor() {
    this.choiceScenes = JSON.parse(
      readFileSync(`${__dirname}/../../../data/rlv2/choices.json`, "utf-8"),
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

  setPinned(id: string): void {
    this.pinned = id;
  }

  giveUpGame(): void {
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
    this._trigger.emit("rlv2:init", [this]);
  }

  async createGame(args: {
    theme: string;
    mode: string;
    modeGrade: number;
    predefinedId: string | null;
  }): Promise<void> {
    //TODO
    console.log("[RLV2] Game creation", args);
    this.current.game = {
      mode: args.mode,
      predefined: args.predefinedId,
      theme: args.theme,
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
    await this._trigger.emit("rlv2:create", [this]);
  }

  async chooseInitialRelic(args: { select: string }) {
    const event = this._status.pending.shift();
    const relic = event!.content.initRelic!.items[args.select];
    await this.inventory!._relic.gain([relic]);
  }

  async chooseInitialRecruitSet(args: { select: string }) {
    const theme = this.current.game!.theme;
    const event = this._status.pending.shift();
    const event2 = this._status.pending.find(
      (e) => e.type === "GAME_INIT_RECRUIT",
    )!;
    //TODO
    excel.RoguelikeConsts[theme].recruitGrps[args.select].forEach((r) => {
      console.log("gain recruit", r);
      this._trigger.emit("rlv2:recruit:gain", [r, "initial", 0]);
    });
    event2.content.initRecruit!.tickets = Object.values(this.inventory!.recruit)
      .filter((r) => r.from == "initial")
      .map((r) => r.index);
  }

  async activeRecruitTicket(args: { id: string }) {
    await this._trigger.emit("rlv2:recruit:active", [args.id]);
  }

  recruitChar(args: {
    ticketIndex: string;
    optionId: string;
  }): PlayerRoguelikeV2.CurrentData.RecruitChar[] {
    this._trigger.emit("rlv2:recruit:done", [args.ticketIndex, args.optionId]);
    return [this.inventory!.recruit[args.ticketIndex].result!];
  }

  finishEvent() {
    this._status.pending.shift();
    this._status.cursor.zone = 1;
    this._status.cursor.position = null;
    this._trigger.emit("rlv2:zone:new", [this._status.cursor.zone]);
    this._status.state = "WAIT_MOVE";
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
      case TorappuRoguelikeEventType.INCIDENT:
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

  finishBattleReward(args: {}) {
    this._status.pending.shift();
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
}
