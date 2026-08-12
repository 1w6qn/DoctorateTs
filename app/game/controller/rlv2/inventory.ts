import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../model/rlv2";
import { RoguelikeRelicManager } from "./relic";
import { RoguelikeRecruitManager } from "./recruit";
import { RoguelikeV2Controller } from "../rlv2";
import excel from "@excel/excel";
import { TypedEventEmitter } from "@game/model/events";
import { logger } from "@utils/logger";

export class RoguelikeInventoryManager
  implements PlayerRoguelikeV2.CurrentData.Inventory
{
  trap: null;
  consumable: {};
  exploreTool: {};
  /** 黑流树海：已暂存（留存）的招募券（_candle 变体 id 列表）——"放弃招募券"= 留存券 */
  stashRecruit: string[];
  stashRecruitLimit: number;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._relic = new RoguelikeRelicManager(player, _trigger);
    this._recruit = new RoguelikeRecruitManager(player, _trigger);
    this.trap = null;
    this.consumable = {};
    this.exploreTool = {};
    this.stashRecruit = [];
    this.stashRecruitLimit = 3; // 招募券留存上限（官方初始值）
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
    this._trigger.on("rlv2:get:items", ([items]: [RoguelikeItemBundle[]]) =>
      items.forEach((item) => this.getItem(item)),
    );
  }

  _relic: RoguelikeRelicManager;

  get relic() {
    return this._relic.relics;
  }

  _recruit: RoguelikeRecruitManager;

  get recruit() {
    return this._recruit.tickets;
  }

  init() {
    this.trap = null;
    this.consumable = {};
    this.exploreTool = {};
    this.stashRecruit = [];
    this.stashRecruitLimit = 3;
  }

  create() {
    this.trap = null;
    this.consumable = {};
    this.exploreTool = {};
    this.stashRecruit = [];
    this.stashRecruitLimit = 3;
  }

  getItem(item: RoguelikeItemBundle) {
    const theme = this._player.current.game!.theme;
    // 类型解析：显式 type 优先，其次 excel items 表；两者都缺失（占位/机制空物品）回退 POOL，
    // 不抛错（此前 items[item.id] undefined 直接 TypeError 500）
    const itemDef = item.id ? excel.RoguelikeTopicTable.details[theme].items?.[item.id] : undefined;
    const type = item.type || itemDef?.type || "POOL";
    logger.info("RLV2Inventory", `获得 ${item.id || item.type} * ${item.count}`);
    const funcs: { [key: string]: (item: RoguelikeItemBundle) => void } = {
      NONE: (item: RoguelikeItemBundle) => {},
      HP: (item: RoguelikeItemBundle) => {
        this._player._status.property.hp.current += item.count;
        if (
          this._player._status.property.hp.current >
          this._player._status.property.hp.max
        ) {
          this._player._status.property.hp.current =
            this._player._status.property.hp.max;
        }
      },
      HPMAX: (item: RoguelikeItemBundle) => {
        this._player._status.property.hp.current += item.count;
        this._player._status.property.hp.max += item.count;
      },
      GOLD: (item: RoguelikeItemBundle) =>
        (this._player._status.property.gold += item.count),
      POPULATION: (item: RoguelikeItemBundle) => {
        if (item.count >= 0) {
          this._player._status.property.population.max += item.count;
        } else {
          this._player._status.property.population.cost -= item.count;
        }
      },
      EXP: (item: RoguelikeItemBundle) => {
        this._player._status.property.exp += item.count;
        const map =
          excel.RoguelikeTopicTable.details[theme].detailConst.playerLevelTable;
        // 升级需求经验：map[N].exp 为达到 N 级所需经验（文档指挥等级表：Lv2=10/24/36/40/55/65/70/75/80）
        // 注意：扣经验与升级效果均用「当前等级」map[level]，非 level+1（原实现 off-by-one 读到下一级）
        while (
          map[this._player._status.property.level + 1] &&
          this._player._status.property.exp >=
            map[this._player._status.property.level + 1].exp
        ) {
          this._player._status.property.level += 1;
          const lv = map[this._player._status.property.level] ?? {};
          this._player._status.property.exp -= lv.exp ?? 0;
          this._trigger.emit("rlv2:levelUp", [
            this._player._status.property.level,
          ]);
          // 等级效果（文档：希望+4/+4… 数量+1）：populationUp→希望上限（客户端侧），
          // squadCapacityUp→携带干员数量，maxHpUp→生命上限（rogue_2..5 有，其余缺省 0）
          this._player._status.property.population.max +=
            lv.populationUp ?? 0;
          this._player._status.property.capacity += lv.squadCapacityUp ?? 0;
          const maxHpUp = lv.maxHpUp ?? 0;
          this._player._status.property.hp.max += maxHpUp;
          this._player._status.property.hp.current += maxHpUp;
        }
      },
      SQUAD_CAPACITY: (item: RoguelikeItemBundle) =>
        (this._player._status.property.capacity += item.count),
      RECRUIT_TICKET: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:recruit:gain", [item.id, "battle", 0]);
        const ticket = Object.values(this.recruit).slice(-1)[0].index;
        this._trigger.emit("rlv2:recruit:active", [ticket]);
        this._trigger.emit("rlv2:event:create", [
          "RECRUIT",
          {
            ticket: ticket,
          },
        ]);
      },
      UPGRADE_TICKET: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:recruit:gain", [item.id, "battle", 0]);
        const ticket = Object.values(this.recruit).slice(-1)[0].index;
        this._trigger.emit("rlv2:recruit:active", [ticket]);
        this._trigger.emit("rlv2:event:create", [
          "RECRUIT",
          {
            ticket: ticket,
          },
        ]);
      },
      RELIC: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:relic:gain", [item]);
      },
      BP_POINT: (item: RoguelikeItemBundle) => {
        const theme = this._player.current.game!.theme;
        this._player.outer[theme].bp.point += item.count;
        const maxNum =
          excel.RoguelikeTopicTable.details[theme].milestones.at(-1)!.tokenNum;
        if (this._player.outer[theme].bp.point > maxNum) {
          this._player.outer[theme].bp.point = maxNum;
        }
      },
      GROW_POINT: (item: RoguelikeItemBundle) => {
        const theme = this._player.current.game!.theme;
      },
      BAND: (item: RoguelikeItemBundle) => {},
      ACTIVE_TOOL: (item: RoguelikeItemBundle) => {},
      CAPSULE: (item: RoguelikeItemBundle) => {},
      POOL: (item: RoguelikeItemBundle) => {
        const ro = this._player._pool.get(
          item.id,
          item.id.includes("fragment"),
        );
        //this._trigger.emit("rlv2:get:items", ro.id);
        //this._trigger.emit("rlv2:pool:gain", item.id)
      },
      RL_BP: (item: RoguelikeItemBundle) => {},
      RL_GP: (item: RoguelikeItemBundle) => {},
      KEY_POINT: (item: RoguelikeItemBundle) => {},
      SAN_POINT: (item: RoguelikeItemBundle) => {},
      DICE_POINT: (item: RoguelikeItemBundle) => {},
      DICE_TYPE: (item: RoguelikeItemBundle) => {},
      SHIELD: (item: RoguelikeItemBundle) =>
        (this._player._status.property.shield += item.count),
      LOCKED_TREASURE: (item: RoguelikeItemBundle) => {},
      CUSTOM_TICKET: (item: RoguelikeItemBundle) => {},
      TOTEM: (item: RoguelikeItemBundle) => {},
      TOTEM_EFFECT: (item: RoguelikeItemBundle) => {},
      FEATURE: (item: RoguelikeItemBundle) => {},
      VISION: (item: RoguelikeItemBundle) => {},
      CHAOS: (item: RoguelikeItemBundle) => {},
      CHAOS_PURIFY: (item: RoguelikeItemBundle) => {},
      CHAOS_LEVEL: (item: RoguelikeItemBundle) => {},
      // rogue_6 废品（SCRAP 型）：转入 SCRAP 模块库存（载具/零件）
      SCRAP: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:scrap:gain", [item.id]);
      },
      // rogue_6 传承（LEGACY 型）：下次探索开局加成（本局无持续效果）
      LEGACY: (item: RoguelikeItemBundle) => {},
      // rogue_6 流窜“居民”节点标记（NODE_BUOY 型）：地图层节点机制，无库存表现
      NODE_BUOY: (item: RoguelikeItemBundle) => {},
      // rogue_6 行动力（SPECIAL_ZONE_AP 型）：机制物品，消耗于地图移动
      SPECIAL_ZONE_AP: (item: RoguelikeItemBundle) => {},
      // rogue_6 存券数量（STASH_RECRUIT_LIMIT 型）：机制数值，无库存表现
      STASH_RECRUIT_LIMIT: (item: RoguelikeItemBundle) => {},
      // rogue_6 干员（CHARACTER 型）：佣兵招募固定干员（如 Sharp/Stormeye/Pith）
      CHARACTER: (item: RoguelikeItemBundle) => {
        if (item.id.startsWith("char_")) {
          void this._trigger.emit("rlv2:recruit:initial_char", [item.id]);
        }
      },
      EXPLORE_TOOL: (item: RoguelikeItemBundle) => {},
      FRAGMENT: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:fragment:gain", [item.id]);
      },
      MAX_WEIGHT: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:fragment:max_weight:add", [item.count]);
      },
      DISASTER: (item: RoguelikeItemBundle) => {},
      DISASTER_TYPE: (item: RoguelikeItemBundle) => {},
      ABSTRACT_DISASTER: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:disaster:abstract", []);
      },
    };
    funcs[type](item);
  }

  toJSON(): PlayerRoguelikeV2.CurrentData.Inventory {
    return {
      relic: this.relic,
      recruit: this.recruit,
      trap: this.trap,
      consumable: this.consumable,
      exploreTool: this.exploreTool,
      stashRecruit: this.stashRecruit,
      stashRecruitLimit: this.stashRecruitLimit,
    } as any;
  }
}
