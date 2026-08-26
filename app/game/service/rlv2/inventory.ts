import { PlayerRoguelikeV2, RoguelikeItemBundle } from "../../domain/rlv2";
import { RoguelikeRelicManager } from "./relic";
import { RoguelikeRecruitManager } from "./recruit";
import { RoguelikeV2Manager } from "./logic";
import excel from "@excel/excel";
import { TypedEventEmitter } from "@game/service/manager/events";
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
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
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
    this._trigger.on("rlv2:get:items", async ([items]: [RoguelikeItemBundle[]]) => {
      for (const item of items) {
        await this.getItem(item);
      }
    });
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

  async getItem(item: RoguelikeItemBundle) {
    const theme = this._player.current.game!.theme;
    // 类型解析：显式 type 优先，其次 excel items 表；两者都缺失（占位/机制空物品）回退 POOL，
    // 不抛错（此前 items[item.id] undefined 直接 TypeError 500）
    const itemDef = item.id ? excel.RoguelikeTopicTable.details[theme].items?.[item.id] : undefined;
    const type = item.type || itemDef?.type || "POOL";
    logger.info("RLV2Inventory", `获得 ${item.id || item.type} * ${item.count}`);
    const funcs: { [key: string]: (item: RoguelikeItemBundle) => void | Promise<void> } = {
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
      GOLD: (item: RoguelikeItemBundle) => {
        this._player._status.property.gold += item.count;
      },
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
      SQUAD_CAPACITY: (item: RoguelikeItemBundle) => {
        this._player._status.property.capacity += item.count;
      },
      RECRUIT_TICKET: async (item: RoguelikeItemBundle) => {
        // await：gain 先写入 recruit 票，active 打开候选、event:create 生成 RECRUIT 事件，
        // 三者需在响应序列化前完成，否则拿券后无 RECRUIT 事件可招募（"拿到券不能招"）。
        await this._trigger.emit("rlv2:recruit:gain", [item.id, "battle", 0]);
        const ticket = Object.values(this.recruit).slice(-1)[0].index;
        await this._trigger.emit("rlv2:recruit:active", [ticket]);
        // 参数键名与 events.ts RECRUIT 构造一致（tickets）——原传 {ticket} 导致 undefined
        await this._trigger.emit("rlv2:event:create", [
          "RECRUIT",
          {
            tickets: ticket,
          },
        ]);
      },
      UPGRADE_TICKET: async (item: RoguelikeItemBundle) => {
        await this._trigger.emit("rlv2:recruit:gain", [item.id, "battle", 0]);
        const ticket = Object.values(this.recruit).slice(-1)[0].index;
        await this._trigger.emit("rlv2:recruit:active", [ticket]);
        await this._trigger.emit("rlv2:event:create", [
          "RECRUIT",
          {
            tickets: ticket,
          },
        ]);
      },
      RELIC: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:relic:gain", [item]);
      },
      BP_POINT: async (item: RoguelikeItemBundle) => {
        const theme = this._player.current.game!.theme;
        // outer 为 _playerdata.rlv2 引用（update() 后冻结），写入须放入配方
        await this._player.update(async (draft) => {
          const bp = draft.outer[theme].bp;
          bp.point += item.count;
          const maxNum =
            excel.RoguelikeTopicTable.details[theme].milestones.at(-1)!.tokenNum;
          if (bp.point > maxNum) {
            bp.point = maxNum;
          }
        });
      },
      GROW_POINT: (item: RoguelikeItemBundle) => {
        const theme = this._player.current.game!.theme;
      },
      BAND: (item: RoguelikeItemBundle) => {},
      ACTIVE_TOOL: (item: RoguelikeItemBundle) => {},
      CAPSULE: (item: RoguelikeItemBundle) => {},
      POOL: async (item: RoguelikeItemBundle) => {
        // 从池抽 count 件并按其类型发放（修复：原实现抽出即弃——
        // pool_scrap_3/6（开拓者分队）、pool_treasure（珍宝池/startbuff_12 ×3）等池物品无法入库存）
        const n = Math.max(1, item.count || 1);
        for (let i = 0; i < n; i++) {
          const ro = this._player._pool.get(
            item.id,
            item.id.includes("fragment"),
          );
          if (ro?.id) {
            await this.getItem({ id: ro.id, count: 1, sub: 0 });
          }
        }
      },
      RL_BP: (item: RoguelikeItemBundle) => {},
      RL_GP: (item: RoguelikeItemBundle) => {},
      KEY_POINT: (item: RoguelikeItemBundle) => {},
      SAN_POINT: (item: RoguelikeItemBundle) => {},
      DICE_POINT: (item: RoguelikeItemBundle) => {},
      DICE_TYPE: (item: RoguelikeItemBundle) => {},
      SHIELD: (item: RoguelikeItemBundle) => {
        this._player._status.property.shield += item.count;
      },
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
      // rogue_6 行动力（SPECIAL_ZONE_AP 型）：增减当前区域剩余行动力（事件/安全的角落/休息选项等）
      SPECIAL_ZONE_AP: (item: RoguelikeItemBundle) => {
        const gz = this._player._module?.gridZone;
        if (gz && typeof item.count === "number") {
          gz.stepRemain = Math.max(0, (gz.stepRemain || 0) + item.count);
        }
      },
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
        // rogue_6：MAX_WEIGHT = 零件箱容量（多边贸易分队 +2/+4）→ 加 SCRAP 模块上限
        if (theme === "rogue_6") {
          const scrap = this._player._module?.scrap;
          if (scrap && typeof item.count === "number") {
            scrap.setLimit((scrap.limit || 6) + item.count);
          }
          return;
        }
        this._trigger.emit("rlv2:fragment:max_weight:add", [item.count]);
      },
      DISASTER: (item: RoguelikeItemBundle) => {},
      DISASTER_TYPE: (item: RoguelikeItemBundle) => {},
      ABSTRACT_DISASTER: (item: RoguelikeItemBundle) => {
        this._trigger.emit("rlv2:disaster:abstract", []);
      },
    };
    await funcs[type](item);
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
