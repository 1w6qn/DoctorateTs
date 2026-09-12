import { PlayerRoguelikeV2, RoguelikeItemBundle } from "./rlv2";
import { RoguelikeRelicManager } from "./relic";
import { RoguelikeRecruitManager } from "./recruit";
import { RoguelikeV2Manager } from "./logic";
import excel from "@excel/excel";
import { TypedEventEmitter } from "../../kernel/events/runtime";
import { logger } from "@utils/logger";
import { now } from "@utils/time";

/** 探索工具条目（官方线格式含 index/count；生成的 ExploreTool 仅声明 id/ts，故此处显式声明） */
export interface ExploreToolEntry {
  /** 实例键（e_N） */
  index: string;
  /** 工具 id（rogue_3_explore_tool_N 等） */
  id: string;
  /** 数量 */
  count: number;
  /** 获取时间 */
  ts: number;
}

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

  /**
   * 探索工具库存的可写视图（结构 { index, id, count, ts }）
   *
   * 类字段按接口声明为 `{}`（见 implements），此处收敛为具体条目类型，
   * 免去调用点的类型转换。
   * @returns 工具条目字典（原地可写）
   */
  exploreTools(): Record<string, ExploreToolEntry> {
    return this.exploreTool as Record<string, ExploreToolEntry>;
  }

  /**
   * 探索工具 id 列表（战斗增益汇总 / 结算 record 用）
   * @returns 工具 id 数组（保持索引顺序）
   */
  exploreToolIds(): string[] {
    return Object.values(this.exploreTools())
      .map((tool) => tool.id)
      .filter((id): id is string => typeof id === "string" && id.length > 0);
  }

  /**
   * 陷阱 id（本局是否布置了陷阱；无陷阱返回 null）
   * @returns 陷阱 id 或 null
   */
  trapId(): string | null {
    const trap = this.trap as { id?: string } | null;
    return trap?.id ?? null;
  }

  /**
   * 下一个探索工具实例键（e_N，官方 getNextExploreToolIndex 同构）
   *
   * @returns 未被占用的 e_N 键
   */
  nextExploreToolIndex(): string {
    const used = new Set<number>();
    for (const key of Object.keys(this.exploreTools())) {
      const n = parseInt(key.slice(2), 10);
      if (Number.isFinite(n)) used.add(n);
    }
    let i = 0;
    while (used.has(i)) i += 1;
    return `e_${i}`;
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
        // 勋章（2026-09-09）：源流样本累计 → 源流堆栈等级（Rlv2BpLevel
        // 「源流堆栈中解锁至 N 级」，按 milestones 门槛换算；载荷为当前等级，模板取 max/覆盖）
        await this._player.emitOuterProgressionMedals(theme);
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
      EXPLORE_TOOL: (item: RoguelikeItemBundle) => {
        // rogue_3 初始探索工具（祭坛式雷达等）：入 inventory.exploreTool，键为 e_N
        // （对齐 ODPY _rlv2.getNextExploreToolIndex 与官服结构 {index,id,count,ts}）。
        // 原实现为空操作 → 工具既不出现在库存（客户端"探索工具"栏空白），结算 record 的
        // activeToolList/exploreToolList 也恒为空。工具本身的战斗内携带效果由客户端按库存渲染，
        // 其 relics 登记 buff（若有）由 RoguelikeBuffManager.getBuffs 的 exploreTool 分支计入。
        const index = this.nextExploreToolIndex();
        this.exploreTools()[index] = {
          index,
          id: item.id,
          count: item.count ?? 1,
          ts: now(),
        };
      },
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
    };
  }
}
