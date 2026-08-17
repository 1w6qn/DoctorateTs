import excel from "@excel/excel";
import { RoguelikeItemBundle } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import { randomChoice } from "@utils/random";
import { TypedEventEmitter } from "@game/model/events";
import { logger } from "@utils/logger";

export class RoguelikePoolManager {
  _pools: { [id: string]: string[] };

  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._pools = {};
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:relic:recycle", this.recycle.bind(this));
    this._trigger.on("rlv2:relic:put", this.put.bind(this));
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
  }

  recycle([id]: [string]) {
    logger.debug("RLV2Pool", "recycle", id);
  }

  put([id]: [string]) {
    logger.debug("RLV2Pool", "put", id);
  }

  init() {
    this._pools = {};
  }

  async create() {
    const theme = this._player.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme];
    this._pools["pool_sacrifice_n"] = [];
    this._pools["pool_sacrifice_r"] = [];
    // 收藏品池：按稀有度分类（官方 items.rarity：NORMAL/RARE/SUPER_RARE/BORN）
    this._pools["pool_relic_normal"] = [];
    this._pools["pool_relic_rare"] = [];
    this._pools["pool_relic_super_rare"] = [];
    this._pools["pool_relic_all"] = [];
    // 加工品池（rogue_6 开拓者分队 zone_into_reward pool_scrap_3/6）：
    // GOODS 型废品（零件箱加工品）；pool_scrap_3=珍贵（简化：随机 3 件中的随机 1 件），pool_scrap_6=普通（全部）
    const scrapMod = (excel.RoguelikeTopicTable.modules[theme] as any) || {};
    const typeMap = scrapMod?.scrap ?? scrapMod?.sCRAP ?? {};
    const goodsIds = Object.keys(typeMap?.scrapItemToType || {}).filter(
      (id) => typeMap.scrapItemToType[id] === "GOODS",
    );
    this._pools["pool_scrap_3"] = [...goodsIds];
    this._pools["pool_scrap_6"] = [...goodsIds];
    const fragment = excel.RoguelikeTopicTable.modules[theme].fragment;
    if (fragment) {
      this._pools["pool_fragment_3"] = [];
      this._pools["pool_fragment_4"] = [];
      this._pools["pool_fragment_5"] = [];
      Object.values(fragment.fragmentData).forEach((data) => {
        if (data.type == "INSPIRATION") {
          this._pools["pool_fragment_3"].push(data.id);
        } else if (data.type == "WISH") {
          this._pools["pool_fragment_4"].push(data.id);
        } else if (data.type == "IDEA") {
          this._pools["pool_fragment_5"].push(data.id);
        }
      });
    }
    Object.values(detail.items)
      .filter((data) => data.canSacrifice)
      .forEach((data) => {
        if (data.value == 8) {
          this._pools["pool_sacrifice_n"].push(data.id);
        } else if (data.value == 12) {
          this._pools["pool_sacrifice_r"].push(data.id);
        }
      });
    // 收藏品池填充（type === RELIC 的物品，含诅咒/遗物等）
    for (const [id, item] of Object.entries(detail.items)) {
      if ((item as any).type !== "RELIC") continue;
      this._pools["pool_relic_all"].push(id);
      const rarity = (item as any).rarity;
      if (rarity === "NORMAL") {
        this._pools["pool_relic_normal"].push(id);
      } else if (rarity === "RARE") {
        this._pools["pool_relic_rare"].push(id);
      } else if (rarity === "SUPER_RARE") {
        this._pools["pool_relic_super_rare"].push(id);
      }
    }
  }

  /**
   * 从收藏品池随机抽一个未拥有的收藏品（不放回）
   * @param poolId 池 id（pool_relic_all / pool_relic_normal / ...）
   * @param hasRelic 已拥有的收藏品 id 列表（过滤避免重复）
   * @returns 收藏品 id；池空或全部已拥有返回空串
   */
  getRelic(poolId: string, hasRelic: string[] = []): string {
    const pool = this._pools[poolId] || [];
    const avail = pool.filter((id) => !hasRelic.includes(id));
    if (avail.length === 0) return "";
    const picked = avail[Math.floor(Math.random() * avail.length)];
    // 不放回：从池中移除（同一探索内不重复出同池藏品）
    this._pools[poolId].splice(this._pools[poolId].indexOf(picked), 1);
    return picked;
  }

  get(id: string, putback = false): RoguelikeItemBundle {
    const pool = this._pools[id] || [];
    const res = pool.length > 0 ? randomChoice(pool) : "";
    if (!putback && pool.length > 0) {
      pool.splice(pool.indexOf(res), 1);
    }
    return { id: res, count: 1 };
  }
}
