/**
 * SCRAP 模块（rogue_6 废品/载具）
 *
 * 客户端状态形状（types-playerdata）：scrap = {
 *   activeVehicle: { instId, isWalk },   // 当前移动方式（0=步行 / 载具 instId）
 *   inventory: { [instId]: { instId, id, value, useCnt, ts } },
 *   limit,                               // 库存上限
 * }
 * 简化实现：开局持有 1 个随机 MOVE 型废品（载具）；changeVehicle 切换当前载具。
 */
import { RoguelikeV2Controller } from "../../rlv2";
import excel from "@excel/excel";
import { now } from "@utils/time";
import { TypedEventEmitter } from "@game/model/events";
import { isBlackstream } from "../theme-rules";
import type { RoguelikeScrapModuleData } from "@excel/roguelike_topic_table";

export interface ScrapItem {
  instId: string;
  id: string;
  value: number;
  useCnt: number;
  ts: number;
}

export class RoguelikeScrapManager {
  activeVehicle: { instId?: string; isWalk: boolean };
  inventory: { [key: string]: ScrapItem };
  limit: number;
  _index: number;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    // 官服 createGame scrap：activeVehicle 仅 { isWalk: true }（步行无 instId）、
    // 开局 2 个初始废品（s_1/s_2 = G_01，value 2）、零件箱容量 8（抓包确认）
    this.activeVehicle = { isWalk: true };
    this.inventory = {};
    this.limit = 10; // 零件箱基础容量 10（难度 buff 叠加后为 8）
    this._index = 0;
    this.seedInitial();
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:scrap:gain", this.gain.bind(this));
  }

  init(): void {
    this.activeVehicle = { isWalk: true };
    this.inventory = {};
    this.limit = 10; // 零件箱基础容量 10（难度 buff 叠加后为 8）
    this._index = 0;
    this.seedInitial();
  }

  /** 官方开局废品：s_1/s_2 = rogue_6_scrap_G_01（value 2）——初始零件箱自带 2 件 */
  private seedInitial(): void {
    const theme = this._player.current.game?.theme || "";
    if (!isBlackstream(theme)) return;
    // 开局废品 id 取官方 moduleConsts.identifyScrapId（实测 = rogue_6_scrap_G_01），
    // 估价取该废品的官方 sellPrice（实测 2），与抓包一致
    const id = this.scrapModule()?.moduleConsts?.identifyScrapId ?? "rogue_6_scrap_G_01";
    const tpl = { id, value: this.sellPriceOf(id, 2), useCnt: 0, ts: now() };
    this.inventory["s_1"] = { instId: "s_1", ...tpl };
    this.inventory["s_2"] = { instId: "s_2", ...tpl };
    this._index = 3; // 下个废品 s_3（不覆盖 s_1/s_2）
  }

  /**
   * 当前主题的 SCRAP 模块数据（官方 modules[theme].scrap）。
   * @returns 模块数据；主题无该模块时为 undefined
   */
  private scrapModule(): RoguelikeScrapModuleData | undefined {
    const theme = this._player.current.game?.theme || "";
    return excel.RoguelikeTopicTable.modules[theme]?.scrap ?? undefined;
  }

  /**
   * 废品官方估价（sellPrice）。
   * 官方按类型分表：goodsScrapData（自然物）/ moveScrapData（加工品/载具）/
   * passiveScrapData（概念体）。估价决定行商售价与"消耗最低估价加工品"的排序。
   * @param id 废品 id
   * @param fallback 数据缺失时的兜底估价
   * @returns 估价
   */
  private sellPriceOf(id: string, fallback = 1): number {
    const m = this.scrapModule();
    const price =
      m?.goodsScrapData?.[id]?.sellPrice ??
      m?.moveScrapData?.[id]?.sellPrice ??
      m?.passiveScrapData?.[id]?.sellPrice;
    return typeof price === "number" ? price : fallback;
  }

  continue(): void {
    const s = this._player.current.module?.scrap as any;
    this.activeVehicle = s?.activeVehicle || { isWalk: true };
    this.inventory = s?.inventory || {};
    this.limit = s?.limit ?? 10;
    // 修复：原实现 _index = 键数——seedInitial 后 s_1/s_2 存在（键数 2），
    // 续局 _index=2 → 下个废品写成 s_2 覆盖已播种项；改为 最大 instId 后缀 + 1
    let maxN = 0;
    for (const id of Object.keys(this.inventory)) {
      const m = /_(\d+)$/.exec(id);
      if (m) maxN = Math.max(maxN, parseInt(m[1], 10));
    }
    this._index = maxN + 1;
  }

  /** 获得废品（战斗/事件奖励） */
  gain([id]: [string]): void {
    const type = this.scrapModule()?.scrapItemToType?.[id];
    if (!type) return;
    if (Object.keys(this.inventory).length >= this.limit) return;
    const instId = `s_${this._index}`;
    this.inventory[instId] = {
      instId,
      id,
      // 估价取官方 sellPrice（原实现恒为 1，导致行商售价与"扣最低估价加工品"排序失真）
      value: this.sellPriceOf(id),
      useCnt: 0,
      ts: now(),
    };
    this._index += 1;
    // 散件获得推送（rlv2GotRandScrap，触发类 RoguelikeScrapGainTrigger）：携带获得的散件 id
    this._player.pushMessage("rlv2GotRandScrap", { idList: [id] });
    // MOVE 型废品自动装备为载具（首个）
    if (type === "MOVE" && this.activeVehicle.isWalk) {
      this.activeVehicle = {
        instId,
        isWalk: false,
      };
    }
  }

  /** 切换当前载具（scrap/changeVehicle）→ rlv2VehicleChange 推送（触发类 RoguelikeVehicleChangeTrigger） */
  changeVehicle(instId: string): void {
    if (instId === "") {
      if (this.activeVehicle?.isWalk) return; // 已是步行，无变化不推送
      this.activeVehicle = { isWalk: true };
      this._player.pushMessage("rlv2VehicleChange", {});
      return;
    }
    const item = this.inventory[instId];
    if (!item || this.activeVehicle?.instId === instId) return;
    this.activeVehicle = { instId, isWalk: false };
    this._player.pushMessage("rlv2VehicleChange", {});
  }

  /**
   * 调整零件箱容量上限（统一入口：MAX_WEIGHT / scrap_limit_add 增减均由外部改 scrap.limit，
   * 这里集中触发容量变化推送，避免各调用点重复逻辑）。
   * 官方触发类：RoguelikeFragmentBagWeightUpgradeTrigger（rlv2LevelUpMaxWeight {count}，扩容）、
   * RoguelikeFragmentBagWeightWorseTrigger（rlv2WeightWorse {}，缩减）。
   * @param next 调整后的容量上限
   */
  setLimit(next: number): void {
    const prev = this.limit;
    const n = Math.max(0, next);
    if (n === prev) return;
    this.limit = n;
    if (n < prev) {
      // 容量缩减 → WeightWorse（零件箱变小提示）
      this._player.pushMessage("rlv2WeightWorse", {});
    } else {
      // 容量扩容 → LevelUpMaxWeight（count = 本次新增容量）
      this._player.pushMessage("rlv2LevelUpMaxWeight", { count: n - prev });
    }
  }

  toJSON(): {
    activeVehicle: { instId?: string; isWalk: boolean };
    inventory: { [key: string]: ScrapItem };
    limit: number;
  } {
    return {
      activeVehicle: this.activeVehicle,
      inventory: this.inventory,
      limit: this.limit,
    };
  }
}
