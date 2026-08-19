import { PlayerRoguelikeV2 } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import excel from "@excel/excel";
import { RoguelikeFragmentManager } from "./modules/fragment";
import { RoguelikeDisasterManager } from "./modules/disaster";
import { RoguelikeNodeUpgradeManager } from "./modules/node_upgrade";
import { RoguelikeTotemManager } from "./modules/totem";
import { RoguelikeGridZoneManager } from "./modules/grid_zone";
import { RoguelikeWeatherManager } from "./modules/weather";
import { RoguelikeScrapManager } from "./modules/scrap";
import { RoguelikeDiceManager, RoguelikeSanManager } from "./modules/dice";
import { RoguelikeCopperManager } from "./modules/copper";
import {
  RoguelikeChaosManager,
  RoguelikeVisionManager,
} from "./modules/chaos";
import {
  RoguelikeSkyManager,
  RoguelikeWrathManager,
} from "./modules/wrath_sky";
import { toCamelCase } from "@utils/string";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeModuleManager {
  _modules: { [key: string]: any };
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._modules = {};
    this._trigger = _trigger;
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
  }

  init() {
    this._modules = {};
  }

  /** 主题模块管理器工厂（create/continue 共用） */
  private moduleHandler(): { [key: string]: () => any } {
    return {
      FRAGMENT: () => new RoguelikeFragmentManager(this._player, this._trigger),
      DISASTER: () => new RoguelikeDisasterManager(this._player, this._trigger),
      NODE_UPGRADE: () =>
        new RoguelikeNodeUpgradeManager(this._player, this._trigger),
      TOTEM: () => new RoguelikeTotemManager(this._player, this._trigger),
      GRID_ZONE: () =>
        new RoguelikeGridZoneManager(this._player, this._trigger),
      WEATHER: () => new RoguelikeWeatherManager(this._player, this._trigger),
      SCRAP: () => new RoguelikeScrapManager(this._player, this._trigger),
      SANCHECK: () => new RoguelikeSanManager(this._player, this._trigger),
      DICE: () => new RoguelikeDiceManager(this._player, this._trigger),
      COPPER: () => new RoguelikeCopperManager(this._player, this._trigger),
      CHAOS: () => new RoguelikeChaosManager(this._player, this._trigger),
      VISION: () => new RoguelikeVisionManager(this._player, this._trigger),
      WRATH: () => new RoguelikeWrathManager(this._player, this._trigger),
      SKY: () => new RoguelikeSkyManager(this._player, this._trigger),
    };
  }

  async create() {
    const theme = this._player.current.game!.theme;
    // 新对局先清空旧主题残留管理器（giveUpGame 已不触发 rlv2:init 清空）
    this._modules = {};
    const moduleHandler = this.moduleHandler();

    const moduleTypes = excel.RoguelikeTopicTable.modules[theme]?.moduleTypes || [];
    // 创建管理器；构造期 rlv2:init（未 await）可能在 create 期间滞后触发清空 → 前后各确保一次
    const ensureManagers = () => {
      for (const moduleName of moduleTypes) {
        if (moduleName in moduleHandler && !this._modules[moduleName]) {
          this._modules[moduleName] = moduleHandler[moduleName]();
        }
      }
    };
    ensureManagers();
    // 先统一重置（rlv2:module:init），再初始化各模块开局状态
    await this._trigger.emit("rlv2:module:init", []);
    ensureManagers();
    // rogue_2 开局骰子类型、rogue_5 开局抽 3 枚铜币
    if (this._modules["DICE"]) {
      this._modules["DICE"].id = Object.keys(
        (excel.RoguelikeTopicTable.modules[theme] as any)?.dice?.dice || {},
      )[0] || "";
    }
    if (this._modules["COPPER"]) {
      this._modules["COPPER"].drawInitial();
    }
  }

  /**
   * 重登"继续探索"恢复：按主题创建模块管理器并主动恢复各模块状态
   * （原实现为空实现——管理器从未创建，gridZone/scrap 等 getter 返回 undefined，
   * 续局请求直接崩溃）。不依赖 Emittery 微任务时序（新注册监听在本次 emit
   * 快照之外不会触发），创建后直接调用子模块的 continue()。
   */
  continue(): void {
    const theme = this._player.current.game?.theme;
    if (!theme) return;
    const moduleHandler = this.moduleHandler();
    const moduleTypes =
      excel.RoguelikeTopicTable.modules[theme]?.moduleTypes || [];
    for (const moduleName of moduleTypes) {
      if (moduleName in moduleHandler && !this._modules[moduleName]) {
        this._modules[moduleName] = moduleHandler[moduleName]();
      }
    }
    // 主动恢复各模块存档状态（grid_zone 恢复 zones/stepRemain、scrap 恢复 inventory
    // 等；存档无该模块数据时子模块 continue 内部做空值兜底）
    for (const m of Object.values(this._modules)) {
      if (typeof m?.continue === "function") m.continue();
    }
  }

  /** 图腾管理器访问器（rogue_3 TOTEM 模块） */
  get totem(): any {
    return this._modules["TOTEM"];
  }

  /** 网格区域管理器访问器（rogue_6 GRID_ZONE） */
  get gridZone(): any {
    return this._modules["GRID_ZONE"];
  }

  /** 废品管理器访问器（rogue_6 SCRAP） */
  get scrap(): any {
    return this._modules["SCRAP"];
  }

  /** 天气管理器访问器（rogue_6 WEATHER） */
  get weather(): any {
    return this._modules["WEATHER"];
  }

  /** 骰子管理器访问器（rogue_2 DICE） */
  get dice(): any {
    return this._modules["DICE"];
  }

  /** 铜币管理器访问器（rogue_5 COPPER） */
  get copper(): any {
    return this._modules["COPPER"];
  }

  /** 坍缩管理器访问器（rogue_3 CHAOS） */
  get chaos(): any {
    return this._modules["CHAOS"];
  }

  /** 视域管理器访问器（rogue_3 VISION） */
  get vision(): any {
    return this._modules["VISION"];
  }

  /** 怒气管理器访问器（rogue_5 WRATH） */
  get wrath(): any {
    return this._modules["WRATH"];
  }

  /** 天空管理器访问器（rogue_5 SKY） */
  get sky(): any {
    return this._modules["SKY"];
  }

  toJSON(): PlayerRoguelikeV2.CurrentData.Module {
    const result: PlayerRoguelikeV2.CurrentData.Module = {};
    Object.entries(this._modules).forEach(([k, v]) => {
      // SANCHECK 模块状态字段为 san（非 sanCheck）
      const key = k === "SANCHECK" ? "san" : toCamelCase(k);
      result[key] = v.toJSON();
    });

    const theme = this._player.current.game?.theme;
    if (!theme) return result;

    const roNum = parseInt(theme.split("_")[1]);
    // 主题默认模块状态（无管理器主题/缺失模块的兜底）
    if (roNum === 2) {
      if (!result.san) result.san = { sanity: 100 };
      if (!result.dice) result.dice = { id: "", count: 1 };
    } else if (roNum === 3) {
      if (!result.totem) {
        result.totem = { totemPiece: [], predictTotemId: "rogue_3_totem_B_E2" };
      }
      if (!result.vision) result.vision = { value: 0, isMax: false };
      if (!result.chaos) {
        result.chaos = {
          value: 0,
          level: 0,
          curMaxValue: 4,
          chaosList: [],
          predict: "",
          deltaChaos: {
            dValue: 0,
            preLevel: 0,
            afterLevel: 0,
            dChaos: [],
          },
          lastBattleGain: 0,
        };
      }
    } else if (roNum === 5) {
      if (!result.copper) {
        result.copper = {
          bag: {},
          redrawCost: 2,
          redrawFreeze: 3,
          redrawFreezeCnt: 0,
        };
      }
      if (!result.wrath) result.wrath = { wraths: [], newWrath: -1 };
      if (!result.sky) result.sky = { zones: {} };
    }

    return result;
  }

  applyModuleDelta(delta: { [key: string]: any }, sign: number): void {
    const moduleData = this.toJSON();
    
    const applyDelta = (target: any, source: any, s: number): void => {
      for (const [key, value] of Object.entries(source)) {
        if (typeof value === "object" && value !== null && typeof target[key] === "object") {
          applyDelta(target[key], value, s);
        } else if (typeof target[key] === "number" && typeof value === "number") {
          target[key] += s * value;
        }
      }
    };
    
    applyDelta(moduleData, delta, sign);
  }
}
