import { PlayerRoguelikeV2 } from "./rlv2";
import { RoguelikeV2Manager } from "./logic";
import type { RoguelikeChoiceEffectMap } from "./logic";
import excel from "@excel/excel";
import {
  composeRlv2ThemeModules,
  type Rlv2ModuleFactoryMap,
  type Rlv2ThemeModule,
  type RoguelikeFragmentManager,
  type RoguelikeTotemManager,
  type RoguelikeGridZoneManager,
  type RoguelikeScrapManager,
  type RoguelikeWeatherManager,
  type RoguelikeDiceManager,
  type RoguelikeSanManager,
  type RoguelikeCopperManager,
  type RoguelikeChaosManager,
  type RoguelikeVisionManager,
  type RoguelikeSkyManager,
  type RoguelikeWrathManager,
} from "./rlv2-module-composition";
import { toCamelCase } from "@utils/string";
import { TypedEventEmitter } from "../../kernel/events/runtime";

export class RoguelikeModuleManager {
  /**
   * 主题模块注册表（moduleType 键 → 管理器；键域见 rlv2-module-composition 分发表）
   *
   * 异构注册表：值类型为 14 个管理器的联合，具体访问器（totem/gridZone/…）按各自类型
   * 收敛（键与类型的对应关系由分发表保证）。
   */
  _modules: { [key: string]: Rlv2ThemeModule };
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
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

  /** 主题模块管理器工厂（create/continue 共用），分发表见 rlv2-module-composition */
  private moduleHandler(): Rlv2ModuleFactoryMap {
    return composeRlv2ThemeModules(this._player, this._trigger);
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
    const diceMgr = this.dice;
    if (diceMgr) {
      diceMgr.id =
        Object.keys(excel.RoguelikeTopicTable.modules[theme]?.dice?.dice || {})[0] ||
        "";
    }
    const copperMgr = this.copper;
    if (copperMgr) {
      copperMgr.drawInitial();
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
    // 各管理器的 continue 为可选成员（如 DISASTER 未实现），故按结构化视图遍历
    const modules: { continue?: () => void; toJSON: Rlv2ThemeModule["toJSON"] }[] =
      Object.values(this._modules);
    for (const m of modules) {
      if (typeof m?.continue === "function") m.continue();
    }
  }

  /** 图腾管理器访问器（rogue_3 TOTEM 模块） */
  get totem(): RoguelikeTotemManager {
    return this._modules["TOTEM"] as RoguelikeTotemManager;
  }

  /** 网格区域管理器访问器（rogue_6 GRID_ZONE） */
  get gridZone(): RoguelikeGridZoneManager {
    return this._modules["GRID_ZONE"] as RoguelikeGridZoneManager;
  }

  /** 碎片管理器访问器（rogue_3/5 FRAGMENT 模块） */
  get fragment(): RoguelikeFragmentManager {
    return this._modules["FRAGMENT"] as RoguelikeFragmentManager;
  }

  /**
   * 主题模块存在性查询（battle 等子模块经此访问，不直接读 _modules）
   * @param moduleId - 模块名（如 "SANCHECK" / "DICE"）
   */
  hasModule(moduleId: string): boolean {
    return moduleId in this._modules;
  }

  /** 废品管理器访问器（rogue_6 SCRAP） */
  get scrap(): RoguelikeScrapManager {
    return this._modules["SCRAP"] as RoguelikeScrapManager;
  }

  /** 天气管理器访问器（rogue_6 WEATHER） */
  get weather(): RoguelikeWeatherManager {
    return this._modules["WEATHER"] as RoguelikeWeatherManager;
  }

  /** 灯火（理智）管理器访问器（rogue_2 SANCHECK，状态字段名为 san） */
  get san(): RoguelikeSanManager {
    return this._modules["SANCHECK"] as RoguelikeSanManager;
  }

  /** 骰子管理器访问器（rogue_2 DICE） */
  get dice(): RoguelikeDiceManager {
    return this._modules["DICE"] as RoguelikeDiceManager;
  }

  /** 铜币管理器访问器（rogue_5 COPPER） */
  get copper(): RoguelikeCopperManager {
    return this._modules["COPPER"] as RoguelikeCopperManager;
  }

  /** 坍缩管理器访问器（rogue_3 CHAOS） */
  get chaos(): RoguelikeChaosManager {
    return this._modules["CHAOS"] as RoguelikeChaosManager;
  }

  /** 视域管理器访问器（rogue_3 VISION） */
  get vision(): RoguelikeVisionManager {
    return this._modules["VISION"] as RoguelikeVisionManager;
  }

  /** 怒气管理器访问器（rogue_5 WRATH） */
  get wrath(): RoguelikeWrathManager {
    return this._modules["WRATH"] as RoguelikeWrathManager;
  }

  /** 天空管理器访问器（rogue_5 SKY） */
  get sky(): RoguelikeSkyManager {
    return this._modules["SKY"] as RoguelikeSkyManager;
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

  /**
   * 模块数值字段累加（事件选项 m_get/m_lose 的数值字典，递归到嵌套数值字段）
   *
   * CurrentData.Module 为开放模块字典（各主题模块键不同，含未建模键），按运行时形状
   * 递归：目标当前值为对象 → 继续下钻；两侧均为 number → 累加。
   * @param delta - 模块数值字典（{dice:{count:1}} / {san:{sanity:15}}）
   * @param sign - 方向（+1 获得 / -1 失去）
   */
  applyModuleDelta(delta: RoguelikeChoiceEffectMap, sign: number): void {
    const moduleData = this.toJSON();

    const applyDelta = (
      target: PlayerRoguelikeV2.CurrentData.Module,
      source: RoguelikeChoiceEffectMap,
      s: number,
    ): void => {
      for (const [key, value] of Object.entries(source)) {
        const current = target[key];
        if (typeof value === "object" && value !== null && typeof current === "object") {
          // 模块状态为开放字典（各主题键不同）——就地收窄回开放字典类型继续下钻
          applyDelta(current as PlayerRoguelikeV2.CurrentData.Module, value, s);
        } else if (typeof current === "number" && typeof value === "number") {
          target[key] = current + s * value;
        }
      }
    };

    applyDelta(moduleData, delta, sign);
  }
}
