import { PlayerRoguelikeV2 } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import excel from "@excel/excel";
import { RoguelikeFragmentManager } from "./modules/fragment";
import { RoguelikeDisasterManager } from "./modules/disaster";
import { RoguelikeNodeUpgradeManager } from "./modules/node_upgrade";
import { RoguelikeTotemManager } from "./modules/totem";
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

  create() {
    const theme = this._player.current.game!.theme;
    const moduleHandler: { [key: string]: () => any } = {
      FRAGMENT: () => new RoguelikeFragmentManager(this._player, this._trigger),
      DISASTER: () => new RoguelikeDisasterManager(this._player, this._trigger),
      NODE_UPGRADE: () =>
        new RoguelikeNodeUpgradeManager(this._player, this._trigger),
      TOTEM: () => new RoguelikeTotemManager(this._player, this._trigger),
    };

    const moduleTypes = excel.RoguelikeTopicTable.modules[theme]?.moduleTypes || [];
    for (const moduleName of moduleTypes) {
      if (moduleName in moduleHandler) {
        this._modules[moduleName] = moduleHandler[moduleName]();
      }
    }

    this._trigger.emit("rlv2:module:init", []);
  }

  continue() {}

  /** 图腾管理器访问器（rogue_3 TOTEM 模块） */
  get totem(): any {
    return this._modules["TOTEM"];
  }

  toJSON(): PlayerRoguelikeV2.CurrentData.Module {
    const result: PlayerRoguelikeV2.CurrentData.Module = {};
    Object.entries(this._modules).forEach(([k, v]) => {
      result[toCamelCase(k)] = v.toJSON();
    });

    const theme = this._player.current.game?.theme;
    if (!theme) return result;

    const roNum = parseInt(theme.split("_")[1]);
    if (roNum === 2) {
      result.san = { sanity: 100 };
      result.dice = { id: "", count: 1 };
    } else if (roNum === 3) {
      if (!result.totem) {
        result.totem = { totemPiece: [], predictTotemId: "rogue_3_totem_B_E2" };
      }
      result.vision = { value: 3, isMax: false };
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
    } else if (roNum === 5) {
      result.copper = null;
      result.wrath = { wraths: [], newWrath: -1 };
      result.sky = { zones: {} };
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
