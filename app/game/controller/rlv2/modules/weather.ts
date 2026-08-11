/**
 * WEATHER 模块（rogue_6 天气）
 *
 * 客户端状态形状（types-playerdata）：weather = {
 *   currentMain, currentSub, eye, effectArea: { [key]: number }, weatherStep
 * }
 * 简化实现：开局随机主天气，随层数推进升级（mainWeatherData 按 level 1/2/3 变体）。
 */
import { RoguelikeV2Controller } from "../../rlv2";
import excel from "@excel/excel";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeWeatherManager {
  currentMain: string;
  currentSub: string;
  eye: string;
  effectArea: { [key: string]: number };
  weatherStep: number;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.currentMain = "";
    this.currentSub = "";
    this.eye = "";
    this.effectArea = {};
    this.weatherStep = 0;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:zone:new", this.onZoneNew.bind(this));
    // 天气步数：每次移动/网格步进推进（天气随步数阶段性变化）
    this._trigger.on("rlv2:move", this.onStep.bind(this));
    this._trigger.on("rlv2:grid:step", this.onStep.bind(this));
  }

  init(): void {
    this.currentMain = "";
    this.currentSub = "";
    this.eye = "";
    this.effectArea = {};
    this.weatherStep = 0;
  }

  continue(): void {
    const w = this._player.current.module?.weather;
    this.currentMain = w?.currentMain || "";
    this.currentSub = w?.currentSub || "";
    this.eye = w?.eye || "";
    this.effectArea = w?.effectArea || {};
    this.weatherStep = w?.weatherStep || 0;
  }

  /** 进入新层：随机选主天气；天气等级随天气步数推进（mainWeatherData 的 level 1/2/3） */
  onZoneNew([zoneId]: [number]): void {
    const theme = this._player.current.game!.theme;
    const mainWeatherData = (
      excel.RoguelikeTopicTable.modules[theme] as any
    )?.weather?.mainWeatherData;
    if (!mainWeatherData) return;
    // 选择天气类型（去掉 _a/_b/_c 等级后缀）
    const types = [
      ...new Set(
        Object.keys(mainWeatherData).map((id) =>
          id.replace(/_[abc]$/, ""),
        ),
      ),
    ];
    if (types.length === 0) return;
    const type = types[Math.floor(Math.random() * types.length)];
    // 等级：层 1-2 → 1（_a），3-4 → 2（_b），5+ → 3（_c）
    const level = Math.min(3, Math.max(1, Math.ceil(zoneId / 2)));
    const suffix = ["", "_a", "_b", "_c"][level];
    this.currentMain = `${type}${suffix}`;
    // 副天气：随机选一个（若有）
    const subWeatherData = (
      excel.RoguelikeTopicTable.modules[theme] as any
    )?.weather?.subWeatherData;
    const subKeys = subWeatherData ? Object.keys(subWeatherData) : [];
    this.currentSub = subKeys.length
      ? subKeys[Math.floor(Math.random() * subKeys.length)]
      : "";
    this.eye = "";
    this.effectArea = {};
    this.weatherStep = 0;
  }

  /** 移动/网格步进：天气步数 +1（官方 weatherStep 追踪天气阶段） */
  onStep(): void {
    this.weatherStep += 1;
  }

  toJSON(): {
    currentMain: string;
    currentSub: string;
    eye: string;
    effectArea: { [key: string]: number };
    weatherStep: number;
  } {
    return {
      currentMain: this.currentMain,
      currentSub: this.currentSub,
      eye: this.eye,
      effectArea: this.effectArea,
      weatherStep: this.weatherStep,
    };
  }
}
