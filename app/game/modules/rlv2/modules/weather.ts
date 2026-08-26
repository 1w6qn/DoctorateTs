/**
 * WEATHER 模块（rogue_6 天气）
 *
 * 客户端状态形状（types-playerdata）：weather = {
 *   currentMain, currentSub, eye, effectArea: { [key]: number }, weatherStep
 * }
 * 简化实现：按官服抓包对齐，进层后 weather 保持为空（不下发随机主/副天气）。
 */
import { RoguelikeV2Controller } from "../../rlv2";
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

  /** 进层（rlv2:zone:new）处理。
   * 按官服抓包对齐：进层后 weather 保持为空（currentMain/currentSub=""、weatherStep=0），
   * 不再随机分配主/副天气——官服黑流树海进层（finishEvent）响应 weather 全空。
   * 保留方法骨架以维持事件订阅，但重置本轮未用的步进计数器。 */
  onZoneNew([_zoneId]: [number]): void {
    // 上一轮生效的天气在进入新层时视为清除（客户端清除对应天气 UI）。
    // 移除随机天气后 currentMain 恒空，此判断通常不触发；保留以兼容外部显式赋值。
    if (this.currentMain) {
      this._player.pushMessage("rlv2WeatherClear", {
        mainId: this.currentMain,
        subId: this.currentSub,
      });
    }
    this.currentMain = "";
    this.currentSub = "";
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
