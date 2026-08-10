/**
 * GRID_ZONE 模块（rogue_6 网格区域——自由探索）
 *
 * 客户端状态形状（types-playerdata）：gridZone = {
 *   zones: { [zoneId]: { nodes: { [nodeId]: {
 *     content: { savage: { stageId }, shop: { goods[] } }, state, show } } } },
 *   stepRemain, needConfirmStepZero
 * }
 *
 * 简化实现：每层生成简单网格（战斗/商店/事件混合），stepRemain 为剩余行动力，
 * 移动/空步消耗步数，耗尽回到下一层。
 */
import { PlayerRoguelikeV2 } from "@game/model/rlv2";
import { RoguelikeV2Controller } from "../../rlv2";
import excel from "@excel/excel";
import { TypedEventEmitter } from "@game/model/events";

interface GridNode {
  content: {
    savage?: { stageId: string };
    shop?: { goods: string[] };
  };
  state: number; // 0 未访问 / 1 可访问 / 2 已访问
  show: number;
}

interface GridZone {
  nodes: { [key: string]: GridNode };
}

export class RoguelikeGridZoneManager {
  zones: { [key: string]: GridZone };
  stepRemain: number;
  needConfirmStepZero: number;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.zones = {};
    this.stepRemain = 20;
    this.needConfirmStepZero = 0;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:zone:new", this.generate.bind(this));
    this._trigger.on("rlv2:grid:step", this.step.bind(this));
  }

  init(): void {
    this.zones = {};
    this.stepRemain = 20;
    this.needConfirmStepZero = 0;
  }

  continue(): void {
    this.zones = this._player.current.module?.gridZone?.zones || {};
    this.stepRemain = this._player.current.module?.gridZone?.stepRemain ?? 20;
    this.needConfirmStepZero =
      this._player.current.module?.gridZone?.needConfirmStepZero ?? 0;
  }

  /** 生成当前层网格（简化：5 行 × 每行 2-3 节点，混合战斗/商店/事件） */
  generate([zoneId]: [number]): void {
    const theme = this._player.current.game!.theme;
    const stages = Object.keys(
      (excel.RoguelikeTopicTable.details[theme] as any)?.stages || {},
    );
    const roNum = theme.slice(-1);
    const zoneStages = stages.filter((s) =>
      s.startsWith(`ro${roNum}_n_${zoneId}_`),
    );
    const normalStages = stages.filter((s) => /^ro\d+_n_\d+_/.test(s));
    const eliteStages = stages.filter((s) => /^ro\d+_e_\d+_/.test(s));
    // 优先本层关卡，缺失回退全主题普通关卡
    const all =
      zoneStages.length > 0
        ? zoneStages
        : [...normalStages, ...eliteStages];

    const nodes: { [key: string]: GridNode } = {};
    // 简单网格：x 0..4，y 0..2（约 12-15 节点）
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 3; y++) {
        const nodeId = `${x}${String(y).padStart(2, "0")}`;
        const roll = Math.random();
        if (roll < 0.45) {
          // 战斗节点
          const stageId =
            all[Math.floor(Math.random() * Math.max(all.length, 1))] || "";
          nodes[nodeId] = {
            content: { savage: { stageId } },
            state: x === 0 ? 1 : 0,
            show: 1,
          };
        } else if (roll < 0.6) {
          // 商店节点
          nodes[nodeId] = {
            content: { shop: { goods: [] } },
            state: x === 0 ? 1 : 0,
            show: 1,
          };
        } else {
          // 事件/空节点
          nodes[nodeId] = {
            content: {},
            state: x === 0 ? 1 : 0,
            show: 1,
          };
        }
      }
    }
    this.zones[String(zoneId)] = { nodes };
    this.stepRemain = 20;
    this.needConfirmStepZero = 1;
  }

  /** 消耗一步行动力（rlv2:grid:step 事件处理器） */
  step(): void {
    if (this.stepRemain > 0) {
      this.stepRemain -= 1;
    }
  }

  /** 移动到指定节点（route 末节点）；标记节点已访问并返回节点 */
  moveTo(route: string[]): GridNode | undefined {
    const zoneId = String(this._player._status.cursor.zone);
    const zone = this.zones[zoneId];
    if (!zone || !route || route.length === 0) return undefined;
    const last = route[route.length - 1];
    const node = zone.nodes[last];
    if (node) {
      node.state = 2;
      // 相连节点置为可访问
      const lastX = parseInt(last[0], 10);
      const lastY = parseInt(last.slice(1), 10);
      for (const [id, n] of Object.entries(zone.nodes)) {
        const nx = parseInt(id[0], 10);
        const ny = parseInt(id.slice(1), 10);
        if (Math.abs(nx - lastX) + Math.abs(ny - lastY) === 1 && n.state === 0) {
          n.state = 1;
        }
      }
    }
    return node;
  }

  toJSON(): {
    zones: { [key: string]: GridZone };
    stepRemain: number;
    needConfirmStepZero: number;
  } {
    return {
      zones: this.zones,
      stepRemain: this.stepRemain,
      needConfirmStepZero: this.needConfirmStepZero,
    };
  }
}
