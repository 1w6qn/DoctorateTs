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
    kind?: number;
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

  /** 生成当前层网格（按官方 zone 数据：portal zone 的 rollNodeData groups 定义允许节点类型） */
  generate([zoneId]: [number]): void {
    const theme = this._player.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const stages = Object.keys(detail?.stages || {});
    const roNum = theme.slice(-1);

    // 官方 portal zone：本层的自由探索区域（zone_portal_normal_{zone}_N）
    const zoneData = detail?.zones || {};
    const portalIds = Object.keys(zoneData).filter((z) =>
      z.startsWith(`zone_portal_normal_${zoneId}_`),
    );
    const portalZoneId =
      portalIds[Math.floor(Math.random() * Math.max(portalIds.length, 1))] ||
      `zone_portal_normal_${zoneId}_1`;

    // rollNodeData：portal zone 允许的节点类型（INCIDENT/BATTLE_NORMAL/...）
    const rollNodeData = detail?.rollNodeData || {};
    const groups = rollNodeData[portalZoneId]?.groups || {};
    const allowedTypes = Object.keys(groups).map(
      (k) => (groups[k] as { nodeType: string }).nodeType,
    );
    const typeToCode: Record<string, number> = {
      BATTLE_NORMAL: 1,
      BATTLE_ELITE: 2,
      BATTLE_BOSS: 4,
      SHOP: 8,
      REST: 16,
      INCIDENT: 32,
      TREASURE: 64,
      ENTERTAINMENT: 128,
      UNKNOWN: 256,
      WISH: 512,
      SACRIFICE: 1024,
      EXPEDITION: 2048,
      BATTLE_SHOP: 4096,
    };

    // 本层关卡优先，缺失回退全主题普通关卡
    const zoneStages = stages.filter((s) =>
      s.startsWith(`ro${roNum}_n_${zoneId}_`),
    );
    const all =
      zoneStages.length > 0
        ? zoneStages
        : stages.filter(
            (s) => /^ro\d+_[ne]_\d+_/.test(s),
          );

    const nodes: { [key: string]: GridNode } = {};
    const gridX = 5;
    const gridY = 3;
    for (let x = 0; x < gridX; x++) {
      for (let y = 0; y < gridY; y++) {
        const nodeId = `${x}${String(y).padStart(2, "0")}`;
        // 节点类型：优先从官方允许类型池抽（战斗为主），缺失回退混合
        const typeCodes =
          allowedTypes.length > 0
            ? allowedTypes
                .map((t) => typeToCode[t])
                .filter((c) => c !== undefined)
            : [1, 1, 32, 4096, 512];
        const roll = Math.floor(
          Math.random() * Math.max(typeCodes.length, 1),
        );
        const type = typeCodes[roll] ?? 1;
        if (type === 1 || type === 2 || type === 4) {
          const stageId =
            all[Math.floor(Math.random() * Math.max(all.length, 1))] || "";
          nodes[nodeId] = {
            content: { savage: { stageId } },
            state: x === 0 ? 1 : 0,
            show: 1,
          };
        } else if (type === 8 || type === 4096) {
          nodes[nodeId] = {
            content: { shop: { goods: [] } },
            state: x === 0 ? 1 : 0,
            show: 1,
          };
        } else {
          nodes[nodeId] = {
            content: { kind: typeToCode[type] ?? type },
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
