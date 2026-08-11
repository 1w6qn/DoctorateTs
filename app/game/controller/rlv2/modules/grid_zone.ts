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
  show: number; // 视野：0 未点亮 / 1 可见
}

interface GridZone {
  nodes: { [key: string]: GridNode };
}

/** 黑流树海节点类型（官方 nodeTypeData 数值） */
const ROGUE6_NODE = {
  BATTLE_NORMAL: 1,
  BATTLE_ELITE: 2,
  BATTLE_BOSS: 4,
  REST: 16,
  INCIDENT: 32,
  WISH: 512,
  SACRIFICE: 1024,
  EXPEDITION: 2048,
  SHOP: 4096,
  MIRAGE: 8192, // 误入奇境
  PROPHECY: 32768, // 命运所指
  FACE_OFF: 262144, // 狭路相逢
  SECRET_SHOP: 2097152, // 秘境行商
  TUNNEL: 4194304, // 曲折密道
  VISIBLE_END: 8388608, // 险路尽头
  VISIBLE_PATH: 16777216, // 险路小径
  EMERGENCY_AID: 33554432, // 应急助力
  RAIN_VIEW: 67108864, // 羽瞰点（照亮 1-2/1-3 曼哈顿距离）
  RESIDENT: 134217728, // "居民"据点
  GLADE: 268435456, // 林间空地
};

/**
 * 各层可出现的节点类型（对照黑流树海机制解析视频）：
 * 每层以 起点+林间空地 为基底；一层额外 作战/紧急/不期/得偿/秘境行商/险路小径；
 * 二层起 先行一步/安全屋/羽瞰点/居民据点/应急助力；三层 +曲折密道/狭路相逢/误入奇境；
 * 四层 +林间空地；五层 +命运所指/失与得；六层收敛（作战/紧急/得偿/不期/安全屋/诡秘行商）
 */
const LAYER_NODE_TYPES: { [layer: number]: number[] } = {
  1: [ROGUE6_NODE.BATTLE_NORMAL, ROGUE6_NODE.BATTLE_ELITE, ROGUE6_NODE.INCIDENT, ROGUE6_NODE.WISH, ROGUE6_NODE.SECRET_SHOP, ROGUE6_NODE.VISIBLE_PATH],
  2: [ROGUE6_NODE.BATTLE_NORMAL, ROGUE6_NODE.BATTLE_ELITE, ROGUE6_NODE.INCIDENT, ROGUE6_NODE.WISH, ROGUE6_NODE.EXPEDITION, ROGUE6_NODE.REST, ROGUE6_NODE.RAIN_VIEW, ROGUE6_NODE.RESIDENT, ROGUE6_NODE.EMERGENCY_AID],
  3: [ROGUE6_NODE.BATTLE_NORMAL, ROGUE6_NODE.BATTLE_ELITE, ROGUE6_NODE.INCIDENT, ROGUE6_NODE.WISH, ROGUE6_NODE.EXPEDITION, ROGUE6_NODE.REST, ROGUE6_NODE.TUNNEL, ROGUE6_NODE.FACE_OFF, ROGUE6_NODE.MIRAGE, ROGUE6_NODE.EMERGENCY_AID],
  4: [ROGUE6_NODE.BATTLE_NORMAL, ROGUE6_NODE.BATTLE_ELITE, ROGUE6_NODE.INCIDENT, ROGUE6_NODE.WISH, ROGUE6_NODE.EXPEDITION, ROGUE6_NODE.REST, ROGUE6_NODE.TUNNEL, ROGUE6_NODE.FACE_OFF, ROGUE6_NODE.GLADE, ROGUE6_NODE.EMERGENCY_AID],
  5: [ROGUE6_NODE.BATTLE_NORMAL, ROGUE6_NODE.BATTLE_ELITE, ROGUE6_NODE.INCIDENT, ROGUE6_NODE.WISH, ROGUE6_NODE.SACRIFICE, ROGUE6_NODE.REST, ROGUE6_NODE.PROPHECY, ROGUE6_NODE.FACE_OFF, ROGUE6_NODE.EMERGENCY_AID],
  6: [ROGUE6_NODE.BATTLE_NORMAL, ROGUE6_NODE.BATTLE_ELITE, ROGUE6_NODE.INCIDENT, ROGUE6_NODE.WISH, ROGUE6_NODE.REST, ROGUE6_NODE.SHOP],
};

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

  /** 生成当前层网格（黑流树海：无相地图 + 视野机制） */
  generate([zoneId]: [number]): void {
    const theme = this._player.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const stages = Object.keys(detail?.stages || {});
    const roNum = theme.slice(-1);

    // 本层关卡优先，缺失回退全主题普通关卡
    const zoneStages = stages.filter((s) =>
      s.startsWith(`ro${roNum}_n_${zoneId}_`),
    );
    const all =
      zoneStages.length > 0
        ? zoneStages
        : stages.filter((s) => /^ro\d+_[ne]_\d+_/.test(s));

    // 本层可出节点类型（视频机制：层数限制）
    const allowedTypes = LAYER_NODE_TYPES[zoneId] || LAYER_NODE_TYPES[1];

    const nodes: { [key: string]: GridNode } = {};
    // 无相地图：起点（起始列）+ 林间空地（视野点亮基底）
    const startX = 0;
    const startY = 1;
    const gridX = 6;
    const gridY = 4;
    for (let x = 0; x < gridX; x++) {
      for (let y = 0; y < gridY; y++) {
        const nodeId = `${x}${String(y).padStart(2, "0")}`;
        const nodeX = Number(nodeId[0]);
        const nodeY = Number(nodeId.slice(1));
        // 起点：固定在最左列中央
        if (nodeX === startX && nodeY === startY) {
          nodes[nodeId] = {
            content: { kind: ROGUE6_NODE.GLADE },
            state: 1,
            show: 1,
          };
          continue;
        }
        // 起点相邻的 林间空地（视野基底，起点同列其余/相邻列偶发）
        const isGlade = Math.random() < 0.12;
        if (isGlade) {
          nodes[nodeId] = {
            content: { kind: ROGUE6_NODE.GLADE },
            state: 0,
            show: 1,
          };
          continue;
        }
        // 随机从本层允许类型抽（战斗为主）
        const type = allowedTypes[Math.floor(Math.random() * allowedTypes.length)];
        if (type === ROGUE6_NODE.BATTLE_NORMAL || type === ROGUE6_NODE.BATTLE_ELITE || type === ROGUE6_NODE.BATTLE_BOSS) {
          const stageId =
            all[Math.floor(Math.random() * Math.max(all.length, 1))] || "";
          nodes[nodeId] = {
            content: { savage: { stageId } },
            state: 0,
            // 视野：起点/林间空地可见，其余隐藏（移动/羽瞰点亮起）
            show: nodeX <= 1 ? 1 : 0,
          };
        } else if (type === ROGUE6_NODE.SHOP || type === ROGUE6_NODE.SECRET_SHOP) {
          nodes[nodeId] = {
            content: { shop: { goods: [] } },
            state: 0,
            show: nodeX <= 1 ? 1 : 0,
          };
        } else {
          nodes[nodeId] = {
            content: { kind: type },
            state: 0,
            show: nodeX <= 1 ? 1 : 0,
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
      // 视野：点亮当前节点曼哈顿距离 1 的可达节点（黑流树海视野机制——
      // 自身视野照亮直接可达节点；羽瞰点照亮 1-2 格）
      const lastX = parseInt(last[0], 10);
      const lastY = parseInt(last.slice(1), 10);
      const visionRange = node.content?.kind === ROGUE6_NODE.RAIN_VIEW ? 2 : 1;
      for (const [id, n] of Object.entries(zone.nodes)) {
        const nx = parseInt(id[0], 10);
        const ny = parseInt(id.slice(1), 10);
        const dist = Math.abs(nx - lastX) + Math.abs(ny - lastY);
        if (dist <= visionRange) {
          n.show = 1;
          if (n.state === 0) n.state = 1;
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
