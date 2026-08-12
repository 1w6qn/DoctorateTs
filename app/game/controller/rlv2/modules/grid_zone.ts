/**
 * GRID_ZONE 模块（rogue_6 网格区域——无相地图）
 *
 * 客户端状态形状（types-playerdata）：gridZone = {
 *   zones: { [zoneId]: { nodes: { [nodeId]: {
 *     content: { savage: { stageId }, shop: { goods[] } }, state, show } } } },
 *   stepRemain, needConfirmStepZero
 * }
 *
 * 黑流树海为"无相地图"：地图由官方构造模板（BLACKSTREAM_CONSTRUCTIONS）决定
 * 连通结构（occupiedSlots/edges/startSlot/terminalSlots），节点类型按
 * 距起点徒步最短距离（沿普通连线数边）落在距离规则（BLACKSTREAM_DISTANCE_RULES）
 * 与数量规则（BLACKSTREAM_COUNT_RULES）范围内。节点 ID 与官服一致：x*100+y。
 */
import { RoguelikeV2Controller } from "../../rlv2";
import excel from "@excel/excel";
import { TypedEventEmitter } from "@game/model/events";
import {
  BLACKSTREAM_CONSTRUCTIONS,
  BLACKSTREAM_COUNT_RULES,
  BLACKSTREAM_DISTANCE_RULES,
  BLACKSTREAM_LAYER_TYPES,
  BlackstreamConstruction,
} from "./blackstream-data";

interface GridNode {
  content: {
    savage?: { stageId: string };
    shop?: { goods: string[] };
    kind?: number;
  };
  state: number; // 0 未访问 / 1 可访问 / 2 已访问
  show: boolean; // 视野：false 未点亮 / true 可见
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
  RAIN_VIEW: 67108864, // 羽瞰点（照亮 1-2 曼哈顿距离）
  RESIDENT: 134217728, // "居民"据点
  GLADE: 268435456, // 林间空地
};

/** 构造模板节点 type 字符串 → 节点数值（与官服 nodeTypeData 对齐） */
const CONSTRUCTION_TYPE_TO_NODE: { [key: string]: number } = {
  start: ROGUE6_NODE.GLADE,
  combat: ROGUE6_NODE.BATTLE_NORMAL,
  "emergency-combat": ROGUE6_NODE.BATTLE_ELITE,
  "danger-enemy": ROGUE6_NODE.BATTLE_BOSS,
  "safe-corner": ROGUE6_NODE.REST,
  encounter: ROGUE6_NODE.INCIDENT,
  wish: ROGUE6_NODE.WISH,
  "gain-loss": ROGUE6_NODE.SACRIFICE,
  "first-step": ROGUE6_NODE.EXPEDITION,
  "rogue-trader": ROGUE6_NODE.SHOP,
  "wrong-turn": ROGUE6_NODE.MIRAGE,
  "fate-choice": ROGUE6_NODE.PROPHECY,
  "narrow-meet": ROGUE6_NODE.FACE_OFF,
  "secret-trader": ROGUE6_NODE.SECRET_SHOP,
  "winding-path": ROGUE6_NODE.TUNNEL,
  "danger-end": ROGUE6_NODE.VISIBLE_END,
  "danger-path": ROGUE6_NODE.VISIBLE_PATH,
  "emergency-aid": ROGUE6_NODE.EMERGENCY_AID,
  overlook: ROGUE6_NODE.RAIN_VIEW,
  settlement: ROGUE6_NODE.RESIDENT,
  glade: ROGUE6_NODE.GLADE,
};

/** 节点数值 → 客户端可渲染类型（用于 content.kind 的显式数值） */
const NODE_TO_KIND: { [key: number]: number } = {
  [ROGUE6_NODE.REST]: ROGUE6_NODE.REST,
  [ROGUE6_NODE.INCIDENT]: ROGUE6_NODE.INCIDENT,
  [ROGUE6_NODE.WISH]: ROGUE6_NODE.WISH,
  [ROGUE6_NODE.SACRIFICE]: ROGUE6_NODE.SACRIFICE,
  [ROGUE6_NODE.EXPEDITION]: ROGUE6_NODE.EXPEDITION,
  [ROGUE6_NODE.SHOP]: ROGUE6_NODE.SHOP,
  [ROGUE6_NODE.MIRAGE]: ROGUE6_NODE.MIRAGE,
  [ROGUE6_NODE.PROPHECY]: ROGUE6_NODE.PROPHECY,
  [ROGUE6_NODE.FACE_OFF]: ROGUE6_NODE.FACE_OFF,
  [ROGUE6_NODE.SECRET_SHOP]: ROGUE6_NODE.SECRET_SHOP,
  [ROGUE6_NODE.TUNNEL]: ROGUE6_NODE.TUNNEL,
  [ROGUE6_NODE.VISIBLE_END]: ROGUE6_NODE.VISIBLE_END,
  [ROGUE6_NODE.VISIBLE_PATH]: ROGUE6_NODE.VISIBLE_PATH,
  [ROGUE6_NODE.EMERGENCY_AID]: ROGUE6_NODE.EMERGENCY_AID,
  [ROGUE6_NODE.RAIN_VIEW]: ROGUE6_NODE.RAIN_VIEW,
  [ROGUE6_NODE.RESIDENT]: ROGUE6_NODE.RESIDENT,
  [ROGUE6_NODE.GLADE]: ROGUE6_NODE.GLADE,
};

/** 层索引（0 起）→ 距离规则列索引：I II III IV IV追忆 V（官服 Ut 映射） */
function distanceColumnForLayer(layer: number): number {
  // 层 1..3 → 列 0..2；层 4 → 列 3（IV）；层 5 → 列 5（V）
  if (layer <= 3) return layer - 1;
  if (layer === 4) return 3;
  return 5;
}

/** 层（1 起）→ 数量规则列索引（I..V → 0..4） */
function countColumnForLayer(layer: number): number {
  return Math.min(4, layer - 1);
}

export class RoguelikeGridZoneManager {
  zones: { [key: string]: GridZone };
  stepRemain: number;
  needConfirmStepZero: boolean;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.zones = {};
    this.stepRemain = 20;
    this.needConfirmStepZero = false;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:zone:new", this.generate.bind(this));
    this._trigger.on("rlv2:grid:step", this.step.bind(this));
  }

  init(): void {
    this.zones = {};
    this.stepRemain = 20;
    this.needConfirmStepZero = false;
  }

  continue(): void {
    this.zones = this._player.current.module?.gridZone?.zones || {};
    this.stepRemain = this._player.current.module?.gridZone?.stepRemain ?? 20;
    this.needConfirmStepZero =
      this._player.current.module?.gridZone?.needConfirmStepZero ?? false;
  }

  /** 官服节点 ID：x*100+y（抓包 route ["602","300"] 确认） */
  nodeId(x: number, y: number): string {
    return String(x * 100 + y);
  }

  /**
   * 生成当前层网格（黑流树海：构造模板 + 距起点边距离规则 + 层数量规则）
   * 从本层构造模板池随机选一张，按模板连通结构铺节点；
   * 起点固定 startSlot（林间空地/起点，可见可访问），终点为 terminalSlots
   * （险路尽头/险路恶敌），固定节点按模板类型放置，其余占位格按
   * 距起点徒步最短距离（沿 edges 数边）落在距离规则范围内。
   */
  generate([zoneId]: [number]): void {
    const theme = this._player.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme] as any;
    const stages = Object.keys(detail?.stages || {});
    const roNum = theme.slice(-1);

    // 本层关卡优先，缺失回退全主题普通关卡
    const zoneStages = stages.filter((s) =>
      s.startsWith(`ro${roNum}_n_${zoneId}_`),
    );
    const eliteStages = stages.filter((s) =>
      s.startsWith(`ro${roNum}_e_${zoneId}_`),
    );
    const all =
      zoneStages.length > 0
        ? zoneStages
        : stages.filter((s) => /^ro\d+_[ne]_\d+_/.test(s));

    // 层 index（0 起）→ 构造模板池（黑流树海 I..V 层；VI 为 boss 层）
    const layerIndex = Math.min(zoneId - 1, 5);
    const pool = BLACKSTREAM_CONSTRUCTIONS.filter(
      (c) => c.layerIndex === layerIndex,
    );
    const template: BlackstreamConstruction =
      pool.length > 0
        ? pool[Math.floor(Math.random() * pool.length)]
        : BLACKSTREAM_CONSTRUCTIONS[0];

    const nodes: { [key: string]: GridNode } = {};

    // 距起点沿边距离（BFS over template.edges）
    const dist = this.edgeDistances(template);

    // 起点
    const [sx, sy] = template.startSlot;
    nodes[this.nodeId(sx, sy)] = {
      content: { kind: ROGUE6_NODE.GLADE },
      state: 1,
      show: true,
    };

    // 终点（险路尽头/险路恶敌）——固定节点/终点状态可见
    const terminalType = template.terminalType;
    const terminalNode = CONSTRUCTION_TYPE_TO_NODE[terminalType] ?? ROGUE6_NODE.VISIBLE_END;
    for (const [tx, ty] of template.terminalSlots) {
      nodes[this.nodeId(tx, ty)] = this.makeContentNode(
        terminalNode,
        all,
        zoneStages.length > 0 ? zoneStages : all,
        true,
      );
    }

    // 模板固定节点（固定 type 字符串）
    for (const f of template.fixedNodes || []) {
      const [fx, fy] = f.slot;
      nodes[this.nodeId(fx, fy)] = this.makeContentNode(
        CONSTRUCTION_TYPE_TO_NODE[f.type] ?? ROGUE6_NODE.INCIDENT,
        all,
        zoneStages.length > 0 ? zoneStages : all,
        false,
      );
    }

    // 其余占位格：按距离规则 + 数量规则抽类型
    const occupied = new Set(
      template.occupiedSlots.map(([x, y]) => this.nodeId(x, y)),
    );
    const remaining = template.occupiedSlots.filter(
      ([x, y]) => !nodes[this.nodeId(x, y)],
    );
    // 起点相邻格一二层强制作战（官服 is={0:"combat",1:"combat"}）
    const startAdjacentCombat = layerIndex <= 1;
    const counts = this.typeCounts(template);
    for (const [x, y] of remaining) {
      const id = this.nodeId(x, y);
      const d = dist.get(id) ?? 1;
      const isStartAdjacent = d === 1;
      let type: number;
      if (startAdjacentCombat && isStartAdjacent) {
        type = ROGUE6_NODE.BATTLE_NORMAL;
      } else {
        type = this.pickTypeByRules(zoneId, d, counts);
      }
      counts[type] = (counts[type] || 0) + 1;
      nodes[id] = this.makeContentNode(
        type,
        all,
        zoneStages.length > 0 ? zoneStages : all,
        false,
      );
    }

    this.zones[`zone_${zoneId}`] = { nodes };
    // 同步官服 map.zones 全量结构（客户端地图渲染读 map.zones：index/pos/next/type/stage/visibility）
    this.syncMapZones(zoneId, template, nodes);
    this.stepRemain = 20;
    this.needConfirmStepZero = true;
  }

  /**
   * 同步官服 map.zones（PlayerRoguelikeV2Dungeon）——与 module.gridZone 并存。
   * 键为层号（与控制器 _map.zones[zone] 读取一致），节点带 pos/next/type/stage/zone_end。
   */
  syncMapZones(
    zoneId: number,
    template: BlackstreamConstruction,
    lightNodes: { [key: string]: GridNode },
  ): void {
    const map = this._player._map;
    if (!map) return;
    const fullNodes: { [key: string]: any } = {};
    // 邻接表：template.edges → next（官服 next 为 {x,y} 列表，按 x,y 排序）
    const adj: { [key: string]: { x: number; y: number }[] } = {};
    for (const [a, b] of template.edges) {
      const ia = this.nodeId(a[0], a[1]);
      const ib = this.nodeId(b[0], b[1]);
      (adj[ia] = adj[ia] || []).push({ x: b[0], y: b[1] });
      (adj[ib] = adj[ib] || []).push({ x: a[0], y: a[1] });
    }
    for (const id of Object.keys(lightNodes)) {
      const x = Math.floor(Number(id) / 100);
      const y = Number(id) % 100;
      const light = lightNodes[id];
      const next = (adj[id] || []).slice().sort((p, q) => p.x - q.x || p.y - q.y);
      const node: any = {
        index: id,
        pos: { x, y },
        next,
        type: this.lightType(light),
        visibility: 0,
      };
      if (light.content?.savage?.stageId) node.stage = light.content.savage.stageId;
      // 终点（险路尽头/险路恶敌）标记 zone_end——控制器 checkZoneEnd 依赖
      const isTerminal = template.terminalSlots.some(
        ([tx, ty]) => tx === x && ty === y,
      );
      if (isTerminal) node.zone_end = true;
      fullNodes[id] = node;
    }
    // 官服 map.zones 键 = 区域索引（zone_1 → 1000），非层号
    map.zones[String(1000 + zoneId - 1)] = {
      id: `zone_${zoneId}`,
      index: 1000 + zoneId - 1,
      nodes: fullNodes,
      variation: [],
    };
  }

  /** GridNode 内容 → 官方节点 type 数值（savage/shop/kind 均带 type 冗余） */
  lightType(light: GridNode): number {
    if (typeof light.content?.kind === "number") return light.content.kind;
    if (light.content?.savage) return ROGUE6_NODE.BATTLE_NORMAL;
    if (light.content?.shop) return ROGUE6_NODE.SHOP;
    return ROGUE6_NODE.GLADE;
  }

  /** 距起点沿模板 edges 的最短步数（BFS），无连通时回退曼哈顿距离 */
  edgeDistances(template: BlackstreamConstruction): Map<string, number> {
    const dist = new Map<string, number>();
    const startId = this.nodeId(template.startSlot[0], template.startSlot[1]);
    dist.set(startId, 0);
    const adj: { [key: string]: string[] } = {};
    const addEdge = (a: string, b: string) => {
      (adj[a] = adj[a] || []).push(b);
      (adj[b] = adj[b] || []).push(a);
    };
    for (const [a, b] of template.edges) {
      addEdge(this.nodeId(a[0], a[1]), this.nodeId(b[0], b[1]));
    }
    const queue = [startId];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      for (const next of adj[cur] || []) {
        if (!dist.has(next)) {
          dist.set(next, dist.get(cur)! + 1);
          queue.push(next);
        }
      }
    }
    // 未连通占位格回退曼哈顿距离（羽瞰/终点的补漏）
    for (const [x, y] of template.occupiedSlots) {
      const id = this.nodeId(x, y);
      if (!dist.has(id)) {
        dist.set(
          id,
          Math.abs(x - template.startSlot[0]) +
            Math.abs(y - template.startSlot[1]),
        );
      }
    }
    return dist;
  }

  /** 本层各类型已占用计数（初始化：模板固定节点 + 终点） */
  typeCounts(template: BlackstreamConstruction): { [type: number]: number } {
    const counts: { [type: number]: number } = {};
    const count = (t: number) => {
      counts[t] = (counts[t] || 0) + 1;
    };
    count(ROGUE6_NODE.GLADE); // 起点
    const terminalType =
      CONSTRUCTION_TYPE_TO_NODE[template.terminalType] ?? ROGUE6_NODE.VISIBLE_END;
    for (const _t of template.terminalSlots) count(terminalType);
    for (const f of template.fixedNodes || []) {
      count(CONSTRUCTION_TYPE_TO_NODE[f.type] ?? ROGUE6_NODE.INCIDENT);
    }
    return counts;
  }

  /**
   * 按距离规则 + 数量规则选择节点类型。
   * 候选 = 距离规则允许该距离的本层类型（未定/— 跳过）；
   * 优先未达数量上限的类型；战斗类型优先（保持层内战斗占比）。
   */
  pickTypeByRules(
    layer: number,
    distance: number,
    counts: { [type: number]: number },
  ): number {
    const dCol = distanceColumnForLayer(layer);
    const cCol = countColumnForLayer(layer);

    // 距离规则表：nodeType → [min,max]，未定跳过，—（null）跳过
    const allowedByDistance = new Set<number>();
    for (const rule of BLACKSTREAM_DISTANCE_RULES) {
      const t = rule.nodeType ? CONSTRUCTION_TYPE_TO_NODE[rule.nodeType] : undefined;
      if (t === undefined) continue;
      const v = rule.values[dCol];
      if (!v || v === "unknown") continue;
      if (Array.isArray(v)) {
        const [min, max] = v;
        if (min !== null && distance >= min && (max === null || distance <= max)) {
          allowedByDistance.add(t);
        }
      } else if (typeof v === "object" && v.set) {
        if (v.set.includes(distance)) allowedByDistance.add(t);
      }
    }
    // 层允许类型过滤（BLACKSTREAM_LAYER_TYPES 用中文标签——映射回数值集合）
    const layerTypes = BLACKSTREAM_LAYER_TYPES[layer - 1] || [];
    const layerNodeSet = this.layerTypeSet(layerTypes);
    const candidates = [...allowedByDistance].filter((t) => layerNodeSet.has(t));

    // 数量规则：候选内未达上限的类型优先
    const underLimit = candidates.filter((t) => {
      const rule = BLACKSTREAM_COUNT_RULES.find((r) => {
        const num =
          r.nodeType === "start"
            ? ROGUE6_NODE.GLADE
            : r.nodeType
              ? CONSTRUCTION_TYPE_TO_NODE[r.nodeType]
              : undefined;
        return num === t;
      });
      if (!rule) return true;
      const v = rule.values[cCol];
      if (!v) return true;
      let max: number | null = null;
      if (Array.isArray(v)) {
        max = v[1];
      } else if (typeof v === "object" && v.set) {
        const nums = v.set.filter((n): n is number => n !== null);
        max = nums.length > 0 ? Math.max(...nums) : null;
      }
      if (max === null) return true;
      return (counts[t] || 0) < max;
    });

    const pool = underLimit.length > 0 ? underLimit : candidates;
    if (pool.length === 0) return ROGUE6_NODE.GLADE;
    return pool[Math.floor(Math.random() * pool.length)];
  }

  /** 层类型中文标签集合 → 节点数值集合 */
  layerTypeSet(labels: string[]): Set<number> {
    const labelToNode: { [key: string]: number } = {
      起点: ROGUE6_NODE.GLADE,
      林间空地: ROGUE6_NODE.GLADE,
      作战: ROGUE6_NODE.BATTLE_NORMAL,
      紧急作战: ROGUE6_NODE.BATTLE_ELITE,
      险路恶敌: ROGUE6_NODE.BATTLE_BOSS,
      安全的角落: ROGUE6_NODE.REST,
      不期而遇: ROGUE6_NODE.INCIDENT,
      得偿所愿: ROGUE6_NODE.WISH,
      失与得: ROGUE6_NODE.SACRIFICE,
      先行一步: ROGUE6_NODE.EXPEDITION,
      诡意行商: ROGUE6_NODE.SHOP,
      误入奇境: ROGUE6_NODE.MIRAGE,
      命运所指: ROGUE6_NODE.PROPHECY,
      狭路相逢: ROGUE6_NODE.FACE_OFF,
      秘境行商: ROGUE6_NODE.SECRET_SHOP,
      曲折密道: ROGUE6_NODE.TUNNEL,
      险路尽头: ROGUE6_NODE.VISIBLE_END,
      险路小径: ROGUE6_NODE.VISIBLE_PATH,
      应急助力: ROGUE6_NODE.EMERGENCY_AID,
      羽瞰点: ROGUE6_NODE.RAIN_VIEW,
      "“居民”据点": ROGUE6_NODE.RESIDENT,
      "流窜“居民”": ROGUE6_NODE.RESIDENT,
    };
    const set = new Set<number>();
    for (const l of labels) {
      const t = labelToNode[l];
      if (t !== undefined) set.add(t);
    }
    // 层列表含林间空地/起点时始终允许 GLADE 作填充
    if (labels.includes("林间空地") || labels.includes("起点")) set.add(ROGUE6_NODE.GLADE);
    return set;
  }

  /** 构造 GridNode：战斗带 stage + kind，商店空货架 + kind，其余 kind 数值；初始均未访问（state 0） */
  makeContentNode(
    type: number,
    allStages: string[],
    zoneStages: string[],
    _isTerminal: boolean,
  ): GridNode {
    if (type === ROGUE6_NODE.BATTLE_NORMAL || type === ROGUE6_NODE.BATTLE_ELITE || type === ROGUE6_NODE.BATTLE_BOSS) {
      const pool = zoneStages.length > 0 ? zoneStages : allStages;
      const stageId = pool[Math.floor(Math.random() * Math.max(pool.length, 1))] || "";
      return { content: { savage: { stageId }, kind: type }, state: 0, show: true };
    }
    if (type === ROGUE6_NODE.SHOP || type === ROGUE6_NODE.SECRET_SHOP) {
      return { content: { shop: { goods: [] }, kind: type }, state: 0, show: true };
    }
    return { content: { kind: type }, state: 0, show: true };
  }

  /** 消耗一步行动力（rlv2:grid:step 事件处理器） */
  step(): void {
    if (this.stepRemain > 0) {
      this.stepRemain -= 1;
    }
  }

  /** 移动到指定节点（route 末节点）；标记节点已访问并返回节点 */
  moveTo(route: string[]): GridNode | undefined {
    const zoneId = `zone_${this._player._status.cursor.zone}`;
    const zone = this.zones[zoneId];
    if (!zone || !route || route.length === 0) return undefined;
    const last = route[route.length - 1];
    const node = zone.nodes[last];
    if (node) {
      node.state = 2;
      // 视野：点亮当前节点曼哈顿距离 1 的可达节点（黑流树海视野机制——
      // 自身视野照亮直接可达节点；羽瞰点照亮 1-2 格）
      const lastX = Math.floor(Number(last) / 100);
      const lastY = Number(last) % 100;
      const visionRange = node.content?.kind === ROGUE6_NODE.RAIN_VIEW ? 2 : 1;
      for (const [id, n] of Object.entries(zone.nodes)) {
        const nx = Math.floor(Number(id) / 100);
        const ny = Number(id) % 100;
        const dist = Math.abs(nx - lastX) + Math.abs(ny - lastY);
        if (dist <= visionRange) {
          n.show = true;
          if (n.state === 0) n.state = 1;
        }
      }
    }
    return node;
  }

  toJSON(): {
    zones: { [key: string]: GridZone };
    stepRemain: number;
    needConfirmStepZero: boolean;
  } {
    // 官方 gridZone 节点 content 仅 savage/shop（无 kind）；kind 为内部类型标记，
    // 序列化时剥离（客户端节点类型从 map.zones.type 读取，多出 kind 字段会导致解析异常）
    const strip = (n: GridNode): GridNode => {
      const c: any = {};
      if (n.content?.savage) c.savage = n.content.savage;
      if (n.content?.shop) c.shop = n.content.shop;
      return { content: c, state: n.state, show: n.show };
    };
    const zones: { [key: string]: GridZone } = {};
    for (const [k, z] of Object.entries(this.zones)) {
      const nodes: { [key: string]: GridNode } = {};
      for (const [id, n] of Object.entries(z.nodes)) {
        nodes[id] = strip(n);
      }
      zones[k] = { nodes };
    }
    return {
      zones,
      stepRemain: this.stepRemain,
      needConfirmStepZero: this.needConfirmStepZero,
    };
  }
}
