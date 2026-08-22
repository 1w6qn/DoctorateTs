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
import {
  ROGUE6_NODE,
  ROGUE6_BATTLE_NODES,
  ROGUE6_SHOP_NODES,
  ROGUE6_INITIALLY_LIT_NODES,
  ROGUE6_REVISITABLE_NODES,
  ROGUE6_FORESIGHT,
  ROGUE6_ZONE_ACTION,
  ROGUE6_WING_OUTBUFF,
  BLACKSTREAM_THEME,
  isBlackstream,
} from "../theme-rules";

// 节点类型数值统一由 theme-rules 提供（单一事实来源）；此处 re-export 保持既有
// `import { ROGUE6_NODE } from "./modules/grid_zone"` 调用方不变。
export { ROGUE6_NODE };

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

/** 本层关卡池（按节点类型取用）：普通作战 / 紧急作战 / 险路恶敌 */
interface ZoneStagePools {
  normal: string[];
  elite: string[];
  boss: string[];
}

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

/** 误入奇境隐藏层（未萌生的摇篮）活动状态：
 * active=true 时当前地图为 portal zone（_map.zones 键 = portalZoneKey），
 * 行动力（stepRemain）耗尽后返回 returnZone/returnPos。
 * 乌托邦效果（variation）在进入时写入 portal zone 的 variation。 */
export interface GridPortalState {
  active: boolean;
  /** 返回区域（进入隐藏层前的 cursor.zone） */
  returnZone: number;
  /** 返回节点（进入隐藏层前的位置，x*100+y 节点 id） */
  returnNode: string;
  /** 本层乌托邦效果 id（variationData 键，如 variation_1） */
  variation: string;
  /** portal zone 在 _map.zones 的键（3000+ 避开常规 1000+ 键） */
  zoneKey: string;
  /** 进入时的场景族（portal1a/1b/2a…，用于返回提示/续局） */
  family: string;
}

/** 雾色场景族（scene_ro6_portalN → N）→ 乌托邦效果 id（variationData 键）。
 * 官方 variationData 共 9 条，与雾色一一对应：1~4=红雾（巨人摇篮/迪斯科狂热/已知浩劫/
 * 孤立石林，4 种战斗乌托邦）、5=蓝（全知者盲区）、6=绿（未亡者遗怨）、7=金（源石之城）、
 * 8=橙（消耗螺旋）、9=紫（换心联结）。
 *
 * 隐藏层构造模板不再硬编码：treehole-* 模板自带 `utopiaPortal`（单族）或
 * `utopiaPortals`（多族，红雾四族共用同一批模板）字段标注其所属雾色族，
 * 由 pickPortalTemplate 按该字段筛选。 */
function portalVariationIds(family: string): string[] {
  const n = parseInt(family, 10);
  // 红雾四族共用 variation_1..4（进入时随机取其一）；其余族与雾色一对一
  return n >= 1 && n <= 4
    ? ["variation_1", "variation_2", "variation_3", "variation_4"]
    : [`variation_${n}`];
}

export class RoguelikeGridZoneManager {
  zones: { [key: string]: GridZone };
  stepRemain: number;
  needConfirmStepZero: boolean;
  /** 误入奇境隐藏层活动状态（未进入时为 null） */
  portal: GridPortalState | null;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;
  /**
   * 本次移动请求中发生状态/视野变化的节点 id 集合（rlv2NodeChange.nodeList 数据源）。
   * 官服 pushMessage 只下发"变化节点"（到达节点 + 新揭示邻居），非整层全量；
   * moveTo 内累积，由控制器经 beginMove/takeChangedNodes 界定一次请求生命周期。
   */
  private _changedNodeIds: Set<string>;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.zones = {};
    this.stepRemain = 20;
    this.needConfirmStepZero = false;
    this.portal = null;
    this._changedNodeIds = new Set();
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:zone:new", this.generate.bind(this));
    this._trigger.on("rlv2:grid:step", this.step.bind(this));
  }

  init(): void {
    this.zones = {};
    this.stepRemain = 20;
    this.needConfirmStepZero = false;
    this.portal = null;
  }

  continue(): void {
    const g = this._player.current.module?.gridZone as any;
    this.zones = g?.zones || {};
    this.stepRemain = g?.stepRemain ?? 20;
    this.needConfirmStepZero =
      g?.needConfirmStepZero ?? false;
    this.portal = g?.portal ?? null;
    // 续局恢复 portal zone（_map.zones 键已在存档，无需重建）
    if (this.portal?.active && this.portal.zoneKey) {
      // 行动力已耗尽则立即返回（防续局卡在隐藏层）
      if (this.stepRemain <= 0) {
        this.leavePortal();
      }
    }
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
    const detail = excel.RoguelikeTopicTable.details[theme];
    const stages = Object.keys(detail?.stages || {});
    const roNum = theme.slice(-1);

    // 本层关卡池：普通 / 紧急（精英）/ 首领分开取——原实现只用普通池，精英与首领
    // 节点也抽普通关卡（eliteStages 算完未用），导致紧急作战/险路恶敌难度与官服不符。
    const zoneStages = stages.filter((s) =>
      s.startsWith(`ro${roNum}_n_${zoneId}_`),
    );
    const eliteStages = stages.filter((s) =>
      s.startsWith(`ro${roNum}_e_${zoneId}_`),
    );
    // 首领关卡：ro6_b_{zone}（含 _b 变体，如 ro6_b_1_b 哀悼铁腕）
    const bossStages = stages.filter((s) =>
      new RegExp(`^ro${roNum}_b_${zoneId}(_|$)`).test(s),
    );
    // 缺失回退全主题普通/紧急关卡（层号越界或数据缺失时不至于无 stage）
    const all =
      zoneStages.length > 0
        ? zoneStages
        : stages.filter((s) => /^ro\d+_[ne]_\d+_/.test(s));
    const pools: ZoneStagePools = {
      normal: zoneStages.length > 0 ? zoneStages : all,
      elite: eliteStages.length > 0 ? eliteStages : all,
      boss: bossStages.length > 0 ? bossStages : all,
    };

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

    // 起点（官服 gridZone：GLADE 起点/林间空地节点 state=2——官服 state 语义
    // 0=普通/未访问、2=GLADE(起点/林间空地)；原 state=1 与官服不符，客户端
    // 按 state 渲染节点状态可能异常）
    const [sx, sy] = template.startSlot;
    nodes[this.nodeId(sx, sy)] = {
      content: { kind: ROGUE6_NODE.GLADE },
      state: 2,
      show: true,
    };

    // 终点（险路尽头/险路恶敌）——固定节点/终点状态可见
    const terminalType = template.terminalType;
    const terminalNode = CONSTRUCTION_TYPE_TO_NODE[terminalType] ?? ROGUE6_NODE.VISIBLE_END;
    for (const [tx, ty] of template.terminalSlots) {
      nodes[this.nodeId(tx, ty)] = this.makeContentNode(terminalNode, pools);
    }

    // 模板固定节点（固定 type 字符串）
    for (const f of template.fixedNodes || []) {
      const [fx, fy] = f.slot;
      nodes[this.nodeId(fx, fy)] = this.makeContentNode(
        CONSTRUCTION_TYPE_TO_NODE[f.type] ?? ROGUE6_NODE.INCIDENT,
        pools,
      );
    }

    // 其余占位格：按距离规则 + 数量规则抽类型
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
      nodes[id] = this.makeContentNode(type, pools);
    }

    this.zones[`zone_${zoneId}`] = { nodes };
    // 同步官服 map.zones 全量结构（客户端地图渲染读 map.zones：index/pos/next/type/stage/visibility）
    this.syncMapZones(zoneId, template, nodes);
    // 进入区域 = 抵达起点：点亮起点沿地图边可达的首节点（初始仅特殊节点点亮，
    // 起点路径在此揭示，否则开局无可移动目标）。
    this.revealReachable(
      this.mapZoneKeyOf(`zone_${zoneId}`),
      `zone_${zoneId}`,
      template.startSlot[0],
      template.startSlot[1],
      1,
    );
    // 羽瞰点默认照亮到羽瞰点曼哈顿距离为 2 的节点（未经过时）：进层即揭示其周边 2 跳；
    // 抵达羽瞰点（经过，state=2）后由 moveTo 增为 3。
    for (const [id, n] of Object.entries(nodes)) {
      if (n.content?.kind === ROGUE6_NODE.RAIN_VIEW) {
        this.revealManhattan(
          this.mapZoneKeyOf(`zone_${zoneId}`),
          `zone_${zoneId}`,
          Math.floor(Number(id) / 100),
          Number(id) % 100,
          2,
        );
      }
    }
    // 进层揭示属于“初始版面”，不落入后续移动的 rlv2NodeChange.nodeList
    this._changedNodeIds = new Set();
    // 行动力：模板显式 action（VI 层/portal 等特殊层）优先，否则按层初始值 5/6/7/8/8
    this.stepRemain = template.action ?? this.initialActionForZone(zoneId);
    this.needConfirmStepZero = true;
    // 常规区域实托邦（难度≥2 起）：附加乌托邦效果（variation）到本层地图，客户端渲染区域效果。
    // 生成频率按难度分档：2~5 较低、6~11 提升（实托邦更频繁）、12+ 更高（晚期）；效果数值由客户端按难度处理。
    this.applyUtopiaVariation(zoneId);
  }

  /**
   * 常规区域实托邦：难度≥2 时按概率给本层附加乌托邦效果（map.zones[zone].variation）。
   * 官方规则：保密等级·2 起"实托邦将会在区域中生成"；6 起"更频繁地生成"；12 起"效果提升至晚期"。
   * 效果 id 取自 variationData（variation_1..9：巨人摇篮/迪斯科狂热/已知浩劫/孤立石林/全知者盲区/
   * 未亡者遗怨/源石之城/消耗螺旋/换心联结）；具体效果数值（早/中/晚期）由客户端按难度渲染。
   */
  private applyUtopiaVariation(zoneId: number): void {
    const theme = this._player.current.game?.theme ?? "";
    if (!isBlackstream(theme)) return;
    // 结局层（zone 6）不生成实托邦
    if (zoneId >= 6) return;
    const modeGrade = this._player.current.game?.modeGrade ?? 0;
    if (modeGrade < 2) return;
    const chance = modeGrade >= 12 ? 0.6 : modeGrade >= 6 ? 0.4 : 0.25;
    if (Math.random() >= chance) return;
    const detail = excel.RoguelikeTopicTable.details[theme];
    const variations = Object.keys(detail?.variationData || {});
    if (variations.length === 0) return;
    const varId = variations[Math.floor(Math.random() * variations.length)];
    const map = this._player._map;
    const key = String(1000 + zoneId - 1);
    if (map?.zones?.[key]) {
      map.zones[key].variation = [varId];
    }
  }

  /** 区域初始行动力（官方 I..V 层 5/6/7/8/8；【生命游戏】"翅膀"节点解锁后 Ⅰ 层 +1；
   * 襁褓天马（rogue_6_start_1）每区 +1 由官方 zone_into_reward buff 实现（进入区域发行动力物品）） */
  private initialActionForZone(zoneId: number): number {
    const base = ROGUE6_ZONE_ACTION[zoneId] ?? 8;
    let bonus = 0;
    const outer = this._player.outer?.[BLACKSTREAM_THEME];
    // 生命游戏"翅膀"节点（rogue_6_outbuff_37，RAW_TEXT_EFFECT"进入第一层时，行动力+1"）：Ⅰ 层初始行动力 6
    if (zoneId === 1 && outer?.buff?.unlocked?.[ROGUE6_WING_OUTBUFF]) {
      bonus += 1;
    }
    return base + bonus;
  }

  /**
   * 同步官服 map.zones（PlayerRoguelikeV2Dungeon）——与 module.gridZone 并存。
   * 键为层号（与控制器 _map.zones[zone] 读取一致），节点带 pos/next/type/stage/zone_end。
   */
  syncMapZones(
    zoneId: number,
    template: BlackstreamConstruction,
    lightNodes: { [key: string]: GridNode },
    mapKey?: string,
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
      // visibility（PlayerNodeForesightType 线格式）：0=NORMAL 已揭示可见（起点/初始点亮的
      // 特殊节点），1=HIDE_INVISIBLE 未揭示隐藏（其余节点——显示"未知事件"）。抵达时由
      // revealReachable/Manhattan 逐级揭示为 NORMAL。到达状态由 gridZone 节点 state 承载。
      const nodeType = this.lightType(light);
      const isStart =
        template.startSlot[0] === x && template.startSlot[1] === y;
      const visibility =
        isStart || ROGUE6_INITIALLY_LIT_NODES.includes(nodeType)
          ? ROGUE6_FORESIGHT.NORMAL
          : ROGUE6_FORESIGHT.HIDE_INVISIBLE;
      const node: any = {
        index: id,
        pos: { x, y },
        next,
        type: nodeType,
        visibility,
      };
      if (light.content?.savage?.stageId) node.stage = light.content.savage.stageId;
      // 终点（险路尽头/险路恶敌）标记 zone_end——控制器 checkZoneEnd 依赖
      const isTerminal = template.terminalSlots.some(
        ([tx, ty]) => tx === x && ty === y,
      );
      if (isTerminal) node.zone_end = true;
      fullNodes[id] = node;
    }
    // 官服 map.zones 键 = 区域索引（zone_1 → 1000），非层号；zone 带 variation + type
    map.zones[mapKey ?? String(1000 + zoneId - 1)] = {
      id: `zone_${zoneId}`,
      index: 1000 + zoneId - 1,
      nodes: fullNodes,
      variation: [],
      type: 0,
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
    // 层允许类型过滤（BLACKSTREAM_LAYER_TYPES 用中文标签——映射回数值集合；
    // 隐藏层/portal（layer 6）无层类型表 → 跳过过滤，由距离规则限定类型范围）
    const layerTypes = BLACKSTREAM_LAYER_TYPES[layer - 1] || [];
    const layerNodeSet = this.layerTypeSet(layerTypes);
    const candidates =
      layerNodeSet.size > 0
        ? [...allowedByDistance].filter((t) => layerNodeSet.has(t))
        : [...allowedByDistance];

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

  /**
   * 构造 GridNode：战斗按类型取对应关卡池（普通/紧急/首领）+ kind，
   * 商店（诡意行商/秘境行商/应急助力）空货架 + kind，其余仅 kind；初始均未访问（state 0）。
   * 视野/点亮状态由 map.zones 节点的 visibility（PlayerNodeForesightType 线格式 0/1/2）表示，
   * gridZone 节点 show 恒为 true，不承担点亮语义——见 syncMapZones / revealReachable。
   * @param type 节点类型数值（ROGUE6_NODE）
   * @param pools 本层关卡池
   * @returns 网格节点
   */
  makeContentNode(type: number, pools: ZoneStagePools): GridNode {
    if (ROGUE6_BATTLE_NODES.includes(type)) {
      const pool =
        type === ROGUE6_NODE.BATTLE_ELITE
          ? pools.elite
          : type === ROGUE6_NODE.BATTLE_BOSS
            ? pools.boss
            : pools.normal;
      const usable = pool.length > 0 ? pool : pools.normal;
      const stageId =
        usable[Math.floor(Math.random() * Math.max(usable.length, 1))] || "";
      return { content: { savage: { stageId }, kind: type }, state: 0, show: true };
    }
    if (ROGUE6_SHOP_NODES.includes(type)) {
      return { content: { shop: { goods: [] }, kind: type }, state: 0, show: true };
    }
    return { content: { kind: type }, state: 0, show: true };
  }

  /** 消耗一步行动力（rlv2:grid:step 事件处理器） */
  step(): void {
    if (this.stepRemain > 0) {
      this.stepRemain -= 1;
    }
    // 隐藏层行动力耗尽 → 返回进入时所在节点（官服：本层专用行动力耗尽后返回）
    if (this.portal?.active && this.stepRemain <= 0) {
      this.leavePortal();
    }
  }

  /**
   * 按雾色场景族抽取隐藏层构造模板（utopia-* 系列，layerIndex=6）。
   * 模板归属由数据字段决定：`utopiaPortal`（单族，如 treehole-05 = 5 蓝雾/全知者盲区）
   * 或 `utopiaPortals`（多族，treehole-01..04 = [1,2,3,4] 红雾四族共用）。
   * @param family 雾色场景族数字字符串（1..9）
   * @returns 构造模板；无匹配时回退任一隐藏层模板
   */
  private pickPortalTemplate(family: string): BlackstreamConstruction {
    const n = parseInt(family, 10);
    const hidden = BLACKSTREAM_CONSTRUCTIONS.filter((c) => c.layerIndex === 6);
    const pool = hidden.filter((c) =>
      c.utopiaPortals
        ? c.utopiaPortals.includes(n)
        : c.utopiaPortal === n,
    );
    const usable = pool.length > 0 ? pool : hidden;
    return (
      usable[Math.floor(Math.random() * usable.length)] ??
      BLACKSTREAM_CONSTRUCTIONS[0]
    );
  }

  /** 生成误入奇境隐藏层（未萌生的摇篮）：
   * 按雾色场景族选乌托邦模板铺节点，写入 map.zones（键 3000+，variation=乌托邦效果），
   * 本层专用行动力 = 模板 action，记录返回点。 */
  generatePortal(family: string, returnZone: number, returnNode: string): void {
    const theme = this._player.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme];
    const variationIds = portalVariationIds(family);
    const variationId =
      variationIds[Math.floor(Math.random() * variationIds.length)] ??
      "variation_1";
    const template = this.pickPortalTemplate(family);
    // 隐藏层无专属关卡池（官方 stages 无 portal 层条目）→ 用全主题关卡兜底
    const stages = Object.keys(detail?.stages || {});
    const pools: ZoneStagePools = { normal: stages, elite: stages, boss: stages };
    const nodes: { [key: string]: GridNode } = {};

    // 起点（林间空地，可见可访问）
    const [sx, sy] = template.startSlot;
    nodes[this.nodeId(sx, sy)] = {
      content: { kind: ROGUE6_NODE.GLADE },
      state: 2,
      show: true,
    };
    // 模板固定节点（utopia 模板无终点：terminalSlots 为空，行动力耗尽返回）
    for (const f of template.fixedNodes || []) {
      const [fx, fy] = f.slot;
      nodes[this.nodeId(fx, fy)] = this.makeContentNode(
        CONSTRUCTION_TYPE_TO_NODE[f.type] ?? ROGUE6_NODE.INCIDENT,
        pools,
      );
    }
    // 其余占位格：按隐藏层（第 6 列）距离/数量规则抽类型
    const remaining = template.occupiedSlots.filter(
      ([x, y]) => !nodes[this.nodeId(x, y)],
    );
    const dist = this.edgeDistances(template);
    for (const [x, y] of remaining) {
      const id = this.nodeId(x, y);
      const d = dist.get(id) ?? 1;
      const type = this.pickTypeByRules(6, d, {});
      nodes[id] = this.makeContentNode(type, pools);
    }

    // portal zone 键：3000 起首个未占用键（原实现 3000+random*900 有 1/900 撞键概率，
    // 同一局多次进入隐藏层可能覆盖上一层残留数据）
    const key = this.nextPortalZoneKey();
    this.zones[`zone_${key}`] = { nodes };
    this.syncMapZones(parseInt(key, 10) - 1000 + 1, template, nodes, key);
    const map = this._player._map;
    if (map?.zones?.[key]) {
      map.zones[key].variation = [variationId];
      map.zones[key].id = `zone_portal_normal_${family}`;
    }
    this.stepRemain = template.action ?? 2;
    this.needConfirmStepZero = true;
    this.portal = {
      active: true,
      returnZone,
      returnNode,
      variation: variationId,
      zoneKey: key,
      family,
    };
    // 进入隐藏层 = 抵达起点：点亮起点沿边可达首节点（portal.active 已置位，
    // mapZoneKeyOf 据此命中 portalZoneKey 本身）
    this.revealReachable(this.mapZoneKeyOf(`zone_${key}`), `zone_${key}`, sx, sy, 1);
    // 初始版面揭示不落入后续移动的 rlv2NodeChange.nodeList
    this._changedNodeIds = new Set();
    // 当前节点 = 隐藏层起点
    const status = this._player._status;
    status.cursor.position = { x: sx, y: sy };
  }

  /**
   * 分配下一个 portal zone 键（3000 起递增，跳过已占用）。
   * @returns 未被 map.zones / this.zones 占用的键
   */
  private nextPortalZoneKey(): string {
    const map = this._player._map;
    for (let n = 3000; n < 3900; n++) {
      const key = String(n);
      if (map?.zones?.[key]) continue;
      if (this.zones[`zone_${key}`]) continue;
      return key;
    }
    return "3000";
  }

  /** 离开隐藏层（行动力耗尽/放弃）：删除 portal zone，恢复返回点，状态回 WAIT_MOVE */
  leavePortal(): void {
    if (!this.portal) return;
    const p = this.portal;
    const map = this._player._map;
    if (map?.zones?.[p.zoneKey]) delete map.zones[p.zoneKey];
    delete this.zones[`zone_${p.zoneKey}`];
    const status = this._player._status;
    status.cursor.zone = p.returnZone;
    const nodeId = parseInt(p.returnNode, 10);
    status.cursor.position = {
      x: Math.floor(nodeId / 100),
      y: nodeId % 100,
    };
    this.portal = null;
    this.stepRemain = this.initialActionForZone(p.returnZone);
    this.needConfirmStepZero = true;
    status.state = "WAIT_MOVE";
    this._trigger.emit("rlv2:portal:return", []);
  }

  /** 当前活动 zone 键（隐藏层返回 portal.zoneKey；常规返回 cursor.zone） */
  currentZoneKey(): string {
    return this.portal?.active
      ? `zone_${this.portal.zoneKey}`
      : `zone_${this._player._status.cursor.zone}`;
  }

  /** 移动到指定节点（route 末节点）；标记节点已访问并返回节点 */
  moveTo(route: string[]): GridNode | undefined {
    const zoneKey = this.currentZoneKey();
    const zone = this.zones[zoneKey];
    if (!zone || !route || route.length === 0) return undefined;
    const last = route[route.length - 1];
    const node = zone.nodes[last];
    if (node) {
      // 到达节点：未访问→已访问（state 0/1 → 2），记为变化节点
      if (node.state !== 2) {
        node.state = 2;
        this._changedNodeIds.add(last);
      }
      // 到达节点在地图上也揭示为可见（visibility=NORMAL）；抵达本身由 gridZone state=2 承载，
      // 不再用 visibility 数值表达（官方 visibility 无"到达"专用值）。
      const mapKey = this.mapZoneKeyOf(zoneKey);
      const mapArrived = this._player._map?.zones?.[mapKey]?.nodes?.[last];
      if (
        mapArrived &&
        (mapArrived.visibility ?? ROGUE6_FORESIGHT.HIDE_INVISIBLE) !==
          ROGUE6_FORESIGHT.NORMAL
      ) {
        mapArrived.visibility = ROGUE6_FORESIGHT.NORMAL;
      }
      // 视野：抵达后揭视可达节点——普通节点沿地图边点亮可达路径首节点（1 跳）；
      // 羽瞰点按到羽瞰点的曼哈顿距离照亮，经过后（state 已置 2）为 3，未经过时的默认 2
      // 在进层生成时揭示（见 generate）。
      const lastX = Math.floor(Number(last) / 100);
      const lastY = Number(last) % 100;
      // 羽瞰点：特殊视野，按到羽瞰点的曼哈顿距离照亮（默认 2，经过后 state=2 增为 3）；
      // 普通节点仍沿地图边点亮可达路径首节点（1 跳）。
      if (node.content?.kind === ROGUE6_NODE.RAIN_VIEW) {
        this.revealManhattan(mapKey, zoneKey, lastX, lastY, 3, true);
      } else {
        this.revealReachable(mapKey, zoneKey, lastX, lastY, 1, true);
      }
    }
    return node;
  }

  /**
   * 节点"被经过"衰减：将玩家移走的旧节点改写为林间空地 GLADE（地图类型 + gridZone 类型）。
   * 可反复进入的节点类型（商店类/林间空地/险路尽头/险路小径/曲折密道，见
   * ROGUE6_REVISITABLE_NODES）保持不变。抵达新节点时对刚移走的上一位置调用。
   * @param mapKey _map.zones 键
   * @param zoneKey gridZone 键
   * @param nodeId 被经过的旧节点 id（x*100+y）
   * @returns 是否实际发生了衰减（类型被改写为 GLADE）
   */
  decayPassed(mapKey: string, zoneKey: string, nodeId: string): boolean {
    const zone = this.zones[zoneKey];
    const gzNode = zone?.nodes[nodeId];
    if (!gzNode) return false;
    const kind = gzNode.content?.kind;
    if (typeof kind !== "number" || ROGUE6_REVISITABLE_NODES.includes(kind)) {
      return false;
    }
    gzNode.content = { kind: ROGUE6_NODE.GLADE };
    const mapNode =
      this._player._map?.zones?.[mapKey]?.nodes?.[nodeId];
    if (mapNode) mapNode.type = ROGUE6_NODE.GLADE;
    this._changedNodeIds.add(nodeId);
    return true;
  }

  /**
   * 网格 zone 键（zone_N 常规 / zone_<portalKey> 隐藏层）→ _map.zones 键。
   * 常规层键 = 1000+N-1（与 syncMapZones 一致）；隐藏层 = portal.zoneKey 本身。
   * @param zoneKey gridZone 的 zone 键
   * @returns _map.zones 的对应键
   */
  private mapZoneKeyOf(zoneKey: string): string {
    if (this.portal?.active && zoneKey === `zone_${this.portal.zoneKey}`) {
      return this.portal.zoneKey;
    }
    const zoneId = parseInt(zoneKey.slice("zone_".length), 10);
    return String(1000 + zoneId - 1);
  }

  /**
   * 从节点 (sx,sy) 沿地图边（_map.zones 节点的 next 邻接表）点亮 ≤hops 跳的首段可达节点：
   * 置其 map.zones visibility=NORMAL（揭示可见），按需把 gridZone state 0→1，并入变化节点集合。
   * 供 moveTo 抵达揭示可达路径，以及进入区域时把起点视为“已抵达”揭示起点路径。
   * 揭示为单调（不降级已探索节点：visibility=NORMAL / state=2 不回退）；只取 current hop 的边邻居。
   * @param mapZoneKey _map.zones 键
   * @param zoneKey gridZone 键
   * @param sx 起始 x（x*100+y 节点坐标）
   * @param sy 起始 y
   * @param hops 可达跳数（普通 1；羽瞰点 2）
   * @param markAccessible 是否把揭示节点 gridZone state 0→1（可访问）。normal moveTo 传 true；
   *  进层起点揭示传 false——官服进层后 gridZone 节点 state 只取 0/2（无中间态），仅点亮不升状态
   */
  private revealReachable(
    mapZoneKey: string,
    zoneKey: string,
    sx: number,
    sy: number,
    hops: number,
    markAccessible = false,
  ): void {
    const zone = this.zones[zoneKey];
    const mapNodes = (this._player._map?.zones?.[mapZoneKey]?.nodes ||
      {}) as {
      [id: string]: { next?: { x: number; y: number }[]; visibility?: number };
    };
    if (!zone) return;
    const visited = new Set<string>([this.nodeId(sx, sy)]);
    let frontier: { x: number; y: number }[] = [{ x: sx, y: sy }];
    for (let hop = 1; hop <= hops; hop++) {
      const nextFrontier: { x: number; y: number }[] = [];
      for (const cur of frontier) {
        for (const nb of mapNodes[this.nodeId(cur.x, cur.y)]?.next ?? []) {
          const nid = this.nodeId(nb.x, nb.y);
          if (visited.has(nid)) continue;
          visited.add(nid);
          const gzNode = zone.nodes[nid];
          const mapNode = mapNodes[nid];
          let changed = false;
          // visibility 单调揭示：HIDE（未定义/1/2/3）→ NORMAL(0)；已揭示不回退
          if (
            mapNode &&
            (mapNode.visibility ?? ROGUE6_FORESIGHT.HIDE_INVISIBLE) !==
              ROGUE6_FORESIGHT.NORMAL
          ) {
            mapNode.visibility = ROGUE6_FORESIGHT.NORMAL;
            changed = true;
          }
          if (gzNode && markAccessible && gzNode.state === 0) {
            gzNode.state = 1;
            changed = true;
          }
          if (changed) this._changedNodeIds.add(nid);
          nextFrontier.push(nb);
        }
      }
      frontier = nextFrontier;
    }
  }

  /**
   * 按到起点 (sx,sy) 的曼哈顿距离点亮 zone 内节点（羽瞰点特殊视野）：
   * 曼哈顿距离 = |x-sx|+|y-sy| ≤ radius 的节点置 map.zones visibility=NORMAL（揭示可见），
   * 按需把 gridZone state 0→1，并入变化节点集合。
   * 与 revealReachable（沿地图边）不同，此处以到羽瞰点的曼哈顿半径铺开，
   * 不要求边连通；揭示为单调（不降级已探索节点）。
   * @param mapZoneKey _map.zones 键
   * @param zoneKey gridZone 键
   * @param sx 羽瞰点 x（x*100+y 节点坐标）
   * @param sy 羽瞰点 y
   * @param radius 曼哈顿距离半径（默认 2；经过后 3）
   * @param markAccessible 是否把揭示节点 gridZone state 0→1（可访问）
   */
  private revealManhattan(
    mapZoneKey: string,
    zoneKey: string,
    sx: number,
    sy: number,
    radius: number,
    markAccessible = false,
  ): void {
    const zone = this.zones[zoneKey];
    if (!zone) return;
    const mapNodes = (this._player._map?.zones?.[mapZoneKey]?.nodes ||
      {}) as {
      [id: string]: { visibility?: number };
    };
    for (const nid of Object.keys(zone.nodes)) {
      const x = Math.floor(Number(nid) / 100);
      const y = Number(nid) % 100;
      if (Math.abs(x - sx) + Math.abs(y - sy) > radius) continue;
      const mapNode = mapNodes[nid];
      const gzNode = zone.nodes[nid];
      let changed = false;
      // visibility 单调揭示：HIDE（未定义/1/2/3）→ NORMAL(0)；已揭示不回退
      if (
        mapNode &&
        (mapNode.visibility ?? ROGUE6_FORESIGHT.HIDE_INVISIBLE) !==
          ROGUE6_FORESIGHT.NORMAL
      ) {
        mapNode.visibility = ROGUE6_FORESIGHT.NORMAL;
        changed = true;
      }
      if (gzNode && markAccessible && gzNode.state === 0) {
        gzNode.state = 1;
        changed = true;
      }
      if (changed) this._changedNodeIds.add(nid);
    }
  }

  /**
   * 开始一次移动请求的变化节点收集（清空上次遗留，界定请求边界）。
   * 由控制器在一条 route 落格前调用。
   */
  beginMove(): void {
    this._changedNodeIds = new Set();
  }

  /**
   * 取走并清空本次移动请求发生状态/视野变化的节点 id 列表（rlv2NodeChange.nodeList）。
   * @returns 变化节点 id 数组（保持插入顺序，Set 迭代序）
   */
  takeChangedNodes(): string[] {
    const out = [...this._changedNodeIds];
    this._changedNodeIds = new Set();
    return out;
  }

  toJSON(): {
    zones: { [key: string]: GridZone };
    stepRemain: number;
    needConfirmStepZero: boolean;
    portal?: GridPortalState | null;
  } {
    // 官方 gridZone 节点 content：地图生成（finishEvent）时全为 {}——战斗信息由 map.zones 提供；
    // 商店节点进入后 content 变为 { shop: { goods } }。savage/kind 为内部标记（战斗触发用），
    // 序列化时剥离（客户端不识别 savage/kind，多余字段解析异常；shop 保留）
    const strip = (n: GridNode): GridNode => {
      const c: any = {};
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
    const out: {
      zones: { [key: string]: GridZone };
      stepRemain: number;
      needConfirmStepZero: boolean;
      portal?: GridPortalState;
    } = {
      zones,
      stepRemain: this.stepRemain,
      needConfirmStepZero: this.needConfirmStepZero,
    };
    // portal 状态仅活动（隐藏层中）时输出——官服线格式无此字段，开局/常规状态严格比对不允许多余键
    if (this.portal?.active) out.portal = this.portal;
    return out;
  }
}
