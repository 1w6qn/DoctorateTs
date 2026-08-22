import { describe, it, expect, vi } from "vitest";

// ===== rogue_6（黑流树海）节点分发与主题规则回归 =====
// 覆盖本轮修复：
// 1. gridZoneMoveTo 的事件节点分发（安全的角落/得偿所愿/失与得/先行一步/狭路相逢/
//    应急助力/险路小径/险路尽头）——原实现仅 MIRAGE/PROPHECY/INCIDENT 有分支，
//    其余节点全部退化为空节点（triggerNodeEvent 定义但零调用）
// 2. 先行一步（EXPEDITION）→ scene_ro6_scout_enter 三结局入口可达
// 3. 节点到达推送（rlv2NodeArrive / rlv2NodeChange）在 gridZone 移动时累积
// 4. 精英/首领节点使用各自关卡池（原 eliteStages 计算后未使用）
// 5. rerollNode 兼容黑流树海 map.zones 键（1000+）且支持 rogue_6 节点类型
// 6. 废品估价取官方 sellPrice（原恒为 1）
// 7. 误入奇境消耗 MOVE 型（官方 scrapTypeData：MOVE=加工品）
const excelMock = vi.hoisted(() => ({
  RoguelikeTopicTable: {
    details: {
      rogue_6: {
        init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
        stages: {
          ro6_n_3_1: { id: "ro6_n_3_1" },
          ro6_n_3_2: { id: "ro6_n_3_2" },
          ro6_e_3_1: { id: "ro6_e_3_1" },
          ro6_e_3_2: { id: "ro6_e_3_2" },
          ro6_b_3: { id: "ro6_b_3" },
          ro6_b_3_b: { id: "ro6_b_3_b" },
        },
        items: {
          rogue_6_scrap_M_01: { id: "rogue_6_scrap_M_01", type: "SCRAP", rarity: "NORMAL" },
          rogue_6_scrap_G_02: { id: "rogue_6_scrap_G_02", type: "SCRAP", rarity: "NORMAL" },
        },
        // 各节点类型对应的官方 enter 场景 + 选项（截取真实 id 命名）
        choiceScenes: {
          scene_ro6_rest_enter: { id: "scene_ro6_rest_enter", title: "金色凝滞" },
          scene_ro6_wish_enter: { id: "scene_ro6_wish_enter", title: "无人商店" },
          scene_ro6_sacrifice1_enter: { id: "scene_ro6_sacrifice1_enter", title: "回滚文明" },
          scene_ro6_scout_enter: { id: "scene_ro6_scout_enter", title: "未涉足之树" },
          scene_ro6_sala1_enter: { id: "scene_ro6_sala1_enter", title: "原始娱乐" },
          scene_ro6_hire1_enter: { id: "scene_ro6_hire1_enter", title: "临时中介所" },
          scene_ro6_final1_enter: { id: "scene_ro6_final1_enter", title: "险路尽头" },
          scene_ro6_evacuate_enter: { id: "scene_ro6_evacuate_enter", title: "三重身" },
          scene_ro6_normal1_enter: { id: "scene_ro6_normal1_enter", title: "沉寂之屋" },
        },
        choices: {
          choice_ro6_rest_1: { id: "choice_ro6_rest_1", type: "TRADE" },
          choice_ro6_rest_2: { id: "choice_ro6_rest_2", type: "TRADE" },
          choice_ro6_wish_1: { id: "choice_ro6_wish_1", type: "TRADE_PROB_SHOW" },
          choice_ro6_sacrifice1_1: { id: "choice_ro6_sacrifice1_1", type: "SACRIFICE" },
          choice_ro6_scout_1: { id: "choice_ro6_scout_1", type: "EXPEDITION" },
          choice_ro6_scout_3: { id: "choice_ro6_scout_3", type: "EXPEDITION" },
          choice_ro6_sala1_1: { id: "choice_ro6_sala1_1", type: "NEXT" },
          choice_ro6_hire1_1: { id: "choice_ro6_hire1_1", type: "TRADE" },
          choice_ro6_final1_3: { id: "choice_ro6_final1_3", type: "ZONE_END" },
          choice_ro6_evacuate_4: { id: "choice_ro6_evacuate_4", type: "ZONE_END" },
          choice_ro6_normal1_1: { id: "choice_ro6_normal1_1", type: "TRADE" },
        },
        // 重掷节点：官方仅隐藏层配置，此处给常规区一组用于验证键与类型映射
        rollNodeData: {
          zone_3: {
            zoneId: "zone_3",
            groups: { SCRAP_SHOP: { nodeType: "SCRAP_SHOP" } },
          },
        },
      },
    },
    modules: {
      rogue_6: {
        moduleTypes: ["GRID_ZONE", "SCRAP"],
        scrap: {
          moduleConsts: { identifyScrapId: "rogue_6_scrap_M_01" },
          moveScrapData: {
            rogue_6_scrap_M_01: { scrapId: "rogue_6_scrap_M_01", sellPrice: 1 },
          },
          goodsScrapData: {
            rogue_6_scrap_G_02: { scrapId: "rogue_6_scrap_G_02", sellPrice: 2 },
          },
          scrapItemToType: {
            rogue_6_scrap_M_01: "MOVE",
            rogue_6_scrap_G_02: "GOODS",
          },
        },
      },
    },
    consts: {},
  },
  CharacterTable: {},
  GameDataConst: { maxLevel: [[], [], [], [], [], []] },
}));

vi.mock("@excel/excel", () => ({ default: excelMock }));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import {
  ROGUE6_NODE,
  ROGUE6_NODE_SCENE_PREFIX,
  ROLL_NODE_TYPE_VALUES,
  isBlackstream,
} from "@game/controller/rlv2/theme-rules";

function makePlayer() {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { rogue_6: {} } as any,
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: {
      missions: { DAILY: {}, ACTIVITY: {} },
      missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} },
    } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = {
    theme: "rogue_6",
    mode: "NORMAL",
    modeGrade: 0,
  } as any;
  return player;
}

/**
 * 在 zone 3 生成地图后，把指定节点改为给定类型并移动到该节点。
 * @returns 落地后的 pending 事件列表与状态
 */
async function moveToNodeOfType(
  player: PlayerDataManager,
  kind: number,
): Promise<{ pending: any[]; state: string }> {
  const rlv2 = player.rlv2 as any;
  const gz = rlv2._module.gridZone;
  gz.generate([3]);
  rlv2._status.cursor.zone = 3;
  const inner = gz.zones["zone_3"].nodes;
  const id = Object.keys(inner)[1];
  // 改内部节点为目标类型（清掉战斗/商店内容，只留 kind）
  inner[id].content = { kind };
  rlv2._status.cursor.position = {
    x: Math.floor(Number(id) / 100),
    y: Number(id) % 100,
  };
  await rlv2.gridZoneMoveTo({ route: [id] });
  return { pending: rlv2._status.pending, state: rlv2._status.state };
}

describe("rogue_6 事件节点分发（gridZoneMoveTo）", () => {
  it.each([
    ["安全的角落", ROGUE6_NODE.REST, /^scene_ro6_rest_enter$/],
    ["得偿所愿", ROGUE6_NODE.WISH, /^scene_ro6_(wish|relic\d*)_enter$/],
    ["失与得", ROGUE6_NODE.SACRIFICE, /^scene_ro6_sacrifice\d*_enter$/],
    ["先行一步", ROGUE6_NODE.EXPEDITION, /^scene_ro6_scout_enter$/],
    ["狭路相逢", ROGUE6_NODE.FACE_OFF, /^scene_ro6_sala\d*_enter$/],
    ["应急助力", ROGUE6_NODE.EMERGENCY_AID, /^scene_ro6_hire\d*_enter$/],
    ["险路尽头", ROGUE6_NODE.VISIBLE_END, /^scene_ro6_final\d*_enter$/],
    ["险路小径", ROGUE6_NODE.VISIBLE_PATH, /^scene_ro6_evacuate\d*_enter$/],
  ])(
    "%s 节点落地生成 SCENE 事件（原实现退化为空节点）",
    async (_name, kind, scenePattern) => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const { pending, state } = await moveToNodeOfType(player, kind);
      expect(state).toBe("PENDING");
      expect(pending.length).toBeGreaterThan(0);
      expect(pending[0].type).toBe("SCENE");
      expect(pending[0].content.scene.id).toMatch(scenePattern);
      // 选项非空（客户端需要至少一个可选项才能推进）
      expect(
        Object.keys(pending[0].content.scene.choices).length,
      ).toBeGreaterThan(0);
    },
  );

  it("先行一步选项含 choice_ro6_scout_1/3（三结局入口可达）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const { pending } = await moveToNodeOfType(player, ROGUE6_NODE.EXPEDITION);
    const choices = Object.keys(pending[0].content.scene.choices);
    expect(choices).toContain("choice_ro6_scout_1");
    expect(choices).toContain("choice_ro6_scout_3");
  });

  it("不期而遇未触发线人时回退通用场景（normal 幕）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    // Math.random=0.9：线人概率判定（<0.4）不通过 → 走通用不期而遇场景
    const spy = vi.spyOn(Math, "random").mockReturnValue(0.9);
    try {
      const { pending, state } = await moveToNodeOfType(
        player,
        ROGUE6_NODE.INCIDENT,
      );
      expect(state).toBe("PENDING");
      expect(pending[0].content.scene.id).toMatch(
        /^scene_ro6_(normal|bat)\d*_enter$/,
      );
    } finally {
      spy.mockRestore();
    }
  });

  it("林间空地/曲折密道/羽瞰点仍为空节点（WAIT_MOVE，官方 subName 为空白/传送/视野）", async () => {
    for (const kind of [
      ROGUE6_NODE.GLADE,
      ROGUE6_NODE.TUNNEL,
      ROGUE6_NODE.RAIN_VIEW,
    ]) {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const { state, pending } = await moveToNodeOfType(player, kind);
      expect(state, `kind ${kind}`).toBe("WAIT_MOVE");
      expect(pending.length, `kind ${kind}`).toBe(0);
    }
  });
});

describe("rogue_6 节点到达推送（pushMessage）", () => {
  it("gridZone 移动累积 rlv2NodeArrive + rlv2NodeChange（原实现永不下发）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    await moveToNodeOfType(player, ROGUE6_NODE.GLADE);
    const msgs = (player.rlv2 as any).takePushMessages();
    const paths = msgs.map((m: any) => m.path);
    expect(paths).toContain("rlv2NodeArrive");
    expect(paths).toContain("rlv2NodeChange");
    const arrive = msgs.find((m: any) => m.path === "rlv2NodeArrive");
    expect((arrive!.payload as any).nodeType).toBe(ROGUE6_NODE.GLADE);
    const change = msgs.find((m: any) => m.path === "rlv2NodeChange");
    expect(
      Array.isArray((change!.payload as any).nodeList),
    ).toBe(true);
    // 取走后清空（避免残留累积到下一请求）
    expect((player.rlv2 as any).takePushMessages().length).toBe(0);
  });

  it("rlv2NodeChange.nodeList 只含发生变化的节点（到达节点+新揭示邻居），非整层全量（官服抓包 R-1786531228496.9993-3674）", async () => {
    // 固定随机：构造模板/关卡/节点类型稳定；用单格 moveTo 直接验证变化节点集合
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const rlv2 = player.rlv2 as any;
    const gz = rlv2._module.gridZone;
    gz.beginMove();
    // 手工铺一张平铺网格：0,0 起点（已访问）；目标节点 100 → 到达后按地图边点亮
    // 可达首节点（边连 0/200/101）。断言 nodeList = 到达节点 + 实际发生状态/视野变化的
    // 边可达邻居，且不含非边连接（曼哈顿相邻但未连通）的 1/2。
    gz.zones = {
      zone_3: {
        nodes: {
          "0": { content: { kind: ROGUE6_NODE.GLADE }, state: 2, show: true },
          "1": { content: { kind: ROGUE6_NODE.BATTLE_NORMAL }, state: 0, show: false },
          "2": { content: { kind: ROGUE6_NODE.INCIDENT }, state: 0, show: false },
          "100": { content: { kind: ROGUE6_NODE.BATTLE_NORMAL }, state: 0, show: true },
          "101": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
          "200": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
        },
      },
    };
    // 沿边可达揭示 visibility：设置 map.zones 邻接（100 边连 0/200/101）供 moveTo 按边揭示。
    // 起点 0 已揭示（visibility=NORMAL），抵达 100 后 200/101 由 HIDE_INVISIBLE → NORMAL，
    // 起点不降级、1/2 非边连接不入列。
    (rlv2._map as any).zones["1002"] = {
      nodes: {
        "0": { next: [{ x: 1, y: 0 }], visibility: 0 },
        "100": { next: [{ x: 0, y: 0 }, { x: 2, y: 0 }, { x: 1, y: 1 }], visibility: 1 },
      },
    };
    rlv2._status.cursor.zone = 3;
    rlv2.beginMove?.();
    gz.moveTo(["100"]);
    const changed = gz.takeChangedNodes();
    expect(changed).toContain("100"); // 到达节点：0 → 2
    expect(changed).toContain("101"); // 距离 1 邻居（x1,y1）：0 → 1（可见+可访问）
    expect(changed).toContain("200"); // 距离 1 邻居（x2,y0）：0 → 1
    expect(changed).not.toContain("1"); // 距离 2（x0,y1）：超出视野，不揭示
    expect(changed).not.toContain("2"); // 距离 3（x0,y2）：超出视野，不揭示
    // 已访问起点 0（state 2 / show 已有）不重复进变化集
    expect(changed).not.toContain("0");
    // nodeList 必须反映真实变化（否则退回归漏、全量兜底回归）
    expect(changed.length).toBe(3);
    // beginMove 界定边界：第二次未变化移动不再累积
    gz.beginMove();
    gz.moveTo(["100"]);
    expect(gz.takeChangedNodes()).toEqual([]);
  });

  it("羽瞰点经过后按到羽瞰点的曼哈顿距离照亮 3（普通节点仅沿边 1 跳）", async () => {
    // 布局：0(起点) 直链边连 100 - 200 - 300；另有 101(1,1)/103(1,3) 不与任何边连通。
    // 羽瞰点 100（抵达即经过，state→2）视野半径 3：按曼哈顿距离铺开，
    // 101(距1)、200(距1)、300(距2)、103(距3) 全部点亮——含无边连接的 101/103。
    // 普通节点 1 跳：沿地图边只点亮直链邻居 200，无边连接的 101/103 与距离 2 的 300 不亮。
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const rlv2 = player.rlv2 as any;
    const gz = rlv2._module.gridZone;
    const layer = (zoneKey: string, kind: number) => {
      gz.beginMove();
      gz.zones = {
        [zoneKey]: {
          nodes: {
            "0": { content: { kind: ROGUE6_NODE.GLADE }, state: 2, show: true },
            "100": { content: { kind }, state: 1, show: true },
            "200": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
            "300": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
            "101": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
            "103": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
          },
        },
      };
      // map.zones 邻接：仅直链 0-100-200-300；101/103 无边（next 空）。
      // visibility 官方枚举语义：0=NORMAL 已揭示，1=HIDE_INVISIBLE 未揭示。
      (rlv2._map as any).zones["1003"] = {
        nodes: {
          "0": { next: [{ x: 1, y: 0 }], visibility: 0 },
          "100": { next: [{ x: 0, y: 0 }, { x: 2, y: 0 }], visibility: 1 },
          "200": { next: [{ x: 1, y: 0 }, { x: 3, y: 0 }], visibility: 1 },
          "300": { next: [{ x: 2, y: 0 }], visibility: 1 },
          "101": { next: [], visibility: 1 },
          "103": { next: [], visibility: 1 },
        },
      };
      rlv2._status.cursor.zone = 4;
      gz.beginMove();
      gz.moveTo(["100"]);
    };
    const mapOf = () => (rlv2._map as any).zones["1003"].nodes;

    // 羽瞰点：曼哈顿距离 ≤3（101/200 距1、300 距2、103 距3）全部揭示为 NORMAL(0)
    layer("zone_4", ROGUE6_NODE.RAIN_VIEW);
    let changed = gz.takeChangedNodes();
    expect(changed).toContain("100");
    expect(changed).toContain("200");
    expect(changed).toContain("300");
    expect(changed).toContain("101"); // 无边连接，但距羽瞰点 1 → 曼哈顿揭示
    expect(changed).toContain("103"); // 距羽瞰点 3 → 半径 3 内
    expect(mapOf()["101"].visibility).toBe(0);
    expect(mapOf()["103"].visibility).toBe(0);

    // 普通节点：沿地图边 1 跳，仅直链邻居 200 揭示；101/103 无边、300 距离 2 均保持 HIDE_INVISIBLE(1)
    layer("zone_4", ROGUE6_NODE.BATTLE_NORMAL);
    changed = gz.takeChangedNodes();
    expect(changed).toContain("200");
    expect(changed).not.toContain("300");
    expect(changed).not.toContain("101");
    expect(changed).not.toContain("103");
    expect(mapOf()["300"].visibility).toBe(1);
    expect(mapOf()["101"].visibility).toBe(1);
  });

  it("进层生成时羽瞰点默认按曼哈顿距离 2 点亮（3 处距离不点）", async () => {
    // 构造一个羽瞰点身处其中、周围曼哈顿距离 2/3 的节点混布的 zone。
    // 直接校验 generate 后 map.zones 的 visibility：羽瞰点 2 半径内揭示为 NORMAL(0)，半径 3 保持 HIDE_INVISIBLE(1)。
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const rlv2 = player.rlv2 as any;
    const gz = rlv2._module.gridZone;
    // 放入羽瞰点 200(2,0)，其曼哈顿距离：300(3,0) 距1、400(4,0) 距2、500(5,0) 距3
    gz.zones = {
      zone_4: {
        nodes: {
          "0": { content: { kind: ROGUE6_NODE.GLADE }, state: 2, show: true },
          "200": { content: { kind: ROGUE6_NODE.RAIN_VIEW }, state: 0, show: true },
          "300": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
          "400": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
          "500": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: false },
        },
      },
    };
    (rlv2._map as any).zones["1003"] = {
      nodes: {
        "0": { next: [{ x: 2, y: 0 }], visibility: 0 },
        "200": { next: [{ x: 0, y: 0 }, { x: 3, y: 0 }], visibility: 1 },
        "300": { next: [{ x: 2, y: 0 }, { x: 4, y: 0 }], visibility: 1 },
        "400": { next: [{ x: 3, y: 0 }, { x: 5, y: 0 }], visibility: 1 },
        "500": { next: [{ x: 4, y: 0 }], visibility: 1 },
      },
    };
    // 触发 generate 的羽瞰点默认揭示逻辑
    gz.beginMove();
    gz.revealManhattan("1003", "zone_4", 2, 0, 2);
    const mapNodes = (rlv2._map as any).zones["1003"].nodes;
    expect(mapNodes["300"].visibility).toBe(0); // 距1 → NORMAL
    expect(mapNodes["400"].visibility).toBe(0); // 距2 → NORMAL
    expect(mapNodes["500"].visibility).toBe(1); // 距3 → 半径 2 之外，保持 HIDE_INVISIBLE
  });
});

describe("rogue_6 关卡池按节点类型分流（eliteStages 修复）", () => {
  it("紧急作战取 ro6_e_*、险路恶敌取 ro6_b_*、作战取 ro6_n_*", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const gz = (player.rlv2 as any)._module.gridZone;
    const pools = { normal: ["ro6_n_3_1"], elite: ["ro6_e_3_1"], boss: ["ro6_b_3"] };
    expect(
      gz.makeContentNode(ROGUE6_NODE.BATTLE_NORMAL, pools).content.savage.stageId,
    ).toBe("ro6_n_3_1");
    expect(
      gz.makeContentNode(ROGUE6_NODE.BATTLE_ELITE, pools).content.savage.stageId,
    ).toBe("ro6_e_3_1");
    expect(
      gz.makeContentNode(ROGUE6_NODE.BATTLE_BOSS, pools).content.savage.stageId,
    ).toBe("ro6_b_3");
  });

  it("生成 zone 3 时精英节点的关卡来自 e 池、boss 节点来自 b 池", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const gz = (player.rlv2 as any)._module.gridZone;
    gz.generate([3]);
    const mapNodes = (player.rlv2 as any)._map.zones["1002"].nodes;
    for (const n of Object.values(mapNodes) as any[]) {
      if (n.type === ROGUE6_NODE.BATTLE_ELITE) {
        expect(n.stage, `elite ${n.index}`).toMatch(/^ro6_e_3_/);
      }
      if (n.type === ROGUE6_NODE.BATTLE_BOSS) {
        expect(n.stage, `boss ${n.index}`).toMatch(/^ro6_b_3/);
      }
      if (n.type === ROGUE6_NODE.BATTLE_NORMAL) {
        expect(n.stage, `normal ${n.index}`).toMatch(/^ro6_n_3_/);
      }
    }
  });
});

describe("rogue_6 重掷节点（rerollNode 键与类型映射修复）", () => {
  it("按 1000+ 键取到节点并写入 rogue_6 节点类型（原实现静默失效）", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2._module.create();
    const gz = rlv2._module.gridZone;
    gz.generate([3]);
    rlv2._status.cursor.zone = 3;
    const mapZone = rlv2._map.zones["1002"];
    // rollNodeData 按 map zone 的 id 匹配（zone_3）
    expect(mapZone.id).toBe("zone_3");
    const nodeIndex = Object.keys(mapZone.nodes)[0];
    await rlv2.rerollNode({ nodeIndex });
    // 官方 groups 仅 SCRAP_SHOP → 秘境行商（2097152），原 typeMap 无此项会退化为 1
    expect(mapZone.nodes[nodeIndex].type).toBe(ROGUE6_NODE.SECRET_SHOP);
  });
});

describe("rogue_6 废品估价（官方 sellPrice）", () => {
  it("gain 的废品 value 取官方 sellPrice，而非恒为 1", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const scrap = (player.rlv2 as any)._module.scrap;
    await (player.rlv2 as any)._trigger.emit("rlv2:scrap:gain", [
      "rogue_6_scrap_G_02",
    ]);
    const gained = Object.values(scrap.inventory).find(
      (it: any) => it.id === "rogue_6_scrap_G_02",
    ) as any;
    expect(gained).toBeTruthy();
    expect(gained.value).toBe(2); // goodsScrapData.sellPrice
  });

  it("开局 s_1/s_2 取 moduleConsts.identifyScrapId 与其 sellPrice", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const scrap = (player.rlv2 as any)._module.scrap;
    expect(scrap.inventory["s_1"].id).toBe("rogue_6_scrap_M_01");
    expect(scrap.inventory["s_1"].value).toBe(1); // moveScrapData.sellPrice
  });
});

describe("主题规则注册表（theme-rules）", () => {
  it("isBlackstream 仅对 rogue_6 为真", () => {
    expect(isBlackstream("rogue_6")).toBe(true);
    expect(isBlackstream("rogue_5")).toBe(false);
    expect(isBlackstream(undefined)).toBe(false);
  });

  it("节点数值与官方 nodeTypeData 键一致（21 项）", () => {
    // 官方 details.rogue_6.nodeTypeData 的键集合
    const official = [
      1, 2, 4, 16, 32, 512, 1024, 2048, 4096, 8192, 32768, 65536, 262144,
      2097152, 4194304, 8388608, 16777216, 33554432, 67108864, 134217728,
      268435456,
    ];
    const mine = Object.values(ROGUE6_NODE).sort((a, b) => a - b);
    expect(mine).toEqual(official.sort((a, b) => a - b));
  });

  it("场景前缀表不含地图机制类节点（曲折密道/羽瞰点/林间空地）", () => {
    expect(ROGUE6_NODE_SCENE_PREFIX[ROGUE6_NODE.TUNNEL]).toBeUndefined();
    expect(ROGUE6_NODE_SCENE_PREFIX[ROGUE6_NODE.RAIN_VIEW]).toBeUndefined();
    expect(ROGUE6_NODE_SCENE_PREFIX[ROGUE6_NODE.GLADE]).toBeUndefined();
  });

  it("重掷类型映射覆盖 rogue_6 专属类型（原 typeMap 缺失 → 退化为作战）", () => {
    expect(ROLL_NODE_TYPE_VALUES.SCRAP_SHOP).toBe(ROGUE6_NODE.SECRET_SHOP);
    expect(ROLL_NODE_TYPE_VALUES.STORY).toBe(ROGUE6_NODE.PROPHECY);
    expect(ROLL_NODE_TYPE_VALUES.DUEL).toBe(ROGUE6_NODE.FACE_OFF);
    expect(ROLL_NODE_TYPE_VALUES.EMPLOY).toBe(ROGUE6_NODE.EMERGENCY_AID);
    expect(ROLL_NODE_TYPE_VALUES.FINAL).toBe(ROGUE6_NODE.VISIBLE_END);
    expect(ROLL_NODE_TYPE_VALUES.EMPTY).toBe(ROGUE6_NODE.GLADE);
  });
});

// ===== 新增 pushMessage 类型（对应官方 Rolggelike*Trigger）=====
describe("rogue_6 新增 pushMessage 类型", () => {
  it("废品 gain → rlv2GotRandScrap{idList}", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    // 先取走创建期可能累积的推送，保证断言针对本次 gain
    (player.rlv2 as any).takePushMessages();
    await (player.rlv2 as any)._trigger.emit("rlv2:scrap:gain", [
      "rogue_6_scrap_G_02",
    ]);
    const msgs = (player.rlv2 as any).takePushMessages();
    const scor = msgs.find((m: any) => m.path === "rlv2GotRandScrap");
    expect(scor).toBeTruthy();
    expect((scor!.payload as any).idList).toEqual(["rogue_6_scrap_G_02"]);
  });

  it("changeVehicle 切载具/回步行 → rlv2VehicleChange{}", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const scrap = (player.rlv2 as any)._module.scrap;
    (player.rlv2 as any).takePushMessages();
    // 开局步行 → 切到已持有的 MOVE 载具
    scrap.changeVehicle("s_1");
    let msgs = (player.rlv2 as any).takePushMessages();
    expect(msgs.map((m: any) => m.path)).toContain("rlv2VehicleChange");
    // 切回步行再触发一次
    scrap.changeVehicle("");
    msgs = (player.rlv2 as any).takePushMessages();
    expect(msgs.map((m: any) => m.path)).toContain("rlv2VehicleChange");
    // 无变化（当前已是该载具，重复切同一载具）不再推送
    scrap.changeVehicle("s_1"); // walk→s_1 有效变更
    (player.rlv2 as any).takePushMessages(); // 排空
    scrap.changeVehicle("s_1"); // 已在该载具 → 无变化
    expect((player.rlv2 as any).takePushMessages().length).toBe(0);
  });

  it("setLimit 扩容 → rlv2LevelUpMaxWeight{count}；缩减 → rlv2WeightWorse{}", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const scrap = (player.rlv2 as any)._module.scrap;
    (player.rlv2 as any).takePushMessages();
    scrap.setLimit(12);
    let msgs = (player.rlv2 as any).takePushMessages();
    const up = msgs.find((m: any) => m.path === "rlv2LevelUpMaxWeight");
    expect(up).toBeTruthy();
    expect((up!.payload as any).count).toBe(2);
    scrap.setLimit(8);
    msgs = (player.rlv2 as any).takePushMessages();
    expect(msgs.map((m: any) => m.path)).toContain("rlv2WeightWorse");
    // 容量不变不推送
    scrap.setLimit(8);
    expect((player.rlv2 as any).takePushMessages().length).toBe(0);
  });

  it("非 rogue_6 主题下 pushMessage 静默跳过（不改污染收集器）", async () => {
    const player = makePlayer();
    (player.rlv2 as any).current.game.theme = "rogue_5";
    player.rlv2.pushMessage("rlv2VehicleChange", {});
    expect((player.rlv2 as any).takePushMessages().length).toBe(0);
  });
});

describe("rogue_6 经过后节点衰减为林间空地（decayPassed）", () => {
  // 主力验证 grid_zone.decayPassed 的类型改写：
  // 普通节点被经过 → gridZone/map 均变 GLADE；可反复进入类节点保持不变。
  it("普通节点被移走后变为林间空地（gridZone 与 map 类型同步）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const rlv2 = player.rlv2 as any;
    const gz = rlv2._module.gridZone;
    gz.zones = {
      zone_3: {
        nodes: {
          "100": { content: { kind: ROGUE6_NODE.BATTLE_NORMAL }, state: 2, show: true },
          "200": { content: { kind: ROGUE6_NODE.REST }, state: 0, show: true },
        },
      },
    };
    (rlv2._map as any).zones["1002"] = {
      nodes: {
        "100": { next: [{ x: 2, y: 0 }], visibility: 0, type: ROGUE6_NODE.BATTLE_NORMAL },
        "200": { next: [{ x: 1, y: 0 }], visibility: 1, type: ROGUE6_NODE.REST },
      },
    };
    expect(gz.decayPassed("1002", "zone_3", "100")).toBe(true);
    expect(gz.zones["zone_3"].nodes["100"].content.kind).toBe(ROGUE6_NODE.GLADE);
    expect((rlv2._map as any).zones["1002"].nodes["100"].type).toBe(ROGUE6_NODE.GLADE);
    // decayPassed 不改 visibility；100 已揭示（NORMAL=0）
    expect((rlv2._map as any).zones["1002"].nodes["100"].visibility).toBe(0);
  });

  it("可反复进入类节点（商店/林间空地/尽头/小径/密道）经过后保持原类型", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const rlv2 = player.rlv2 as any;
    const gz = rlv2._module.gridZone;
    const revisit = [
      ROGUE6_NODE.SHOP,
      ROGUE6_NODE.SECRET_SHOP,
      ROGUE6_NODE.EMERGENCY_AID,
      ROGUE6_NODE.GLADE,
      ROGUE6_NODE.VISIBLE_END,
      ROGUE6_NODE.VISIBLE_PATH,
      ROGUE6_NODE.TUNNEL,
    ];
    gz.zones = { zone_3: { nodes: {} } };
    (rlv2._map as any).zones["1002"] = { nodes: {} };
    revisit.forEach((kind, i) => {
      const id = String((i + 1) * 100);
      gz.zones["zone_3"].nodes[id] = { content: { kind }, state: 2, show: true };
      (rlv2._map as any).zones["1002"].nodes[id] = { type: kind, visibility: 0 };
    });
    revisit.forEach((kind, i) => {
      const id = String((i + 1) * 100);
      expect(gz.decayPassed("1002", "zone_3", id)).toBe(false);
      expect(gz.zones["zone_3"].nodes[id].content.kind).toBe(kind);
      expect((rlv2._map as any).zones["1002"].nodes[id].type).toBe(kind);
    });
  });

  it("gridZoneMoveTo：移动后上一位置普通节点变 GLADE 并进入 nodeList", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const rlv2 = player.rlv2 as any;
    const gz = rlv2._module.gridZone;
    // 起点 0 已访问（GLADE）；目标 100 为普通作战；玩家起点在 0 → 移动到 100
    gz.zones = {
      zone_3: {
        nodes: {
          "0": { content: { kind: ROGUE6_NODE.GLADE }, state: 2, show: true },
          "100": { content: { kind: ROGUE6_NODE.BATTLE_NORMAL }, state: 0, show: true },
          "200": { content: { kind: ROGUE6_NODE.GLADE }, state: 0, show: true },
        },
      },
    };
    (rlv2._map as any).zones["1002"] = {
      nodes: {
        "0": { next: [{ x: 1, y: 0 }], visibility: 0, type: ROGUE6_NODE.GLADE },
        "100": { next: [{ x: 0, y: 0 }, { x: 2, y: 0 }], visibility: 1, type: ROGUE6_NODE.BATTLE_NORMAL },
        "200": { next: [{ x: 1, y: 0 }], visibility: 1, type: ROGUE6_NODE.GLADE },
      },
    };
    rlv2._status.cursor.zone = 3;
    rlv2._status.cursor.position = { x: 0, y: 0 };
    gz.beginMove();
    await rlv2.gridZoneMoveTo({ route: ["100"] });
    // 抵达 100 后，起点 0 为 GLADE（本来就 GLADE，不衰减）；无中途节点 → 无衰减
    expect((rlv2._map as any).zones["1002"].nodes["100"].type).toBe(ROGUE6_NODE.BATTLE_NORMAL);
    expect((rlv2._map as any).zones["1002"].nodes["0"].type).toBe(ROGUE6_NODE.GLADE);
  });
});
