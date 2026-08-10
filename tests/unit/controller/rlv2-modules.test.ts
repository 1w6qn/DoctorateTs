import { describe, it, expect, vi, beforeEach } from "vitest";
import { enablePatches } from "immer";

enablePatches();

vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_6: {
          stages: {
            ro6_n_1_1: { id: "ro6_n_1_1" },
            ro6_n_1_2: { id: "ro6_n_1_2" },
            ro6_n_2_1: { id: "ro6_n_2_1" },
          },
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
        },
        rogue_5: {
          stages: {},
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          items: { rogue_5_gold: { id: "rogue_5_gold", type: "GOLD" } },
        },
      },
      modules: {
        rogue_6: {
          moduleTypes: ["GRID_ZONE", "WEATHER", "SCRAP"],
          weather: {
            mainWeatherData: {
              rogue_6_weather_1_a: { id: "rogue_6_weather_1_a", level: 1 },
              rogue_6_weather_1_b: { id: "rogue_6_weather_1_b", level: 2 },
              rogue_6_weather_1_c: { id: "rogue_6_weather_1_c", level: 3 },
              rogue_6_weather_2_a: { id: "rogue_6_weather_2_a", level: 1 },
            },
            subWeatherData: {
              rogue_6_subweather_1: { id: "rogue_6_subweather_1" },
            },
          },
          scrap: {
            scrapItemToType: {
              rogue_6_scrap_M_01: "MOVE",
              rogue_6_scrap_G_01: "GOODS",
            },
          },
        },
        rogue_5: {
          moduleTypes: ["COPPER", "WRATH", "SKY"],
          copper: {
            copperData: {
              rogue_5_copper_P_01: { id: "rogue_5_copper_P_01" },
              rogue_5_copper_R_01: { id: "rogue_5_copper_R_01" },
              rogue_5_copper_F_01: { id: "rogue_5_copper_F_01" },
            },
          },
        },
        rogue_3: {
          moduleTypes: ["CHAOS", "VISION", "TOTEMBUFF"],
        },
        rogue_2: {
          stages: {},
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
        },
      },
      consts: {},
    },
    CharacterTable: {},
    GameDataConst: { maxLevel: [[], [], [], [], [], []] },
  },
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";

function makePlayer(theme: string) {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { [theme]: {} } as any,
      current: {},
      pinned: {},
    } as any,
    inventory: {} as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = {
    theme,
    mode: "NORMAL",
    modeGrade: 0,
  } as any;
  return player;
}

/** 触发 module.create()（按主题 moduleTypes 实例化管理器；rlv2:module:init 异步重置后初始化开局状态） */
async function createModules(player: PlayerDataManager) {
  await (player.rlv2 as any)._module.create();
  return player;
}

describe("rlv2 主题模块管理器（2026-08-10）", () => {
  describe("GRID_ZONE（rogue_6）", () => {
    it("generate 应生成网格节点并设置 stepRemain", async () => {
      const player = await createModules(makePlayer("rogue_6"));
      const gz = (player.rlv2 as any)._module.gridZone;
      expect(gz).toBeTruthy();
      gz.generate([1]);
      const json = gz.toJSON();
      expect(json.stepRemain).toBe(20);
      expect(json.needConfirmStepZero).toBe(1);
      expect(Object.keys(json.zones["1"].nodes).length).toBeGreaterThan(0);
      // 战斗节点应有 savage.stageId
      const nodes = Object.values(json.zones["1"].nodes) as any[];
      expect(nodes.some((n) => n.content.savage?.stageId)).toBe(true);
    });

    it("moveTo 应标记节点已访问并开放相邻节点", async () => {
      const player = await createModules(makePlayer("rogue_6"));
      const gz = (player.rlv2 as any)._module.gridZone;
      gz.generate([1]);
      (player.rlv2 as any)._status.cursor.zone = 1;
      const nodeId = "100";
      const node = gz.moveTo([nodeId]);
      expect(node).toBeTruthy();
      expect(node.state).toBe(2);
      expect(gz.toJSON().zones["1"].nodes[nodeId].state).toBe(2);
    });

    it("step 应消耗行动力", async () => {
      const player = await createModules(makePlayer("rogue_6"));
      const gz = (player.rlv2 as any)._module.gridZone;
      gz.generate([1]);
      gz.step();
      expect(gz.toJSON().stepRemain).toBe(19);
    });
  });

  describe("WEATHER（rogue_6）", () => {
    it("onZoneNew 应选择主/副天气", async () => {
      const player = await createModules(makePlayer("rogue_6"));
      const w = (player.rlv2 as any)._module.weather;
      w.onZoneNew([1]);
      const json = w.toJSON();
      expect(json.currentMain).toMatch(/^rogue_6_weather_\d+_[abc]$/);
      expect(json.currentSub).toBe("rogue_6_subweather_1");
    });
  });

  describe("SCRAP（rogue_6）", () => {
    it("gain MOVE 型废品应自动装备为载具", async () => {
      const player = await createModules(makePlayer("rogue_6"));
      const s = (player.rlv2 as any)._module.scrap;
      s.gain(["rogue_6_scrap_M_01"]);
      const json = s.toJSON();
      expect(Object.keys(json.inventory)).toHaveLength(1);
      expect(json.activeVehicle.isWalk).toBe(0);
      expect(json.activeVehicle.instId).toMatch(/^s_\d+$/);
    });

    it("changeVehicle 空串应切回步行", async () => {
      const player = await createModules(makePlayer("rogue_6"));
      const s = (player.rlv2 as any)._module.scrap;
      s.gain(["rogue_6_scrap_M_01"]);
      s.changeVehicle("");
      expect(s.toJSON().activeVehicle.isWalk).toBe(1);
    });
  });

  describe("COPPER（rogue_5）", () => {
    it("drawInitial 应抽 3 枚铜币入袋", async () => {
      const player = await createModules(makePlayer("rogue_5"));
      const c = (player.rlv2 as any)._module.copper;
      const json = c.toJSON();
      expect(Object.keys(json.bag)).toHaveLength(3);
      for (const item of Object.values(json.bag) as any[]) {
        expect(item.isDrawn).toBe(1);
      }
    });

    it("gild 应升级铜币层数", async () => {
      const player = await createModules(makePlayer("rogue_5"));
      const c = (player.rlv2 as any)._module.copper;
      const key = Object.keys(c.toJSON().bag)[0];
      c.gild(key);
      expect(c.toJSON().bag[key].layer).toBe(1);
    });

    it("redraw 应重新抽牌", async () => {
      const player = await createModules(makePlayer("rogue_5"));
      const c = (player.rlv2 as any)._module.copper;
      const ret = c.redraw();
      expect(ret.copper).toHaveLength(3);
    });
  });

  describe("SANCHECK / DICE（rogue_2）", () => {
    it("module.toJSON 应输出 san/dice 状态", async () => {
      const player = await createModules(makePlayer("rogue_2"));
      // 手动创建模块管理器（create 需完整 excel）
      const moduleJson = (player.rlv2 as any)._module.toJSON();
      // 无管理器时由主题兜底输出
      expect(moduleJson.san).toEqual({ sanity: 100 });
      expect(moduleJson.dice).toEqual({ id: "", count: 1 });
    });
  });
});

describe("CHAOS / VISION（rogue_3）", () => {
  it("gainChaos 应累积坍缩值并在达到上限时升层挂坍缩", async () => {
    const player = await createModules(makePlayer("rogue_3"));
    const c = (player.rlv2 as any)._module.chaos;
    expect(c).toBeTruthy();
    // 累积到上限（4）触发升层
    c.gainChaos(4);
    const json = c.toJSON();
    expect(json.level).toBe(1);
    expect(json.value).toBe(0);
    expect(json.deltaChaos.afterLevel).toBe(1);
  });

  it("vision 应输出 value/isMax", async () => {
    const player = await createModules(makePlayer("rogue_3"));
    const v = (player.rlv2 as any)._module.vision;
    expect(v).toBeTruthy();
    expect(v.toJSON()).toEqual({ value: 0, isMax: 0 });
  });
});

describe("WRATH / SKY（rogue_5）", () => {
  it("wrath gain 应收集怒气", async () => {
    const player = await createModules(makePlayer("rogue_5"));
    const w = (player.rlv2 as any)._module.wrath;
    expect(w).toBeTruthy();
    w.gain(["rogue_5_wrath_1"]);
    expect(w.toJSON().wraths).toEqual(["rogue_5_wrath_1"]);
    expect(w.toJSON().newWrath).toBe(0);
  });

  it("sky 应输出 zones", async () => {
    const player = await createModules(makePlayer("rogue_5"));
    const s = (player.rlv2 as any)._module.sky;
    expect(s).toBeTruthy();
    expect(s.toJSON()).toEqual({ zones: {} });
  });
});
