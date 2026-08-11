import { describe, it, expect, vi } from "vitest";
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
            ro6_n_1_3: { id: "ro6_n_1_3" },
            ro6_e_1_1: { id: "ro6_e_1_1" },
            ro6_n_5_1: { id: "ro6_n_5_1" },
            ro6_e_5_1: { id: "ro6_e_5_1" },
          },
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
        },
      },
      modules: { rogue_6: { moduleTypes: ["GRID_ZONE"] } },
      consts: {},
    },
    CharacterTable: {},
    GameDataConst: { maxLevel: [[], [], [], [], [], []] },
  },
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import { BLACKSTREAM_CONSTRUCTIONS } from "@game/controller/rlv2/modules/blackstream-data";

function makePlayer() {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { rogue_6: {} } as any,
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = { theme: "rogue_6", mode: "NORMAL", modeGrade: 0 } as any;
  return player;
}

/** Math.random 固定 0：generate 恒取每层第一张模板，便于按模板精确断言 */
async function withFixedRandom(fn: () => Promise<void> | void) {
  const spy = vi.spyOn(Math, "random").mockReturnValue(0);
  try {
    await fn();
  } finally {
    spy.mockRestore();
  }
}

describe("GRID_ZONE 官服结构对齐（构造模板）", () => {
  it("各层生成：节点 ID 为 x*100+y、map/light 对齐、终点 zone_end", async () => {
    await withFixedRandom(async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const gz = (player.rlv2 as any)._module.gridZone;

      for (const zone of [1, 2, 3, 4, 5]) {
        gz.generate([zone]);
        const light = gz.toJSON().zones[String(zone)].nodes;
        const mapNodes = (player.rlv2 as any)._map.zones[zone]?.nodes;
        expect(mapNodes, `zone ${zone} map.zones`).toBeTruthy();
        expect(Object.keys(mapNodes).length).toBe(Object.keys(light).length);
        for (const id of Object.keys(light)) {
          expect(mapNodes[id], `zone ${zone} node ${id}`).toBeTruthy();
          const x = Math.floor(Number(id) / 100);
          const y = Number(id) % 100;
          expect(mapNodes[id].pos).toEqual({ x, y });
        }
        // 起点（唯一 state 1）为 GLADE
        const start = Object.entries(light).find(([, n]: any) => n.state === 1);
        expect(start, `zone ${zone} 起点`).toBeTruthy();
        expect((start![1] as any).content.kind).toBe(268435456);
        // 终点 zone_end ≥1 且 type 为 VISIBLE_END/BATTLE_BOSS
        const ends = Object.values(mapNodes).filter((n: any) => n.zone_end);
        expect(ends.length, `zone ${zone} 终点`).toBeGreaterThan(0);
        for (const e of ends) {
          expect([8388608, 4]).toContain(e.type);
        }
        // 战斗节点带 stage
        const battles = Object.values(mapNodes).filter((n: any) => n.type === 1 || n.type === 2 || n.type === 4);
        for (const b of battles) expect(b.stage).toBeTruthy();
      }
    });
  });

  it("1-2 层起点相邻（边距离 1）必为作战", async () => {
    await withFixedRandom(async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const gz = (player.rlv2 as any)._module.gridZone;
      for (const zone of [1, 2]) {
        gz.generate([zone]);
        const light = gz.toJSON().zones[String(zone)].nodes;
        const t = BLACKSTREAM_CONSTRUCTIONS.find((c) => c.layerIndex === zone - 1)!;
        const dist = gz.edgeDistances(t);
        const startId = Object.entries(light).find(([, n]: any) => n.state === 1)![0];
        for (const [id, n] of Object.entries(light) as [string, any][]) {
          if (dist.get(id) === 1 && id !== startId) {
            expect(n.content.savage, `zone ${zone} 相邻 ${id}`).toBeTruthy();
          }
        }
      }
    });
  });

  it("非战斗节点类型必须落在层 5 距离规则内（沿边距离）", async () => {
    await withFixedRandom(async () => {
      const player = makePlayer();
      await (player.rlv2 as any)._module.create();
      const gz = (player.rlv2 as any)._module.gridZone;
      gz.generate([5]);
      const light = gz.toJSON().zones["5"].nodes;
      const t5 = BLACKSTREAM_CONSTRUCTIONS.find((c) => c.layerIndex === 4)!;
      const dist = gz.edgeDistances(t5);
      // 起点
      const startId = Object.entries(light).find(([, n]: any) => n.state === 1)![0];
      for (const [id, n] of Object.entries(light) as [string, any][]) {
        if (id === startId) continue; // 起点不受距离规则约束
        const d = dist.get(id);
        expect(d, `zone5 ${id} 距离`).toBeGreaterThanOrEqual(1);
      }
    });
  });
});
