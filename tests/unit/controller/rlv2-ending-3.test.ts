import { describe, it, expect, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

// rogue_6 三结局·纠缠调和：先行一步送干员 → 下一层返回 +2 希望 + 怦然信标
// → 持有怦然信标通过第Ⅴ层 → 第Ⅵ层（源流交汇处）→ ending_3
const excelMock = vi.hoisted(() => ({
  RoguelikeTopicTable: {
    details: {
      rogue_6: {
        stages: {
          ro6_n_1_1: { id: "ro6_n_1_1" },
          ro6_n_3_1: { id: "ro6_n_3_1" },
          ro6_n_5_1: { id: "ro6_n_5_1" },
          ro6_n_6_1: { id: "ro6_n_6_1" },
        },
        init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
        items: {
          rogue_6_population: { id: "rogue_6_population", type: "POPULATION", rarity: "NONE" },
          rogue_6_relic_final_3: { id: "rogue_6_relic_final_3", type: "RELIC", rarity: "SUPER_RARE" },
        },
        relics: {
          rogue_6_relic_final_3: { id: "rogue_6_relic_final_3", buffs: [] },
        },
        choices: {
          choice_ro6_scout_1: { id: "choice_ro6_scout_1", nextSceneId: "scene_ro6_scout_2" },
          choice_ro6_scout_3: { id: "choice_ro6_scout_3", nextSceneId: "scene_ro6_scout_3" },
          choice_ro6_scout_4: { id: "choice_ro6_scout_4", nextSceneId: null },
        },
        choiceScenes: {
          scene_ro6_scout_2: { id: "scene_ro6_scout_2" },
          scene_ro6_scout_3: { id: "scene_ro6_scout_3" },
        },
        gameConst: { expedEndingRelic: "rogue_6_relic_final_3" },
      },
    },
    modules: {
      rogue_6: {
        moduleTypes: ["GRID_ZONE", "SCRAP"],
        scrap: { scrapItemToType: {} },
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

/** 在 map.zones 放一个 zone_end 节点，cursor 指向它（checkZoneEnd 前置条件） */
function placeZoneEnd(player: any, zone: number, key: string, x: number, y: number) {
  const map = (player.rlv2 as any)._map;
  map.zones[key] = {
    id: `zone_${zone}`,
    index: Number(key),
    nodes: {
      [String(x * 100 + y)]: {
        index: String(x * 100 + y),
        pos: { x, y },
        next: [],
        type: 16,
        zone_end: true,
      },
    },
    variation: [],
  };
  (player.rlv2 as any)._status.cursor.zone = zone;
  (player.rlv2 as any)._status.cursor.position = { x, y };
}

describe("rogue_6 三结局·纠缠调和（先行一步 → 怦然信标 → 第Ⅵ层）", () => {
  it("先行一步选'派一名同伴进入/探索'→ 标记三结局远征", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    // scout_1：派一名同伴进入
    await (player.rlv2 as any).selectChoice({ choice: "choice_ro6_scout_1" });
    expect((player.rlv2 as any).troop.expeditionDetails.ending).toBe(true);
    // scout_4：离开 → 不标记
    const player2 = makePlayer();
    await (player2.rlv2 as any)._module.create();
    await (player2.rlv2 as any).selectChoice({ choice: "choice_ro6_scout_4" });
    expect((player2.rlv2 as any).troop.expeditionDetails.ending).toBeUndefined();
  });

  it("expeditionChoice 派出干员 → 进入下一区域时返回 2 希望 + 怦然信标", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const gz = (player.rlv2 as any)._module.gridZone;
    // 标记三结局远征 + 派出干员
    await (player.rlv2 as any).selectChoice({ choice: "choice_ro6_scout_1" });
    await (player.rlv2 as any).expeditionChoice({ choice: "8" });
    expect((player.rlv2 as any).troop.expedition).toEqual(["8"]);
    // 到达 zone 2 终点 → checkZoneEnd 推进 zone 3 → 干员返回
    gz.generate([2]);
    // 2 希望（population.max +2）
    const beforePop = (player.rlv2 as any)._status.property.population.max;
    placeZoneEnd(player, 2, "1001", 3, 1);
    await (player.rlv2 as any).checkZoneEnd();
    const relics = Object.values((player.rlv2 as any).inventory.relic).map(
      (r: any) => r.id,
    );
    expect(relics).toContain("rogue_6_relic_final_3");
    expect((player.rlv2 as any)._status.property.population.max).toBe(
      beforePop + 2,
    );
    // 远征清空、标记清除、推进 zone 3
    expect((player.rlv2 as any).troop.expedition).toEqual([]);
    expect((player.rlv2 as any).troop.expeditionDetails.ending).toBeUndefined();
    expect((player.rlv2 as any)._status.cursor.zone).toBe(3);
  });

  it("持有怦然信标 → maxZone 允许第Ⅵ层（6）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    // 无怦然信标 → 5
    expect((player.rlv2 as any).maxZone).toBe(5);
    // 持有怦然信标 → 6
    (player.rlv2 as any).inventory._relic.relics = {
      r_0: { index: "r_0", id: "rogue_6_relic_final_3", count: 1, ts: 0 },
    };
    expect((player.rlv2 as any).maxZone).toBe(6);
  });

  it("持有怦然信标通过第Ⅵ层 → toEnding = ro6_ending_3", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const gz = (player.rlv2 as any)._module.gridZone;
    // 持有怦然信标 + 已到 zone 6（VI 层）
    (player.rlv2 as any).inventory._relic.relics = {
      r_0: { index: "r_0", id: "rogue_6_relic_final_3", count: 1, ts: 0 },
    };
    gz.generate([6]);
    placeZoneEnd(player, 6, "1005", 3, 2);
    await (player.rlv2 as any).checkZoneEnd();
    expect((player.rlv2 as any)._status.toEnding).toBe("ro6_ending_3");
    expect((player.rlv2 as any)._status.runResult).toBe("success");
  });

  it("第Ⅵ层（源流交汇处）生成：终点险路恶敌 + 起点右侧命运所指（调谐仪式入口）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any)._module.create();
    const gz = (player.rlv2 as any)._module.gridZone;
    gz.generate([6]);
    const light = gz.toJSON().zones["zone_6"].nodes;
    const mapNodes = (player.rlv2 as any)._map.zones["1005"]?.nodes || {};
    // 终点（zone_end）为险路恶敌 BATTLE_BOSS
    const ends = Object.values(mapNodes).filter((n: any) => n.zone_end);
    expect(ends.length).toBeGreaterThan(0);
    for (const e of ends) expect(e.type).toBe(4);
    // 命运所指（32768）存在于地图（调谐仪式入口）
    const fates = Object.values(mapNodes).filter((n: any) => n.type === 32768);
    expect(fates.length).toBeGreaterThan(0);
    // 行动力 5（VI 层）
    expect(gz.stepRemain).toBe(5);
    expect(light).toBeTruthy();
  });
});
