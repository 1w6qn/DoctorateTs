import { describe, it, expect, vi, beforeEach } from "vitest";

// 官方 excel mock：rogue_4 choiceScenes（rest/sacrifice 等 enter 场景）+ choices（选项含 displayData.itemId）
vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_4: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          gameConst: { unlockRouteItemId: "rogue_4_key", unlockRouteItemCount: 1 },
          choiceScenes: {
            scene_ro4_rest1_enter: { id: "scene_ro4_rest1_enter", title: "淡然面对", subTypeId: 0 },
            scene_ro4_rest1_1: { id: "scene_ro4_rest1_1", title: "淡然面对", subTypeId: 0 },
            scene_ro4_sacrifice1_enter: { id: "scene_ro4_sacrifice1_enter", title: "失与得", subTypeId: 0 },
            scene_ro4_sacrifice1_1: { id: "scene_ro4_sacrifice1_1", title: "失与得", subTypeId: 0 },
            scene_ro4_chest_enter: { id: "scene_ro4_chest_enter", title: "古堡馈赠", subTypeId: 0 },
          },
          choices: {
            choice_ro4_rest1_1: {
              id: "choice_ro4_rest1_1", title: "稍事休息", type: "TRADE", nextSceneId: "scene_ro4_rest1_1",
              displayData: { type: "NORMAL", itemId: "rogue_4_hpmax" },
            },
            choice_ro4_rest1_2: {
              id: "choice_ro4_rest1_2", title: "强化训练", type: "TRADE", nextSceneId: "scene_ro4_rest1_2",
              displayData: { type: "ITEM", itemId: "rogue_4_upgrade_ticket_all" },
            },
            choice_ro4_sacrifice1_1: {
              id: "choice_ro4_sacrifice1_1", title: "献祭", type: "SACRIFICE", nextSceneId: null,
              displayData: { type: "NORMAL", itemId: null },
            },
            choice_ro4_chest_1: {
              id: "choice_ro4_chest_1", title: "打开宝箱", type: "TRADE_PROB_SHOW", nextSceneId: "scene_ro4_chest_1",
              displayData: { type: "NORMAL", itemId: null },
            },
          },
          items: {
            rogue_4_hpmax: { id: "rogue_4_hpmax", type: "HPMax", rarity: "NONE" },
            rogue_4_upgrade_ticket_all: { id: "rogue_4_upgrade_ticket_all", type: "RECRUIT_TICKET", rarity: "NONE" },
            rogue_4_relic_a01: { id: "rogue_4_relic_a01", type: "RELIC", rarity: "NORMAL" },
          },
          relics: {},
        },
      },
      modules: { rogue_4: { fragment: null } },
      consts: {},
    },
    CharacterTable: {},
    RoguelikeConsts: {},
  },
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: { outer: {}, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  player.rlv2.current.game = { theme: "rogue_4", mode: "NORMAL", modeGrade: 0, predefined: null, start: 1 } as any;
  (player.rlv2 as any)._data.eventChoices = {}; // 无 odpy 效果数据，走官方路径
  return player;
}

describe("rlv2 节点效果（非战斗节点）", () => {
  let player: PlayerDataManager;

  beforeEach(async () => {
    player = makePlayer();
    await new Promise((r) => setTimeout(r, 0)); // 等构造期异步 init
    // 地图：zone 1 的 rest/sacrifice/chest 节点
    (player.rlv2 as any)._map.zones[1] = {
      id: "zone_1",
      nodes: {
        "0": { index: "0", pos: { x: 0, y: 0 }, next: [{ x: 1, y: 0 }, { x: 1, y: 1 }, { x: 1, y: 2 }, { x: 1, y: 3 }], type: 0, zone_end: false },
        "100": { index: "100", pos: { x: 1, y: 0 }, next: [], type: 16, zone_end: false }, // REST
        "101": { index: "101", pos: { x: 1, y: 1 }, next: [], type: 1024, zone_end: false }, // SACRIFICE
        "102": { index: "102", pos: { x: 1, y: 2 }, next: [], type: 64, zone_end: false }, // TREASURE
        "103": { index: "103", pos: { x: 1, y: 3 }, next: [], type: 32, zone_end: false }, // INCIDENT
      },
    };
    (player.rlv2 as any)._status.cursor.zone = 1;
    (player.rlv2 as any)._status.cursor.position = { x: 0, y: 0 };
  });

  it("moveTo REST 节点应生成 SCENE（rest 前缀场景 + 官方选项）", async () => {
    await (player.rlv2 as any).moveTo({ to: { x: 1, y: 0 } });
    const scene = (player.rlv2 as any)._status.pending.find((e: any) => e.type === "SCENE");
    expect(scene).toBeDefined();
    expect(scene.content.scene.id).toContain("rest1");
    expect(scene.content.scene.choices).toHaveProperty("choice_ro4_rest1_1");
    expect(scene.content.scene.choices).toHaveProperty("choice_ro4_rest1_2");
  });

  it("moveTo SACRIFICE 节点应生成 SCENE（sacrifice 前缀）", async () => {
    await (player.rlv2 as any).moveTo({ to: { x: 1, y: 1 } });
    const scene = (player.rlv2 as any)._status.pending.find((e: any) => e.type === "SCENE");
    expect(scene).toBeDefined();
    expect(scene.content.scene.id).toContain("sacrifice1");
    expect(scene.content.scene.choices).toHaveProperty("choice_ro4_sacrifice1_1");
  });

  it("selectChoice 官方选项（displayData.itemId）应发物品", async () => {
    const getItems = vi.spyOn((player.rlv2 as any)._trigger, "emit");
    // 直接进入 REST 场景并选择"稍事休息"（itemId: rogue_4_hpmax）
    await (player.rlv2 as any).moveTo({ to: { x: 1, y: 0 } });
    await (player.rlv2 as any).selectChoice({ choice: "choice_ro4_rest1_1" });
    const gainCall = getItems.mock.calls.find((c: any) => c[0] === "rlv2:get:items");
    expect(gainCall).toBeDefined();
    const items = gainCall[1][0];
    expect(items).toContainEqual(expect.objectContaining({ id: "rogue_4_hpmax", count: 1 }));
  });

  it("INCIDENT 节点行为不回归（event_choices 池为空时无 SCENE 但状态推进）", async () => {
    (player.rlv2 as any)._map.zones[1].nodes["103"] = { index: "103", pos: { x: 1, y: 3 }, next: [], type: 32, zone_end: false };
    await (player.rlv2 as any).moveTo({ to: { x: 1, y: 3 } });
    expect((player.rlv2 as any)._status.cursor.position).toEqual({ x: 1, y: 3 });
  });
});
