import { describe, it, expect, vi, beforeEach } from "vitest";
import { enablePatches } from "immer";

enablePatches();

// 官方 excel mock：rogue_1 stages 覆盖 zone 1-6（主流程 6 层）
vi.mock("@excel/excel", () => {
  const stages: any = {};
  for (let z = 1; z <= 6; z++) {
    stages[`ro1_n_${z}_1`] = { id: `ro1_n_${z}_1` };
    stages[`ro1_e_${z}_1`] = { id: `ro1_e_${z}_1` };
  }
  stages["ro1_b_1"] = { id: "ro1_b_1" };
  stages["ro1_b_2"] = { id: "ro1_b_2" };
  return {
    default: {
      RoguelikeTopicTable: {
        details: {
          rogue_1: {
            init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
            choices: { choice_leave: { type: "LEAVE", nextSceneId: null } },
            stages,
            gameConst: { unlockRouteItemId: null, unlockRouteItemCount: 0 },
            items: {},
            relics: {},
            detailConst: { playerLevelTable: {} },
            milestones: [],
          },
        },
        modules: { rogue_1: {} },
        consts: {},
      },
      CharacterTable: {},
      RoguelikeConsts: { rogue_1: { outbuff: {}, modebuff: {}, recruitGrps: {} } },
    },
  };
});

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    rlv2: { outer: {}, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  return new PlayerDataManager(pd._playerdata);
}

describe("rlv2 地图生成数据与区域推进", () => {
  let player: PlayerDataManager;

  beforeEach(() => {
    player = makePlayer();
    player.rlv2.current.game = { theme: "rogue_1", mode: "NORMAL", modeGrade: 0, predefined: null } as any;
  });

  describe("nodesInfo.json 数据文件", () => {
    it("应覆盖 6 主题且各主题 zones 有关卡列表", () => {
      const data = require("../../../data/rlv2/nodesInfo.json");
      const themes = Object.keys(data.themes);
      expect(themes.length).toBeGreaterThanOrEqual(6);
      for (const th of ["rogue_1", "rogue_2", "rogue_3", "rogue_4", "rogue_5", "rogue_6"]) {
        const zones = data.themes[th].zones;
        const zs = Object.keys(zones);
        expect(zs.length).toBeGreaterThan(0);
        // 主流程 zone 1 应有 Normal/Emergency
        expect(zones["1"].Normal.length).toBeGreaterThan(0);
        expect(zones["1"].Emergency.length).toBeGreaterThan(0);
      }
    });

    it("rogue_1 应有 boss 关卡", () => {
      const data = require("../../../data/rlv2/nodesInfo.json");
      const hasBoss = Object.values(data.themes.rogue_1.zones).some(
        (z: any) => (z.Boss || []).length > 0
      );
      expect(hasBoss).toBe(true);
    });
  });

  describe("map 生成", () => {
    it("生成 zone 2 地图应读取 nodesInfo 关卡列表", () => {
      (player.rlv2 as any)._map.init();
      (player.rlv2 as any)._map.generate([2]);
      const zone = (player.rlv2 as any)._map.zones[2];
      expect(zone).toBeDefined();
      expect(zone.id).toBe("zone_2");
      // 应存在普通作战节点且带有 stage（来自 nodesInfo 的 ro1_n_2_1）
      const battleNode = Object.values(zone.nodes).find(
        (n: any) => n.type === 1 && n.stage
      );
      expect(battleNode).toBeDefined();
      expect((battleNode as any).stage).toBe("ro1_n_2_1");
    });
  });

  describe("区域推进", () => {
    it("finishEvent 在 zone_end 节点应推进到下一层并生成新地图", async () => {
      // zone 1 终点节点 300（zone_end）
      (player.rlv2 as any)._map.zones[1] = {
        id: "zone_1",
        nodes: {
          "300": { index: "300", pos: { x: 3, y: 0 }, next: [], type: 8, zone_end: true },
        },
      };
      (player.rlv2 as any)._status.cursor.zone = 1;
      (player.rlv2 as any)._status.cursor.position = { x: 3, y: 0 };
      (player.rlv2 as any)._status._pending._pending.push({ type: "SHOP", content: {} });
      const zoneEmit = vi.spyOn((player.rlv2 as any)._trigger, "emit");

      await (player.rlv2 as any).finishEvent();

      expect((player.rlv2 as any)._status.cursor.zone).toBe(2);
      expect((player.rlv2 as any)._status.cursor.position).toBeNull();
      const zoneCalls = zoneEmit.mock.calls.filter((c: any) => c[0] === "rlv2:zone:new");
      expect(zoneCalls.length).toBe(1);
      expect(zoneCalls[0][1][0]).toBe(2);
      // 新一层地图已生成
      expect((player.rlv2 as any)._map.zones[2]).toBeDefined();
    });

    it("finishEvent 在非 zone_end 节点不应推进", async () => {
      (player.rlv2 as any)._map.zones[1] = {
        id: "zone_1",
        nodes: {
          "100": { index: "100", pos: { x: 1, y: 0 }, next: [], type: 1 },
        },
      };
      (player.rlv2 as any)._status.cursor.zone = 1;
      (player.rlv2 as any)._status.cursor.position = { x: 1, y: 0 };
      (player.rlv2 as any)._status._pending._pending.push({ type: "SCENE", content: {} });

      await (player.rlv2 as any).finishEvent();

      expect((player.rlv2 as any)._status.cursor.zone).toBe(1);
    });

    it("最终层 zone_end 应触发游戏结算（END_RESULT）", async () => {
      (player.rlv2 as any)._map.zones[6] = {
        id: "zone_6",
        nodes: {
          "600": { index: "600", pos: { x: 6, y: 0 }, next: [], type: 8, zone_end: true },
        },
      };
      (player.rlv2 as any)._status.cursor.zone = 6;
      (player.rlv2 as any)._status.cursor.position = { x: 6, y: 0 };
      (player.rlv2 as any)._status.property.level = 1;
      (player.rlv2 as any)._status.property.gold = 10;
      (player.rlv2 as any)._status.toEnding = "ro1_ending_1";
      (player.rlv2 as any)._status._pending._pending.push({ type: "SHOP", content: {} });

      await (player.rlv2 as any).finishEvent();

      expect((player.rlv2 as any)._status.state).toBe("END");
      const pending = (player.rlv2 as any)._status.pending;
      const endEvent = pending.find((e: any) => e.type === "END_RESULT");
      expect(endEvent).toBeDefined();
    });
  });
});
