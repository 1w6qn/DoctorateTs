import { describe, it, expect, vi } from "vitest";

// 回归：商店节点抵达——商店判定不能只依赖 gridZone content.shop：
// 续局恢复/存档精简后 content 被剥除（kind/shop 丢失），须回退 map.zones
// 节点类型判定，否则诡意行商/秘境行商/应急助力抵达后不开商店。
const excelMock = vi.hoisted(() => ({
  RoguelikeTopicTable: {
    details: {
      rogue_6: {
        init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
        stages: {
          ro6_n_1_1: { id: "ro6_n_1_1" },
          ro6_n_2_1: { id: "ro6_n_2_1" },
        },
        items: {},
        relics: {},
        variationData: {},
        recruitTickets: {},
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

import { PlayerDataManager } from "@game/service/manager/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";

function makePlayer(): any {
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

describe("商店节点抵达（会话内 / 续局精简 / content 全空）", () => {
  it("三种形态均生成 BATTLE_SHOP 事件", async () => {
    await new Promise((r) => setTimeout(r, 0));
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2._module.create();
    const gz = rlv2._module.gridZone;
    // 反复生成直到出现商店节点（第 1 层 诡意行商 数量规则 [1,2] 必有）
    let shopId = "";
    for (let tries = 0; tries < 20 && !shopId; tries++) {
      gz.generate([1]);
      const nodes = gz.zones["zone_1"].nodes;
      for (const [id, n] of Object.entries(nodes) as [string, any][]) {
        if (n.content?.shop) {
          shopId = id;
          break;
        }
      }
    }
    expect(shopId).not.toBe("");
    rlv2._status.cursor.zone = 1;
    rlv2._status.cursor.position = { x: 0, y: 1 };

    // 1. 会话内（content.shop + kind 完整）
    await rlv2.gridZoneMoveTo({ route: [shopId] });
    expect(rlv2._status.pending.map((e: any) => e.type)).toContain(
      "BATTLE_SHOP",
    );

    // 2. 续局精简形态（kind 被剥除，仅保留 shop）
    rlv2._status._pending._pending.length = 0;
    const node = gz.zones["zone_1"].nodes[shopId];
    node.content = { shop: node.content.shop };
    await rlv2.gridZoneMoveTo({ route: [shopId] });
    expect(rlv2._status.pending.map((e: any) => e.type)).toContain(
      "BATTLE_SHOP",
    );

    // 3. content 全空（kind/shop 均丢失）→ 回退 map.zones 节点类型判定
    rlv2._status._pending._pending.length = 0;
    node.content = {};
    await rlv2.gridZoneMoveTo({ route: [shopId] });
    expect(rlv2._status.pending.map((e: any) => e.type)).toContain(
      "BATTLE_SHOP",
    );
  });
});
