import { describe, it, expect, vi } from "vitest";

// rogue_6（黑流树海）网格对局"落盘 → 重登续局"的恢复回归测试。
// 触发点：重登后 gridZone.zones 节点 content 已是客户端线格式（savage/kind 被剥除），
// 续局 gridZoneMoveTo 进战斗节点必须能判定并触发战斗（此前从 gridZone 节点 content 取
// savgment.stageId/kind → 恢复后缺失 → 只回 WAIT_MOVE，客户端卡死，2026-08-20 复现）。
const excelMock = vi.hoisted(() => ({
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
        items: {},
      },
    },
    modules: {
      rogue_6: {
        moduleTypes: ["GRID_ZONE"],
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

/** Math.random 固定 0：generate 恒取每层第一张模板，便于精确确定战斗节点 */
async function withFixedRandom(fn: () => Promise<void> | void) {
  const spy = vi.spyOn(Math, "random").mockReturnValue(0);
  try {
    await fn();
  } finally {
    spy.mockRestore();
  }
}

/** 构造一个"进行中 rogue_6 第 1 层"的控制器，并生成第 1 层网格 */
async function makeRunningGridPlayer() {
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
  const rlv2 = player.rlv2 as any;
  rlv2.current.game = {
    theme: "rogue_6",
    mode: "NORMAL",
    modeGrade: 0,
    predefined: null,
    outer: { support: false },
    start: 1,
    equivalentGrade: 0,
  };
  await rlv2._module.create();
  rlv2._module.gridZone.generate([1]);
  return player;
}

/** 用已生成对局的内存态，构造一份"落盘后再读回"的存档快照（等价 JSON 序列化往返） */
function persistedSnapshot(player: PlayerDataManager) {
  const rlv2 = player.rlv2 as any;
  return {
    module: JSON.parse(JSON.stringify(rlv2._module.toJSON())),
    map: JSON.parse(JSON.stringify(rlv2._map.toJSON())),
  };
}

/** 用存档快照重建控制器（重登"继续探索"分支），返回可调用的 rlv2 */
function reloadFromSnapshot(snapshot: { module: any; map: any }) {
  const pd: any = mockPlayerData({
    rlv2: {
      outer: { rogue_6: {} } as any,
      current: {
        player: {
          state: "WAIT_MOVE",
          property: { hp: { current: 4, max: 4 }, gold: 8 },
          cursor: { zone: 1, position: null },
          trace: [],
          pending: [],
          status: { bankPut: 0 },
          toEnding: "ro6_ending_1",
          chgEnding: false,
        },
        map: snapshot.map,
        module: snapshot.module,
        game: {
          theme: "rogue_6",
          mode: "NORMAL",
          modeGrade: 0,
          predefined: null,
          outer: { support: false },
          start: 1,
          equivalentGrade: 0,
        },
        buff: { tmpHP: 0, capsule: null, squadBuff: [] },
        record: { brief: null },
        troop: {
          chars: {},
          expedition: [],
          expeditionDetails: {},
          expeditionReturn: null,
          hasExpeditionReturn: false,
        },
        inventory: {
          relic: {},
          recruit: {},
          trap: null,
          exploreTool: {},
          consumable: {},
        },
      },
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: {
      missions: { DAILY: {}, ACTIVITY: {} },
      missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} },
    } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  // 构造期 hasRunning=true 走 rlv2:continue（异步微任务），等落定后再驱动续局
  return player.rlv2 as any;
}

describe("rogue_6 网格对局重登续局恢复", () => {
  it("续局网格地图已按存档恢复（zones 非空，可继续走）", async () => {
    await withFixedRandom(async () => {
      const origin = await makeRunningGridPlayer();
      const gz = (origin.rlv2 as any)._module.gridZone;
      expect(Object.keys(gz.zones["zone_1"].nodes).length).toBeGreaterThan(0);

      const snapshot = persistedSnapshot(origin);
      const rlv2 = reloadFromSnapshot(snapshot);
      // 等构造期 continue 微任务落定
      await Promise.resolve();
      await Promise.resolve();
      // 存档模块恢复后 zones 仍在（map 完整恢复）
      expect(Object.keys(rlv2._module.gridZone.zones["zone_1"].nodes).length).toBeGreaterThan(0);
      const mapNodes = (rlv2._map as any).zones["1000"]?.nodes;
      expect(Object.keys(mapNodes).length).toBeGreaterThan(0);
    });
  });

  it("续局移动进战斗节点：必须触发战斗并推送节点到达（防客户端卡死）", async () => {
    await withFixedRandom(async () => {
      const origin = await makeRunningGridPlayer();
      const gridZone = (origin.rlv2 as any)._module.gridZone;
      // 取一个作战节点（type===1）作为目标
      const battleId = Object.entries(gridZone.zones["zone_1"].nodes).find(
        ([, n]: any) => n.content?.kind === 1,
      )![0];
      expect(battleId).toBeTruthy();

      const snapshot = persistedSnapshot(origin);
      const rlv2 = reloadFromSnapshot(snapshot);
      await Promise.resolve();
      await Promise.resolve();

      // 重登恢复后按存档驱动续局：移动到该战斗节点
      await rlv2.gridZoneMoveTo({ route: [battleId] });
      const msgs = rlv2.takePushMessages();
      // 节点到达推送必须携带节点类型（客户端据此渲染到达节点，否则卡死）
      expect(msgs.find((m: any) => m.path === "rlv2NodeArrive")).toBeTruthy();
      // 战斗节点必须进入战斗态（PENDING + BATTLE pending 事件），而非仅 WAIT_MOVE（卡死态）
      expect(rlv2._status.state).toBe("PENDING");
      expect(rlv2._status.pending.some((e: any) => e.type === "BATTLE")).toBe(true);
    });
  });
});