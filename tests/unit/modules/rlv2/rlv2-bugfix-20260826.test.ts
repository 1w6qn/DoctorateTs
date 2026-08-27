import { describe, it, expect, vi } from "vitest";

// 回归：2026-08-26 用户反馈缺陷修复
// 1. 战斗结算 earn 口径（damage/hp/shield 恒 0、不回血）→ 见 rlv2-battle-reward-blackstream
// 2. 指挥经验：战斗结束即入账（需求值+三星加成）→ 见 rlv2-battle-reward-blackstream
// 3. 节点状态仅 0/2（官服抓包，无中间态 1）
// 7. pushMessage 路由补齐 → 见 tests/unit/router/rlv2.test.ts
// 8. 上一把分队 buff 不残留到新局（招募希望消耗受上把分队影响的根因）
const excelMock = vi.hoisted(() => ({
  // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
  getItem(id: string) { return this.ItemTable?.items?.[id]; },
  itemName(id: string): string { return this.getItem(id)?.name ?? id; },
  makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
  charData(charId: string) { return this.CharacterTable?.[charId]; },
  stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
  RoguelikeTopicTable: {
    details: {
      rogue_6: {
        init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
        stages: { ro6_n_1_1: { id: "ro6_n_1_1" } },
        items: {},
        relics: {},
        variationData: {},
        recruitTickets: {
          rogue_6_recruit_ticket_sniper: {
            id: "rogue_6_recruit_ticket_sniper",
            professionList: ["SNIPER"],
            rarityList: ["TIER_3", "TIER_4", "TIER_5", "TIER_6"],
          },
        },
        detailConst: { playerLevelTable: { 2: { exp: 10, populationUp: 4 } } },
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
  RoguelikeConsts: {},
  CharacterTable: {},
  GameDataConst: { maxLevel: [[], [], [], [], [], []] },
}));

vi.mock("@excel/excel", () => ({ default: excelMock }));

import { PlayerDataManager } from "@game/service/PlayerDataManager";
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

describe("节点状态仅 0/2（官服口径，无中间态 1）", () => {
  it("生成后全部节点 state ∈ {0,2}；初始点亮节点=2；移动揭示不产生中间态", async () => {
    await new Promise((r) => setTimeout(r, 0));
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2._module.create();
    const gz = rlv2._module.gridZone;
    gz.generate([1]);
    const nodes = gz.zones["zone_1"].nodes;
    for (const [id, n] of Object.entries(nodes) as [string, any][]) {
      expect([0, 2], `node ${id} state=${n.state}`).toContain(n.state);
    }
    // 初始点亮类型（起点/险路尽头/曲折密道/羽瞰点）= 2
    const lit = Object.values(nodes).filter(
      (n: any) => [268435456, 8388608, 4194304, 67108864].includes(n.content?.kind),
    );
    for (const n of lit as any[]) expect(n.state).toBe(2);
    // 移动揭示后邻居仍为 0（不置中间态 1）
    rlv2._status.cursor.zone = 1;
    const startId = Object.keys(nodes).find(
      (id) => nodes[id].content?.kind === 268435456,
    );
    rlv2._status.cursor.position = {
      x: Math.floor(Number(startId) / 100),
      y: Number(startId) % 100,
    };
    const nb = Object.values(nodes).find((n: any) => n.state === 0) as any;
    const nbId = Object.keys(nodes).find((k) => nodes[k] === nb)!;
    gz.moveTo([nbId]);
    for (const [id, n] of Object.entries(nodes) as [string, any][]) {
      if (id === nbId) continue; // 抵达节点本身置 2
      expect(n.state === 1, `node ${id} 不应出现中间态 1`).toBe(false);
    }
  });
});

describe("上一把分队 buff 不残留到新局", () => {
  it("新局 rlv2:create 清空上局 recruit_cost 等分队 buff", async () => {
    await new Promise((r) => setTimeout(r, 0));
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    // 模拟上一把：分队招募减耗 buff 入池
    await rlv2._trigger.emit("rlv2:buff:apply", [
      [
        {
          key: "recruit_cost",
          blackboard: [
            { key: "rarity", value: 0, valueStr: "TIER_4,TIER_5,TIER_6" },
            { key: "profession", value: 0, valueStr: "PIONEER,WARRIOR" },
            { key: "delta", value: -2 },
          ],
        },
      ],
    ]);
    expect(rlv2._buff.filterBuffs("recruit_cost").length).toBe(1);
    // 新局创建（createGame 发 rlv2:create）→ buff 全量重置
    await rlv2._buff.create();
    expect(rlv2._buff.filterBuffs("recruit_cost").length).toBe(0);
    // 续局恢复同样先重置（避免重复累积）
    await rlv2._trigger.emit("rlv2:buff:apply", [
      [
        {
          key: "recruit_cost",
          blackboard: [
            { key: "rarity", value: 0, valueStr: "TIER_4,TIER_5,TIER_6" },
            { key: "profession", value: 0, valueStr: "PIONEER,WARRIOR" },
            { key: "delta", value: -2 },
          ],
        },
      ],
    ]);
    await rlv2._buff.continue();
    expect(rlv2._buff.filterBuffs("recruit_cost").length).toBe(0);
  });
});

describe("战斗奖励招募券：仅入券列表，不自动弹招募", () => {
  it("选券不生成 RECRUIT 事件，券以 state=0 入库（玩家自行激活）", async () => {
    await new Promise((r) => setTimeout(r, 0));
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    rlv2._status._pending._pending.push({
      type: "BATTLE_REWARD",
      content: {
        battleReward: {
          earn: {},
          rewards: [
            {
              index: 0,
              items: [{ sub: 0, id: "rogue_6_recruit_ticket_sniper", count: 1 }],
              done: 0,
            },
          ],
          show: "2",
          state: 0,
        },
      },
    });
    await rlv2.chooseBattleReward({ index: 0, sub: 0 });
    // 券入库（可后续激活），但不弹招募界面（无 RECRUIT pending）
    const tickets = Object.values(rlv2.inventory.recruit) as any[];
    expect(
      tickets.some((t) => t.id === "rogue_6_recruit_ticket_sniper" && t.state === 0),
    ).toBe(true);
    expect(
      rlv2._status.pending.some((e: any) => e.type === "RECRUIT"),
    ).toBe(false);
  });
});
