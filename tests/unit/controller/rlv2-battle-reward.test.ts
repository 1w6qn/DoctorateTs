import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";


vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({
    completeState: 1,
    finalHp: 10,
    isPerfect: 0,
  }),
}));

vi.mock("@game/manager/AccountManager", () => ({
  accountManager: {
    getBattleInfo: vi.fn().mockResolvedValue({ stageId: "ro1_n_1_1" }),
  },
}));

// 官方 excel mock：rogue_1 items 含 RELIC（收藏品池）+ fragment + detailConst
vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_1: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          items: {
            rogue_1_relic_a01: { id: "rogue_1_relic_a01", type: "RELIC", rarity: "NORMAL", canSacrifice: true, value: 8 },
            rogue_1_relic_a02: { id: "rogue_1_relic_a02", type: "RELIC", rarity: "NORMAL", canSacrifice: true, value: 8 },
            rogue_1_relic_b01: { id: "rogue_1_relic_b01", type: "RELIC", rarity: "RARE", canSacrifice: true, value: 12 },
            rogue_1_relic_b02: { id: "rogue_1_relic_b02", type: "RELIC", rarity: "RARE", canSacrifice: true, value: 12 },
            rogue_1_relic_c01: { id: "rogue_1_relic_c01", type: "RELIC", rarity: "SUPER_RARE", canSacrifice: false, value: 16 },
            rogue_1_fragment_I_1: { id: "rogue_1_fragment_I_1", type: "FRAGMENT", rarity: "NONE" },
            rogue_1_gold: { id: "rogue_1_gold", type: "GOLD", rarity: "NONE" },
          },
          relics: {},
          detailConst: { playerLevelTable: { 2: { exp: 10 } } },
        },
      },
      modules: { rogue_1: { fragment: { fragmentData: {} } } },
      consts: {},
    },
    CharacterTable: {},
    RoguelikeConsts: {},
  },
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: { outer: {}, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  player.rlv2.current.game = { theme: "rogue_1", mode: "NORMAL", modeGrade: 0, predefined: null, start: 1 } as any;
  return player;
}

describe("rlv2 战斗胜利收藏品掉落", () => {
  let player: PlayerDataManager;
  let randomSpy: any;

  beforeEach(async () => {
    player = makePlayer();
    // 构造期 emit 的 rlv2:init 是异步的（Emittery），等待其 listener 完成后再 create，
    // 否则 init() 会在 create() 之后清空 _pools
    await new Promise((r) => setTimeout(r, 0));
    // 初始化收藏品池（battle 依赖 _pool）
    await (player.rlv2 as any)._pool.create();
    // BATTLE pending 事件（finish 会 shift）
    (player.rlv2 as any)._status._pending._pending.push({ type: "BATTLE", content: {} });
    (player.rlv2 as any)._status.property.hp = { current: 10, max: 10 };
    (player.rlv2 as any)._status.property.level = 1;
    // Math.random 固定 0.1：命中 40% 收藏品概率、金币 6、碎片取第一个
    randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.1);
  });

  afterEach(() => {
    randomSpy.mockRestore();
  });

  async function finishBattle(stageId: string) {
    (player.rlv2 as any)._map.zones[1] = {
      nodes: { "100": { pos: { x: 1, y: 0 }, next: [], type: 1, stage: stageId } },
    };
    (player.rlv2 as any)._status.cursor.zone = 1;
    (player.rlv2 as any)._status.cursor.position = { x: 1, y: 0 };
    await (player.rlv2 as any)._battle.finish([
      { battleLog: "", data: "encrypted", battleData: { completeState: 1 } },
    ]);
  }

  it("普通战斗胜利应生成收藏品奖励项（概率命中）", async () => {
    await finishBattle("ro1_n_1_1");
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    expect(rewardEvent).toBeDefined();
    const rewards = rewardEvent.content.battleReward.rewards;
    // 收藏品项：items 含 RELIC id
    const relicGrp = rewards.find((r: any) =>
      r.items.some((it: any) => String(it.id).includes("relic"))
    );
    expect(relicGrp).toBeDefined();
    expect(relicGrp.items[0]).toEqual(
      expect.objectContaining({ sub: 0, count: 1 }),
    );
    expect(relicGrp.done).toBe(0);
  });

  it("boss 战斗必掉 2 个收藏品", async () => {
    await finishBattle("ro1_b_1");
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    const rewards = rewardEvent.content.battleReward.rewards;
    const relicGrp = rewards.find((r: any) =>
      r.items.some((it: any) => String(it.id).includes("relic"))
    );
    expect(relicGrp).toBeDefined();
    expect(relicGrp.items.length).toBe(2);
  });

  it("收藏品奖励 id 应来自收藏品池且不重复", async () => {
    await finishBattle("ro1_b_1");
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    const rewards = rewardEvent.content.battleReward.rewards;
    const relicGrp = rewards.find((r: any) =>
      r.items.some((it: any) => String(it.id).includes("relic"))
    );
    const ids = relicGrp.items.map((it: any) => it.id);
    expect(new Set(ids).size).toBe(ids.length); // 不重复
    const validRelics = ["rogue_1_relic_a01", "rogue_1_relic_a02", "rogue_1_relic_b01", "rogue_1_relic_b02", "rogue_1_relic_c01"];
    for (const id of ids) {
      expect(validRelics).toContain(id);
    }
  });
});
