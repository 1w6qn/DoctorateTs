import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";


vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({
    completeState: 2,
    finalHp: 10,
    isPerfect: 0,
  }),
}));

vi.mock("@game/service/player/AccountManager", () => ({
  accountManager: {
    getBattleInfo: vi.fn().mockResolvedValue({ stageId: "ro3_n_1_1" }),
  },
}));

// 官方 excel mock：rogue_3 含 CHAOS 模块数据（levelInfoDict）+ 收藏品池 + detailConst
vi.mock("@excel/excel", () => ({
  default: {
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string) { return this.CharacterTable?.[charId]; },
    stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },

    RoguelikeTopicTable: {
      details: {
        rogue_3: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          items: {
            rogue_3_relic_a01: { id: "rogue_3_relic_a01", type: "RELIC", rarity: "NORMAL", canSacrifice: true, value: 8 },
            rogue_3_relic_a02: { id: "rogue_3_relic_a02", type: "RELIC", rarity: "NORMAL", canSacrifice: true, value: 8 },
            rogue_3_relic_b01: { id: "rogue_3_relic_b01", type: "RELIC", rarity: "RARE", canSacrifice: true, value: 12 },
            rogue_3_fragment_I_1: { id: "rogue_3_fragment_I_1", type: "FRAGMENT", rarity: "NONE" },
            rogue_3_gold: { id: "rogue_3_gold", type: "GOLD", rarity: "NONE" },
          },
          relics: {},
          detailConst: { playerLevelTable: { 2: { exp: 10 } } },
        },
      },
      modules: {
        rogue_3: {
          moduleTypes: ["CHAOS", "VISION", "TOTEMBUFF"],
          chaos: {
            chaosDatas: {
              rogue_3_chaos_1: { id: "rogue_3_chaos_1", level: 1 },
              rogue_3_chaos_2: { id: "rogue_3_chaos_2", level: 2 },
            },
            levelInfoDict: {
              rule_1: {
                0: { chaosLevelBeginNum: 0, chaosLevelEndNum: 4 },
                1: { chaosLevelBeginNum: 4, chaosLevelEndNum: 8 },
              },
            },
          },
        },
      },
      consts: {},
    },
    CharacterTable: {},
    RoguelikeConsts: {},
  },
}));

import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: { outer: {}, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  player.rlv2.current.game = { theme: "rogue_3", mode: "NORMAL", modeGrade: 0, predefined: null, start: 1 } as any;
  return player;
}

describe("rlv2 战斗胜利驱动 CHAOS 坍缩", () => {
  let player: PlayerDataManager;
  let randomSpy: any;

  beforeEach(async () => {
    player = makePlayer();
    await new Promise((r) => setTimeout(r, 0));
    // 初始化收藏品池 + CHAOS 管理器
    await (player.rlv2 as any)._pool.create();
    await (player.rlv2 as any)._module.create();
    (player.rlv2 as any)._status._pending._pending.push({ type: "BATTLE", content: {} });
    (player.rlv2 as any)._status.property.hp = { current: 10, max: 10 };
    (player.rlv2 as any)._status.property.level = 1;
    randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.1);
  });

  afterEach(() => {
    randomSpy.mockRestore();
  });

  it("战斗胜利应累积坍缩值（gainChaos）", async () => {
    const chaosMgr = (player.rlv2 as any)._module.chaos;
    expect(chaosMgr).toBeTruthy();
    expect(chaosMgr.toJSON().value).toBe(0);
    // 模拟战斗胜利
    (player.rlv2 as any)._map.zones[1] = {
      nodes: { "100": { pos: { x: 1, y: 0 }, next: [], type: 1, stage: "ro3_n_1_1" } },
    };
    (player.rlv2 as any)._status.cursor.zone = 1;
    (player.rlv2 as any)._status.cursor.position = { x: 1, y: 0 };
    await (player.rlv2 as any)._battle.finish([
      { battleLog: "", data: "encrypted", battleData: { completeState: 2 } },
    ]);
    // 胜利 +1 坍缩值，deltaChaos.dValue = 1
    expect(chaosMgr.toJSON().value).toBe(1);
    expect(chaosMgr.toJSON().deltaChaos.dValue).toBe(1);
    expect(chaosMgr.toJSON().lastBattleGain).toBe(1);
  });

  it("连续胜利达到上限应升层并挂坍缩", async () => {
    const chaosMgr = (player.rlv2 as any)._module.chaos;
    // 直接驱动 gainChaos(4) 到上限（level 0 上限 4）
    chaosMgr.gainChaos(4);
    const json = chaosMgr.toJSON();
    expect(json.level).toBe(1);
    expect(json.value).toBe(0);
    // level 1 上限按官方 levelInfoDict = 8
    expect(json.curMaxValue).toBe(8);
    // 挂入 1 个坍缩（level 1 候选）
    expect(json.chaosList.length).toBe(1);
    expect(json.chaosList[0]).toBe("rogue_3_chaos_1");
  });
});
