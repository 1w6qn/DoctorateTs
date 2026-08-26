import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { decryptBattleData, decryptBattleReplay } from "@utils/crypt";

// 默认 mock：解密返回完整战报（含 stats.totalDamage/checkKilledCnt 与 isCheat），
// 回放（battleLog）解析返回对象。
vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({
    completeState: 2,
    finalHp: 10,
    isPerfect: 0,
    battleData: {
      isCheat: "cheat-token",
      stats: { totalDamage: 1200, checkKilledCnt: 45 },
    },
  }),
  decryptBattleReplay: vi.fn().mockResolvedValue({
    actions: ["attack"],
    rounds: 3,
  }),
}));

vi.mock("@game/manager/AccountManager", () => ({
  accountManager: {
    getBattleInfo: vi.fn().mockResolvedValue({ stageId: "ro1_n_1_1" }),
  },
}));

// 官方 excel mock：rogue_1 items 含 RELIC（收藏品池）+ fragment
vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_1: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          items: {
            rogue_1_relic_a01: { id: "rogue_1_relic_a01", type: "RELIC", rarity: "NORMAL", canSacrifice: true, value: 8 },
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
import { mockPlayerData } from "../../../helpers";

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

describe("rlv2 battleFinish 战报字段消费（data/battleData/battleLog）", () => {
  let player: PlayerDataManager;
  let saveSpy: any;
  let randomSpy: any;

  beforeEach(async () => {
    player = makePlayer();
    // 构造期 emit 的 rlv2:init 是异步（Emittery），等待其 listener 完成后再 create
    await new Promise((r) => setTimeout(r, 0));
    // 初始化收藏品池（battle 依赖 _pool）
    await (player.rlv2 as any)._pool.create();
    // BATTLE pending 事件（finish 会 shift）
    (player.rlv2 as any)._status._pending._pending.push({ type: "BATTLE", content: {} });
    (player.rlv2 as any)._status.property.hp = { current: 10, max: 10 };
    (player.rlv2 as any)._status.property.level = 1;
    // 标准主题地图节点（层号键）
    (player.rlv2 as any)._map.zones[1] = {
      nodes: { "100": { pos: { x: 1, y: 0 }, next: [], type: 1, stage: "ro1_n_1_1" } },
    };
    (player.rlv2 as any)._status.cursor.zone = 1;
    (player.rlv2 as any)._status.cursor.position = { x: 1, y: 0 };
    // 捕获留存记录内容（不落库）——controller._player 即同一 PlayerDataManager 实例
    saveSpy = vi.spyOn(player as any, "saveBattleRecord").mockResolvedValue(undefined);
    // Math.random 固定 0.1：命中 40% 收藏品概率、金币区间低位
    randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.1);
  });

  afterEach(() => {
    randomSpy.mockRestore();
    saveSpy?.mockRestore();
  });

  it("battleId 优先取战报回传值（无会话记录时也能解析上下文）", async () => {
    // 不经过 start（会话 Map 无记录）——战报 battleId 提供上下文
    await (player.rlv2 as any)._battle.finish([
      { battleLog: "", data: "encrypted", battleData: { battleId: "report-battle-1" } },
    ]);
    expect(saveSpy).toHaveBeenCalled();
    const record = saveSpy.mock.calls[0][0];
    expect(record.battleId).toBe("report-battle-1");
  });

  it("battleLog 解析结果与 isCheat 写入战斗记录", async () => {
    await (player.rlv2 as any)._battle.finish([
      { battleLog: "BASE64ZIP", data: "encrypted", battleData: { completeState: 2 } },
    ]);
    expect(decryptBattleReplay).toHaveBeenCalledWith("BASE64ZIP");
    const record = saveSpy.mock.calls[0][0];
    expect(record.battleLog).toEqual({ actions: ["attack"], rounds: 3 });
    expect(record.isCheat).toBe("cheat-token");
  });

  it("解密失败时请求明文 battleData 兜底判胜（仍生成 BATTLE_REWARD）", async () => {
    vi.mocked(decryptBattleData).mockRejectedValueOnce(new Error("bad data"));
    await (player.rlv2 as any)._battle.finish([
      { battleLog: "", data: "bad", battleData: { completeState: 2, finalHp: 5 } },
    ]);
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    expect(rewardEvent).toBeDefined();
  });

  it("无效 battleLog 不阻断结算（仅告警，仍判胜）", async () => {
    vi.mocked(decryptBattleReplay).mockRejectedValueOnce(new Error("bad base64"));
    await (player.rlv2 as any)._battle.finish([
      { battleLog: "garbage", data: "encrypted", battleData: { completeState: 2 } },
    ]);
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    expect(rewardEvent).toBeDefined();
  });

  it("earn.damage/hp/shield 恒 0（官服 battleFinish 口径；战报伤害仅存记录不入 earn）", async () => {
    await (player.rlv2 as any)._battle.finish([
      { battleLog: "", data: "encrypted", battleData: { completeState: 2 } },
    ]);
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    expect(rewardEvent.content.battleReward.earn.damage).toBe(0);
    expect(rewardEvent.content.battleReward.earn.hp).toBe(0);
    expect(rewardEvent.content.battleReward.earn.shield).toBe(0);
  });
});
