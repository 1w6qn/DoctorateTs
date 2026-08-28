import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({
    completeState: 2,
    finalHp: 10,
    isPerfect: 1,
  }),
}));

vi.mock("@game/modules/account/AccountManager", () => ({
  accountManager: {
    getBattleInfo: vi.fn().mockResolvedValue({ stageId: "ro6_n_1_1" }),
  },
}));

// 官服 rogue_6（黑流树海）battleFinish 抓包 mock：
// rewards = [金(0), 废品(1), 职业招募券(2)]，earn.populationMax=4，show="2"；
// 黑流树海收藏品/碎片不随战斗掉落 → items 虽含 fragment 也不该出现在奖励组。
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
        rogue_6: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          items: {
            rogue_6_gold: { id: "rogue_6_gold", type: "GOLD", rarity: "NONE" },
            rogue_6_shield: { id: "rogue_6_shield", type: "SHIELD", rarity: "NONE" },
            rogue_6_fragment_sd_1: { id: "rogue_6_fragment_sd_1", type: "FRAGMENT", rarity: "NONE" },
          },
          relics: {},
          recruitTickets: {
            rogue_6_recruit_ticket_sniper: { id: "rogue_6_recruit_ticket_sniper", professionList: ["SNIPER"], rarityList: ["TIER_3", "TIER_4", "TIER_5", "TIER_6"] },
          },
          detailConst: {
            playerLevelTable: {
              2: { exp: 10, populationUp: 4 },
              3: { exp: 24, populationUp: 4 },
            },
          },
        },
      },
      modules: {
        rogue_6: {
          moduleTypes: ["SCRAP"],
          scrap: {
            scrapItemToType: {
              rogue_6_scrap_P_01: {},
              rogue_6_scrap_P_02: {},
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

import { PlayerDataManager } from "@game/kernel/PlayerDataManager";
import { decryptBattleData } from "@utils/crypt";
import { mockPlayerData } from "../../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: { outer: {}, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  player.rlv2.current.game = { theme: "rogue_6", mode: "NORMAL", modeGrade: 0, predefined: null, start: 1 } as any;
  return player;
}

describe("rlv2 黑流树海（rogue_6）战斗胜利奖励对齐官服 battleFinish 抓包", () => {
  let player: PlayerDataManager;
  let randomSpy: any;

  beforeEach(async () => {
    player = makePlayer();
    // 构造期 emit 的 rlv2:init 是异步（Emittery），等待其 listener 完成后再注入 BATTLE 事件
    await new Promise((r) => setTimeout(r, 0));
    (player.rlv2 as any)._status._pending._pending.push({ type: "BATTLE", content: {} });
    (player.rlv2 as any)._status.property.hp = { current: 10, max: 10 };
    (player.rlv2 as any)._status.property.level = 1;
    // Math.random 固定 0.1：非 boss 必掉 1 件废品（<0.5）
    randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.1);
  });

  afterEach(() => {
    randomSpy.mockRestore();
  });

  async function finishBattle(stageId: string) {
    // 黑流树海地图 zone 键为区域索引（层1 → "1000"）
    (player.rlv2 as any)._map.zones["1000"] = {
      nodes: { "100": { pos: { x: 1, y: 0 }, next: [], type: 1, stage: stageId } },
    };
    (player.rlv2 as any)._status.cursor.zone = 1;
    (player.rlv2 as any)._status.cursor.position = { x: 1, y: 0 };
    await (player.rlv2 as any)._battle.finish([
      { battleLog: "", data: "encrypted", battleData: { completeState: 2 } },
    ]);
  }

  it("奖励组应为金/废品/职业招募券（顺序与 id 对齐官服）", async () => {
    await finishBattle("ro6_n_1_1");
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    expect(rewardEvent).toBeDefined();
    const { earn, rewards, show } = rewardEvent.content.battleReward;

    // 顺序：金(0) → 废品(1) → 招募券(2)
    expect(rewards.length).toBeGreaterThanOrEqual(3);
    expect(rewards[0]).toMatchObject({
      index: 0,
      items: [{ sub: 0, id: "rogue_6_gold", count: expect.any(Number) }],
      done: 0,
    });

    const scrapGrp = rewards[1];
    expect(scrapGrp.index).toBe(1);
    expect(scrapGrp.items.every((it: any) => String(it.id).startsWith("rogue_6_scrap_P_"))).toBe(true);

    const ticketGrp = rewards[2];
    expect(ticketGrp.index).toBe(2);
    const ticketId = ticketGrp.items[0].id;
    // 官服发职业券（rogue_6_recruit_ticket_sniper）而非通用 _all
    expect(ticketId).toMatch(
      /^rogue_6_recruit_ticket_(pioneer|warrior|tank|sniper|caster|support|medic|special)$/,
    );

    // 黑流树海收藏品/碎片不随战斗掉落
    const allIds = rewards.flatMap((r: any) => r.items.map((it: any) => String(it.id)));
    expect(allIds.some((id: string) => id.includes("fragment"))).toBe(false);
    expect(allIds.some((id: string) => id.includes("relic"))).toBe(false);

    // show 对齐官服（"2"）
    expect(show).toBe("2");
  });

  it("earn.populationMax 取下一级希望上限（官服 =4），exp = 需求值 + 三星加成（10+3）", async () => {
    await finishBattle("ro6_n_1_1");
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    const { earn } = rewardEvent.content.battleReward;
    expect(earn.populationMax).toBe(4); // lv2.populationUp
    expect(earn.exp).toBe(13); // lv2.exp 10 + isPerfect 3（官服单点抓包 exp=13）
  });

  it("战斗结束不回血，earn.damage/hp/shield 恒 0（官服口径）", async () => {
    (player.rlv2 as any)._status.property.hp = { current: 4, max: 8 };
    await finishBattle("ro6_n_1_1");
    const rewardEvent = (player.rlv2 as any)._status.pending.find(
      (e: any) => e.type === "BATTLE_REWARD",
    );
    const { earn } = rewardEvent.content.battleReward;
    expect(earn.damage).toBe(0);
    expect(earn.hp).toBe(0);
    expect(earn.shield).toBe(0);
    // 不因战斗结算回复目标生命（官服无此行为）
    expect((player.rlv2 as any)._status.property.hp.current).toBe(4);
  });

  it("战斗战败（completeState=1）不生成 BATTLE_REWARD，直接触发 gameSettle 结束本局", async () => {
    // 战败路径：completeState 语义 1=失败（2/3=胜利）——战败即结算终止。
    // 结算内部依赖完整；此处 spy 校验战败分支确实调用 gameSettle（完整结算由 settle 套件覆盖）。
    const settleSpy = vi
      .spyOn(player.rlv2 as any, "gameSettle")
      .mockResolvedValue(undefined);
    try {
      (decryptBattleData as any).mockResolvedValueOnce({
        completeState: 1,
        finalHp: 5,
        isPerfect: 0,
      });
      (player.rlv2 as any)._map.zones["1000"] = {
        nodes: { "100": { pos: { x: 1, y: 0 }, next: [], type: 1, stage: "ro6_n_1_1" } },
      };
      (player.rlv2 as any)._status.cursor.zone = 1;
      (player.rlv2 as any)._status.cursor.position = { x: 1, y: 0 };
      await (player.rlv2 as any)._battle.finish([
        { battleLog: "", data: "encrypted", battleData: { completeState: 1 } },
      ]);
      // 战败不弹战斗奖励
      expect(
        (player.rlv2 as any)._status.pending.some(
          (e: any) => e.type === "BATTLE_REWARD",
        ),
      ).toBe(false);
      // 直接触发结算，runResult 标记为 fail（非 success → 结算页显示失败）
      expect(settleSpy).toHaveBeenCalledTimes(1);
      expect((player.rlv2 as any)._status.runResult).toBe("fail");
    } finally {
      settleSpy.mockRestore();
    }
  });

  it("指挥分队升级（battle_extra_drop）：护盾低于阈值时战斗结束 +1 护盾，达标不追加", async () => {
    // 注入 band_2 升级效果：护盾 <5 时每次战斗结束额外获得 1 点护盾
    await (player.rlv2 as any)._trigger.emit("rlv2:buff:apply", [
      [
        {
          key: "battle_extra_drop",
          blackboard: [
            { key: "threshold", value: 5, valueStr: null },
            { key: "id", value: 0, valueStr: "rogue_6_shield" },
            { key: "count", value: 1, valueStr: null },
          ],
        },
      ],
    ]);
    (player.rlv2 as any)._status.property.shield = 0;
    await finishBattle("ro6_n_1_1");
    expect((player.rlv2 as any)._status.property.shield).toBe(1);
    // 护盾已达阈值（5）：再战不追加；未达阈值继续补到阈值前持续生效——
    // 此处验证达标不追加：手动置 5，再战仍为 5（阈值判定为 < 而非 <=）
    (player.rlv2 as any)._status._pending._pending.push({ type: "BATTLE", content: {} });
    (player.rlv2 as any)._status.property.shield = 5;
    await finishBattle("ro6_n_1_1");
    expect((player.rlv2 as any)._status.property.shield).toBe(5);
  });

  it("chooseBattleReward：gold 实时入账；招募券仅入券列表不自动弹招募（官服口径）", async () => {
    // 清空上一 BATTLE 事件，确保要选的 BATTLE_REWARD 位于 pending[0]（chooseBattleReward 读队首）
    (player.rlv2 as any)._status._pending._pending.length = 0;
    // 直接注入 BATTLE_REWARD pending：金组(index0) + 职业招募券组(index1)
    (player.rlv2 as any)._status._pending._pending.push({
      type: "BATTLE_REWARD",
      content: {
        battleReward: {
          earn: {},
          rewards: [
            { index: 0, items: [{ sub: 0, id: "rogue_6_gold", count: 5 }], done: 0 },
            { index: 1, items: [{ sub: 0, id: "rogue_6_recruit_ticket_sniper", count: 1 }], done: 0 },
          ],
          show: "2",
          state: 0,
        },
      },
    });
    (player.rlv2 as any)._status.property.gold = 0;

    // 选金：gold 实时入账（getItem 异步，chooseBattleReward 需 await 后才更新）
    await (player.rlv2 as any).chooseBattleReward({ index: 0, sub: 0 });
    expect((player.rlv2 as any)._status.property.gold).toBe(5);

    // 选招募券：券以 state=0 入招募券列表（玩家自行激活）；不自动弹招募界面（无 RECRUIT pending）
    await (player.rlv2 as any).chooseBattleReward({ index: 1, sub: 0 });
    const tickets = Object.values(player.rlv2.inventory.recruit) as any[];
    expect(
      tickets.some((t) => t.id === "rogue_6_recruit_ticket_sniper" && t.state === 0),
    ).toBe(true);
    expect(
      (player.rlv2 as any)._status.pending.some((e: any) => e.type === "RECRUIT"),
    ).toBe(false);
  });
});