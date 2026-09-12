/**
 * ODPY 9-10 同步新增路由的单元测试（2026-09-11）
 *
 * 覆盖 /rlv2/{setSeed, battlePass/buyReward, copper/change, copper/confirmDraw}
 * 四条新增端点的领域行为（unlockBuff 的节点逻辑已有 rlv2-unlock-buff.test.ts 覆盖，
 * 本次只补路由接线）。
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    ItemTable: { items: { "4001": { itemId: "4001", name: "龙门币", itemType: "GOLD" } } },
    getItem(id: string) {
      return (this as any).ItemTable?.items?.[id];
    },
    itemName(id: string) {
      return this.getItem(id)?.name ?? id;
    },
    makeItem(id: string, count: number, type?: string) {
      return type ? { id, count, type } : { id, count };
    },
    charData: () => undefined,
    stageData: () => undefined,
    RoguelikeTopicTable: {
      details: {
        rogue_6: {
          milestones: [
            { id: "bp_level_1", tokenNum: 200, itemID: "4001", itemType: "GOLD", itemCount: 20000 },
            { id: "bp_level_2", tokenNum: 400, itemID: "4001", itemType: "GOLD", itemCount: 30000 },
          ],
          grandPrizes: [{ grandPrizeDisplayId: "grand_1", bpLevelId: "bp_level_1" }],
        },
      },
      modules: {},
      consts: {},
    },
    RoguelikeConsts: {},
  },
}));

import { PlayerDataManager } from "@game/kernel/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";
import { RLV2_SEED_LENGTH } from "@game/modules/roguelike/game-init";

/** 构造带 rogue_6 outer 数据的玩家（bp 点数 1000） */
function makePlayer() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    status: { uid: 1, nickName: "T", nickNumber: 0, level: 1, exp: 0, gold: 0 } as any,
    rlv2: {
      outer: {
        rogue_6: {
          bp: { point: 1000, reward: {} },
          buff: { pointOwned: 0, pointCost: 0, unlocked: {}, score: 0 },
        },
      },
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: {
      missions: { DAILY: {}, ACTIVITY: {} },
      missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} },
    } as any,
  });
  return new PlayerDataManager(pd._playerdata);
}

describe("rlv2 setSeed（自定义种子）", () => {
  const seed = "a".repeat(RLV2_SEED_LENGTH);

  it("合法种子返回 SUCCESS(0) 并被下一局消费", async () => {
    const player = makePlayer();
    (player.rlv2 as any).current.game = { theme: "rogue_6", modeGrade: 15 };
    const ret = await (player.rlv2 as any).setSeed({ seed });
    expect(ret).toEqual({ result: 0 });
    // 结算种子 = 自定义种子 + 主题 + 难度（一次性消费）
    expect((player.rlv2 as any).gameSeed()).toBe(`${seed},rogue_6,15`);
    expect((player.rlv2 as any)._pendingSeed).toBeNull();
  });

  it("长度不符返回 INVALID_LENGTH(1)，字符集不符返回 INVALID_CHARSET(2)", async () => {
    const player = makePlayer();
    const short = await (player.rlv2 as any).setSeed({ seed: "abc" });
    expect(short).toEqual({ result: 1 });
    const bad = await (player.rlv2 as any).setSeed({
      seed: "!".repeat(RLV2_SEED_LENGTH),
    });
    expect(bad).toEqual({ result: 2 });
    // 失败不得写入待用种子
    expect((player.rlv2 as any)._pendingSeed).toBeNull();
  });

  it("未设种子时随机生成 18 位（与官服种子长度一致）", async () => {
    const player = makePlayer();
    (player.rlv2 as any).current.game = { theme: "rogue_6", modeGrade: 0 };
    const seedStr = (player.rlv2 as any).gameSeed();
    const [rand] = seedStr.split(",");
    expect(rand).toHaveLength(RLV2_SEED_LENGTH);
    expect(rand).toMatch(/^[0-9A-Za-z]+$/);
  });

  it("同一局内种子固定；开新局清缓存后重新生成", async () => {
    const player = makePlayer();
    (player.rlv2 as any).current.game = { theme: "rogue_6", modeGrade: 0 };
    const first = (player.rlv2 as any).gameSeed();
    // 同局重复读取复用缓存（结算 brief.seed 与分享串稳定）
    expect((player.rlv2 as any).gameSeed()).toBe(first);
    // createGame 开新局时清空缓存（game-init.ts `mgr._gameSeed = null`）→ 下一局换种子
    (player.rlv2 as any)._gameSeed = null;
    expect((player.rlv2 as any).gameSeed()).not.toBe(first);
  });
});

describe("rlv2 battlePass/buyReward（战令直购）", () => {
  it("扣点数、发奖并标记已领", async () => {
    const player = makePlayer();
    const { items } = await (player.rlv2 as any).battlePassBuyReward(
      "rogue_6",
      "bp_level_1",
      200,
    );
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ id: "4001", type: "GOLD", count: 20000 });
    const bp = (player.rlv2 as any).outer.rogue_6.bp;
    expect(bp.point).toBe(800);
    expect(bp.reward.bp_level_1).toBe(1);
  });

  it("大奖展示 id（grand_N）归一为里程碑 id", async () => {
    const player = makePlayer();
    await (player.rlv2 as any).battlePassBuyReward("rogue_6", "grand_1", 100);
    const bp = (player.rlv2 as any).outer.rogue_6.bp;
    expect(bp.reward.bp_level_1).toBe(1);
    expect(bp.point).toBe(900);
  });

  it("重复购买不再发放（幂等）", async () => {
    const player = makePlayer();
    await (player.rlv2 as any).battlePassBuyReward("rogue_6", "bp_level_1", 200);
    const second = await (player.rlv2 as any).battlePassBuyReward(
      "rogue_6",
      "bp_level_1",
      200,
    );
    expect(second.items).toHaveLength(0);
    expect((player.rlv2 as any).outer.rogue_6.bp.point).toBe(800);
  });

  it("点数不足不扣不发", async () => {
    const player = makePlayer();
    const { items } = await (player.rlv2 as any).battlePassBuyReward(
      "rogue_6",
      "bp_level_2",
      5000,
    );
    expect(items).toHaveLength(0);
    expect((player.rlv2 as any).outer.rogue_6.bp.point).toBe(1000);
    expect((player.rlv2 as any).outer.rogue_6.bp.reward.bp_level_2).toBeUndefined();
  });

  it("未知奖励 id 不改数据", async () => {
    const player = makePlayer();
    const { items } = await (player.rlv2 as any).battlePassBuyReward(
      "rogue_6",
      "bp_level_999",
      10,
    );
    expect(items).toHaveLength(0);
    expect((player.rlv2 as any).outer.rogue_6.bp.point).toBe(1000);
  });
});

describe("rlv2 copper/change 与 copper/confirmDraw（状态机）", () => {
  let player: PlayerDataManager;

  beforeEach(() => {
    player = makePlayer();
  });

  it("confirmDraw 清空挂起事件并回到 WAIT_MOVE", async () => {
    (player.rlv2 as any)._status._pending._pending = [{ type: "DRAW_COPPER" }];
    (player.rlv2 as any)._status.state = "PENDING";
    await (player.rlv2 as any).copperConfirmDraw();
    expect((player.rlv2 as any)._status._pending._pending).toHaveLength(0);
    expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
  });

  it("change 不篡改铜钱袋（对齐 ODPY 空操作语义）并回到 WAIT_MOVE", async () => {
    const copper = (player.rlv2 as any)._module?.copper;
    const before = copper ? JSON.stringify(copper.bag) : null;
    (player.rlv2 as any)._status.state = "PENDING";
    await (player.rlv2 as any).copperChange({ index: "c_0" });
    expect(copper ? JSON.stringify(copper.bag) : null).toBe(before);
    expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
  });
});
