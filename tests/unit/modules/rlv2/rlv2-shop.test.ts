import { describe, it, expect, vi, beforeEach } from "vitest";

// 官方 excel mock：rogue_1 带商品池（票/碎片/战术道具/各稀有度藏品）；rogue_6 带 SCRAP 池
vi.mock("@excel/excel", () => {
  const items: any = {
    rogue_1_relic_a: { type: "RELIC", rarity: "NORMAL" },
    rogue_1_relic_b: { type: "RELIC", rarity: "RARE" },
    rogue_1_relic_c: { type: "RELIC", rarity: "SUPER_RARE" },
    rogue_1_relic_d: { type: "RELIC", rarity: "NORMAL" },
    rogue_1_relic_e: { type: "RELIC", rarity: "RARE" },
    rogue_1_fragment_I_1: { type: "FRAGMENT" },
    rogue_1_active_tool_1: { type: "ACTIVE_TOOL" },
    rogue_6_scrap_G_01: { type: "SCRAP" },
    rogue_6_legacy_01: { type: "LEGACY" },
  };
  return {
    default: {
      RoguelikeTopicTable: {
        details: {
          rogue_1: {
            init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
            choices: { choice_leave: { type: "LEAVE", nextSceneId: null } },
            choiceScenes: {},
            stages: { ro1_n_1_1: { id: "ro1_n_1_1" } },
            gameConst: { unlockRouteItemId: null, unlockRouteItemCount: 0 },
            items,
            relics: {},
            recruitTickets: { rogue_1_recruit_ticket_caster: {} },
            detailConst: { playerLevelTable: {} },
            milestones: [],
          },
          rogue_6: {
            init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
            choices: {},
            choiceScenes: {},
            stages: {},
            gameConst: {},
            items,
            relics: {},
            recruitTickets: {},
            detailConst: { playerLevelTable: {} },
            milestones: [],
          },
        },
        modules: {
          rogue_1: { fragment: { fragmentData: {} } },
          rogue_6: {
            scrap: { scrapItemToType: { rogue_6_scrap_G_01: "G" } },
          },
        },
        consts: {},
      },
      CharacterTable: {},
      RoguelikeConsts: {
        rogue_1: { outbuff: {}, modebuff: {}, recruitGrps: {} },
        rogue_6: { outbuff: {}, modebuff: {}, recruitGrps: {} },
      },
    },
  };
});

import { PlayerDataManager } from "@game/service/manager/PlayerDataManager";
import { RoguelikeScrapManager } from "@game/service/rlv2/modules/scrap";
import { mockPlayerData } from "../../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    rlv2: { outer: {}, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  return new PlayerDataManager(pd._playerdata);
}

describe("rlv2 商店系统（BATTLE_SHOP）", () => {
  let player: PlayerDataManager;

  beforeEach(async () => {
    player = makePlayer();
    // 控制器构造期 emit("rlv2:init") 为异步（Emittery）——等微任务落定后再改状态，
    // 否则 status.init 的异步重置会覆盖下面的 zone 赋值
    await new Promise((r) => setTimeout(r, 0));
    player.rlv2.current.game = {
      theme: "rogue_1",
      mode: "NORMAL",
      modeGrade: 0,
      predefined: null,
    } as any;
    (player.rlv2 as any)._status.cursor.zone = 1;
  });

  /** 向状态机注入 pending 事件（pending 为只读 getter，经内部数组操作） */
  function pushPending(event: any) {
    (player.rlv2 as any)._status._pending._pending.push(event);
  }

  describe("buildShopContent", () => {
    it("应生成官方 battleShop 线格式（bank/id/goods/价格/刷新次数）", () => {
      const shop = (player.rlv2 as any).buildShopContent("rogue_1");
      expect(shop.id).toBe("zone_1_shop");
      expect(shop.bank.open).toBe(true);
      expect(shop.canBattle).toBe(true);
      expect(shop.hasBoss).toBe(true);
      expect(shop.refreshCnt).toBeGreaterThan(0);
      expect(shop.goods.length).toBeGreaterThanOrEqual(5);
      // 每件商品带官方字段
      for (const g of shop.goods) {
        expect(g.index).toBeDefined();
        expect(g.itemId).toBeDefined();
        expect(g.count).toBe(1);
        expect(g.priceId).toBe("rogue_1_gold");
        expect(g.priceCount).toBeGreaterThan(0);
        expect(g.origCost).toBeGreaterThan(0);
        expect(g.displayPriceChg).toBeTypeOf("boolean");
        expect(g._retainDiscount).toBeGreaterThan(0);
      }
      // 稀有度定价（origCost 为基准价，priceCount 可能打折减半）
      const relic = shop.goods.find((g: any) => g.itemId === "rogue_1_relic_c");
      expect(relic.origCost).toBe(16);
      expect([8, 16]).toContain(relic.priceCount);
      const frag = shop.goods.find((g: any) => g.itemId === "rogue_1_fragment_I_1");
      expect(frag.origCost).toBe(4);
      expect([2, 4]).toContain(frag.priceCount);
      // FRAGMENT 模块主题：附回收商品
      expect(shop.recycleGoods.length).toBeGreaterThan(0);
      expect(shop.recycleCount).toBe(shop.recycleGoods.length);
    });

    it("网格区域（zone 1000 起）商店 id 应还原为层号", () => {
      (player.rlv2 as any)._status.cursor.zone = 1000;
      const shop = (player.rlv2 as any).buildShopContent("rogue_1");
      expect(shop.id).toBe("zone_1_shop");
    });
  });

  describe("moveTo SHOP 节点", () => {
    it("应生成带真实商品的 BATTLE_SHOP pending 事件", async () => {
      (player.rlv2 as any)._map.zones[1] = {
        id: "zone_1",
        nodes: {
          "100": {
            index: "100",
            pos: { x: 1, y: 0 },
            next: [],
            type: 8, // SHOP
          },
        },
      };
      (player.rlv2 as any)._status.cursor.position = null;
      await (player.rlv2 as any).moveTo({ to: { x: 1, y: 0 } });

      const pending = (player.rlv2 as any)._status.pending;
      const shopEvent = pending.find((e: any) => e.type === "BATTLE_SHOP");
      expect(shopEvent).toBeDefined();
      expect(shopEvent.content.battleShop).toBeDefined();
      expect(shopEvent.content.battleShop.goods.length).toBeGreaterThan(0);
      expect((player.rlv2 as any)._status.state).toBe("PENDING");
    });
  });

  describe("buyGoods", () => {
    it("应扣金币并将商品置为售罄（count=0，官方保留列表）", async () => {
      const shop = (player.rlv2 as any).buildShopContent("rogue_1");
      pushPending({ type: "BATTLE_SHOP", content: { battleShop: shop } });
      (player.rlv2 as any)._status.property.gold = 100;

      await (player.rlv2 as any).buyGoods({ select: 0 });

      const good = shop.goods[0];
      expect(good.count).toBe(0);
      expect((player.rlv2 as any)._status.property.gold).toBe(
        100 - good.priceCount,
      );
    });

    it("金币不足不应扣款/售出", async () => {
      const shop = (player.rlv2 as any).buildShopContent("rogue_1");
      pushPending({ type: "BATTLE_SHOP", content: { battleShop: shop } });
      (player.rlv2 as any)._status.property.gold = 1;

      await (player.rlv2 as any).buyGoods({ select: 0 });

      expect(shop.goods[0].count).toBe(1);
      expect((player.rlv2 as any)._status.property.gold).toBe(1);
    });

    it("已售罄商品不可重复购买", async () => {
      const shop = (player.rlv2 as any).buildShopContent("rogue_1");
      shop.goods[0].count = 0;
      pushPending({ type: "BATTLE_SHOP", content: { battleShop: shop } });
      const gold = (player.rlv2 as any)._status.property.gold = 100;

      await (player.rlv2 as any).buyGoods({ select: 0 });
      expect((player.rlv2 as any)._status.property.gold).toBe(gold);
    });

    it("无商店 pending 应静默返回", async () => {
      pushPending({ type: "BATTLE", content: {} });
      await (player.rlv2 as any).buyGoods({ select: 0 });
    });
  });

  describe("refreshShop", () => {
    it("应重生成商品并扣刷新次数（battleShop 键）", async () => {
      const shop = (player.rlv2 as any).buildShopContent("rogue_1");
      const oldGoods = shop.goods;
      pushPending({ type: "BATTLE_SHOP", content: { battleShop: shop } });

      await (player.rlv2 as any).refreshShop();

      expect(shop.refreshCnt).toBe(1);
      expect(shop.goods).not.toBe(oldGoods);
      expect(shop.goods.length).toBeGreaterThan(0);
    });

    it("刷新次数耗尽后不再刷新", async () => {
      const shop = (player.rlv2 as any).buildShopContent("rogue_1");
      shop.refreshCnt = 0;
      const oldGoods = shop.goods;
      pushPending({ type: "BATTLE_SHOP", content: { battleShop: shop } });

      await (player.rlv2 as any).refreshShop();
      expect(shop.goods).toBe(oldGoods);
    });
  });

  describe("leaveShop", () => {
    it("应清空 pending 并回到 WAIT_MOVE", async () => {
      const shop = (player.rlv2 as any).buildShopContent("rogue_1");
      pushPending({ type: "BATTLE_SHOP", content: { battleShop: shop } });
      (player.rlv2 as any)._status.state = "PENDING";

      await (player.rlv2 as any).leaveShop();

      expect((player.rlv2 as any)._status.pending).toHaveLength(0);
      expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
    });
  });

  describe("scrapIdentify（rogue_6 废品鉴定）", () => {
    it("应返回 scrap/legacy 组并写入零件箱", async () => {
      player.rlv2.current.game = {
        theme: "rogue_6",
        mode: "NORMAL",
        modeGrade: 0,
        predefined: null,
      } as any;
      // 真实 SCRAP 管理器接线（订阅 rlv2:scrap:gain）
      const sm = new RoguelikeScrapManager(
        player.rlv2 as any,
        (player.rlv2 as any)._trigger,
      );
      (player.rlv2 as any)._module._modules["SCRAP"] = sm;

      const ret = await (player.rlv2 as any).scrapIdentify({ count: 2 });

      expect(ret.scrap.length).toBe(2);
      expect(ret.scrap[0].id).toMatch(/^rogue_6_scrap_/);
      expect(ret.legacy.length).toBeGreaterThanOrEqual(1);
      // 已写入零件箱（s_3 起——初始 s_1/s_2 播种后 _index=3）
      expect(Object.keys(sm.inventory).some((k) => k === "s_3")).toBe(true);
      expect(sm.inventory["s_3"].id).toBe(ret.scrap[0].id);
    });
  });
});
