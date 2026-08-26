import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_3: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL", initRelic: {}, initRecruit: {} }],
          recruitTickets: {},
        },
      },
      modules: {
        rogue_3: { totemBuff: { totemBuffDatas: {} } },
      },
      consts: {},
    },
    CharacterTable: {},
  },
}));

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

describe("rlv2 补全接口", () => {
  let player: PlayerDataManager;

  beforeEach(() => {
    player = makePlayer();
  });

  /** 向状态机注入 pending 事件（pending 为只读 getter，经内部数组操作） */
  function pushPending(event: any) {
    (player.rlv2 as any)._status._pending._pending.push(event);
  }

  describe("refreshShop", () => {
    it("应重生成商品并扣刷新次数", async () => {
      player.rlv2.current.game = { theme: "rogue_3", mode: "NORMAL" } as any;
      const shopEvent: any = {
        type: "SHOP",
        content: {
          shop: { id: "shop_1", goods: [{ index: "0", itemId: "x" }], refreshCnt: 2 },
        },
      };
      pushPending(shopEvent);
      (player.rlv2 as any).generateShopGoods = vi.fn().mockReturnValue([
        { index: "0", itemId: "relic_a" },
      ]);
      await (player.rlv2 as any).refreshShop();
      expect(shopEvent.content.shop.refreshCnt).toBe(1);
      expect(shopEvent.content.shop.goods).toEqual([{ index: "0", itemId: "relic_a" }]);
    });

    it("非 SHOP pending 不应刷新", async () => {
      pushPending({ type: "BATTLE", content: {} });
      const shopSpy = vi.fn();
      (player.rlv2 as any).generateShopGoods = shopSpy;
      await (player.rlv2 as any).refreshShop();
      expect(shopSpy).not.toHaveBeenCalled();
    });
  });

  describe("leaveShop", () => {
    it("应清空 pending 并回到 WAIT_MOVE", async () => {
      pushPending({ type: "SHOP", content: { shop: { goods: [] } } });
      (player.rlv2 as any)._status.state = "IN_SHOP";
      await (player.rlv2 as any).leaveShop();
      expect((player.rlv2 as any)._status.pending).toHaveLength(0);
      expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
    });
  });

  describe("confirmPredict", () => {
    it("应清空 pending 并回到 WAIT_MOVE", async () => {
      pushPending({ type: "PREDICT", content: {} });
      (player.rlv2 as any)._status.state = "IN_PREDICT";
      await (player.rlv2 as any).confirmPredict();
      expect((player.rlv2 as any)._status.pending).toHaveLength(0);
      expect((player.rlv2 as any)._status.state).toBe("WAIT_MOVE");
    });
  });

  describe("useTotem", () => {
    it("应调用图腾管理器 use 并标记已用", async () => {
      const totemUse = vi.fn();
      (player.rlv2 as any)._module._modules["TOTEM"] = { use: totemUse };
      await (player.rlv2 as any).useTotem({ totemIndex: ["t_0", "t_1"], nodeIndex: ["1"] });
      expect(totemUse).toHaveBeenCalledWith(["t_0", "t_1"], ["1"]);
    });
  });

  describe("closeRecruitTicket", () => {
    it("应关闭指定招募票（state=3 并清空列表）", async () => {
      player.rlv2.inventory.recruit["t_1"] = {
        index: "t_1",
        id: "ticket_1",
        state: 1,
        list: [{ instId: 0 }],
        result: null,
        ts: 0,
        from: "shop",
        mustExtra: 0,
        needAssist: false,
      } as any;
      await (player.rlv2 as any).closeRecruitTicket({ id: "t_1" });
      // 放弃票保留（state=3 终态）；inventory.recruit 由 finishEvent 初始阶段统一清空
      expect(player.rlv2.inventory.recruit["t_1"].state).toBe(3);
      expect(player.rlv2.inventory.recruit["t_1"].list).toHaveLength(0);
    });

    it("不存在的票应静默返回", async () => {
      await (player.rlv2 as any).closeRecruitTicket({ id: "t_999" });
    });
  });
});
