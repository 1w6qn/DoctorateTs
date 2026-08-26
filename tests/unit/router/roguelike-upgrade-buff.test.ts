import { describe, it, expect, vi, beforeEach } from "vitest";


vi.mock("express-http-context2", () => ({
  default: {
    get: vi.fn(),
  },
}));

// mock accountManager（PlayerDataManager 构造依赖）
vi.mock("@game/service/manager/AccountManager", () => ({
  accountManager: {
    init: vi.fn().mockResolvedValue(undefined),
    getBattleInfo: vi.fn().mockResolvedValue({}),
  },
}));

vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_1: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
          items: {},
          relics: {},
        },
      },
      modules: { rogue_1: { fragment: null } },
      customizeData: {
        rogue_1: {
          developments: {
            outbuff_1: { buffId: "outbuff_1", frontNodeId: [], nextNodeId: [], tokenCost: 10, nodeType: "BRANCH" },
            outbuff_5: { buffId: "outbuff_5", frontNodeId: ["outbuff_1"], nextNodeId: [], tokenCost: 20, nodeType: "BRANCH" },
          },
        },
      },
      consts: {},
    },
    CharacterTable: {},
    RoguelikeConsts: {},
  },
}));

import httpContext from "express-http-context2";
import { PlayerDataManager } from "@game/service/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import router from "@game/service/router/roguelike";

function makePlayerData() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: {
      outer: {
        rogue_1: {
          buff: { pointOwned: 50, pointCost: 0, unlocked: {}, score: 0 },
        },
      },
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  return new PlayerDataManager(pd._playerdata);
}

function callRouter(method: string, path: string, body: any): Promise<{ status: number; data: any }> {
  return new Promise((resolve, reject) => {
    const req: any = { body, method, url: path };
    const res: any = {
      statusCode: 0,
      status(code: number) { this.statusCode = code; return this; },
      send(data: any) { resolve({ status: this.statusCode, data }); },
    };
    (router as any).handle(req, res, (err: any) => (err ? reject(err) : resolve({ status: res.statusCode, data: undefined })));
  });
}

describe("roguelike upgradeOutBuff 路由", () => {
  let player: PlayerDataManager;

  beforeEach(async () => {
    player = makePlayerData();
    (httpContext.get as any).mockReturnValue(player);
  });

  it("解锁成功返回 result 0 + delta 记录 unlocked", async () => {
    const { status, data } = await callRouter("POST", "/roguelike/upgradeOutBuff", {
      theme: "rogue_1",
      id: "outbuff_1",
    });
    expect(status).toBe(0);
    expect(data.result).toBe(0);
    // delta 记录了 outer 修改
    const delta = data.playerDataDelta;
    expect(delta.modified).toBeDefined();
    const buffDelta = JSON.stringify(delta.modified);
    expect(buffDelta).toContain("outbuff_1");
    // 内存状态已解锁
    expect(player._playerdata.rlv2.outer.rogue_1.buff.unlocked).toHaveProperty("outbuff_1", 1);
  });

  it("前置未解锁返回 result 1 + errorMsg", async () => {
    const { data } = await callRouter("POST", "/roguelike/upgradeOutBuff", {
      theme: "rogue_1",
      id: "outbuff_5",
    });
    expect(data.result).toBe(1);
    expect(data.errorMsg).toBe("FRONT_NOT_UNLOCKED");
    expect(player._playerdata.rlv2.outer.rogue_1.buff.pointOwned).toBe(50);
  });

  it("兼容 buffId 字段名", async () => {
    const { data } = await callRouter("POST", "/roguelike/upgradeOutBuff", {
      theme: "rogue_1",
      buffId: "outbuff_1",
    });
    expect(data.result).toBe(0);
  });
});
