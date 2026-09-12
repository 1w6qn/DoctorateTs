import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import type { Response } from "express";
import httpContext from "express-http-context2";
import { rootRouter } from "@game/modules/activities";
import { mockPlayerData } from "../../helpers";

/** act25side 请求体视图（本文件各端点字段合集） */
interface Act25Body {
  stageId?: string;
  squad?: { slots?: { charInstId?: number; level?: number }[] };
  usePracticeTicket?: number;
  assistFriend?: string | null;
  data?: string;
  battleData?: { isCheat?: string; completeTime?: number };
  actId?: string;
  areaId?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: Act25Body;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof rootRouter>[0];

/** 战斗替身返回值（历史夹具；真实结算只 spread 后覆盖 result，故无需 result 键） */
const battleStartResult = {
  result: 0,
  battleId: "b1",
  apFailReturn: 0,
  isApProtect: 0,
  inApProtectPeriod: false,
  notifyPowerScoreNotEnoughIfFailed: false,
};

const battleFinishResult = {
  apFailReturn: 0,
  expScale: 1,
  goldScale: 1,
  rewards: [],
  firstRewards: [],
  unlockStages: [],
  unusualRewards: [],
  additionalRewards: [],
  furnitureRewards: [],
  alert: [],
  suggestFriend: false,
  pryResult: [],
};

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

/**
 * 组装 act25side 用例的玩家组合根
 *
 * `MockPlayerDataManager` 的窄接口不含 battle 的完整替身面（`battle.finish` 声明必带
 * `result`，而本用例历史夹具无该键），故用 `Object.assign` 在运行时挂 battle 替身，
 * 其余成员（update/_playerdata/delta/gainItem）保持 mock 原样。
 */
function makePlayer() {
  const mock = mockPlayerData({ status: { uid: "1" } });
  return Object.assign(mock, {
    battle: {
      start: vi.fn().mockResolvedValue(battleStartResult),
      finish: vi.fn().mockResolvedValue(battleFinishResult),
    },
  });
}

type PlayerFixture = ReturnType<typeof makePlayer>;

describe("act25side（生息演算）根路由", () => {
  let player: PlayerFixture;
  let res: MockRes;

  beforeEach(() => {
    vi.clearAllMocks();
    player = makePlayer();
    res = mockRes();
    vi.mocked(httpContext.get).mockReturnValue(player);
  });

  async function call(url: string, body: Act25Body) {
    const req: MockReq = { method: "POST", url, body };
    // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
    rootRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /act25side/battleStart 应复用 battle.start", async () => {
    await call("/act25side/battleStart", {
      stageId: "act25side_01",
      squad: { slots: [] },
      usePracticeTicket: 0,
      assistFriend: null,
    });
    expect(player.battle.start).toHaveBeenCalledWith(
      expect.objectContaining({ stageId: "act25side_01" })
    );
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 0, battleId: "b1" })
    );
  });

  it("POST /act25side/battleFinish 应复用 battle.finish", async () => {
    await call("/act25side/battleFinish", {
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    expect(player.battle.finish).toHaveBeenCalledWith({
      data: "x",
      battleData: { isCheat: "0", completeTime: 1 },
    });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ expScale: 1, goldScale: 1 })
    );
  });

  it("POST /act25side/dailyRefresh 应返回 tokenDelta 0", async () => {
    await call("/act25side/dailyRefresh", { actId: "act25side" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ tokenDelta: 0, reachRecvMax: false })
    );
  });

  it("POST /act25side/harvest 应返回空奖励", async () => {
    await call("/act25side/harvest", { actId: "act25side" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ items: [], additionalItems: [] })
    );
  });

  it("POST /act25side/investigate / finishInvestigation 应正常响应", async () => {
    await call("/act25side/investigate", { actId: "act25side", areaId: "area_1" });
    expect(res.send).toHaveBeenCalledWith({ playerDataDelta: {} });

    await call("/act25side/finishInvestigation", { actId: "act25side", areaId: "area_1" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ items: [] })
    );
  });
});
