import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
/** excel mock 行形状（本文件用到的字段子集） */
interface ExcelRowMock {
  name?: string;
}

/** 干员行夹具形状（本文件用到的字段子集） */
interface ExcelCharRowMock {
  charId?: string;
  rarity?: string;
  profession?: string;
}

vi.mock("@excel/excel", () => ({
  default: {
    ActivityTable: {
      anniv7thData: {
        clueRewardData: [
          { clueRecordId: "clueActivity_1", clueRecord: 1, rewards: [{ id: "31024", count: 1, type: "MATERIAL" }] },
          { clueRecordId: "clueActivity_2", clueRecord: 3, rewards: [{ id: "31054", count: 1, type: "MATERIAL" }] },
        ],
      },
    },
  },
}));
import type { Response } from "express";
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";

/** 主线线索请求体视图（兼容 ids 数组与旧单 id 写法） */
interface MainlineClueBody {
  ids?: string[];
  id?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: MainlineClueBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  type: Response["type"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof rootRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    type: vi.fn<Response["type"]>().mockReturnThis(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(player: MockPlayerDataManager, body: MainlineClueBody): Promise<MockRes> {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  const req: MockReq = { method: "POST", url: "/mainlineClue/getRewards", body };
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  rootRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("mainlineClue getRewards", () => {
  let player: MockPlayerDataManager;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" },
      mainline: { clue: { unlock: false, state: { clue_1_1: 2, clue_1_2: 2 }, reward: {} } },
    });
  });

  it("ids 全部达标时发放奖励并标记已领取", async () => {
    const res = await call(player, { ids: ["clueActivity_1"] });
    const response = vi.mocked(res.send).mock.calls[0][0];
    expect(response.items).toEqual([{ type: "MATERIAL", id: "31024", count: 1 }]);
    expect(player._playerdata.mainline.clue.reward["clueActivity_1"]).toBe(1);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("已领取的线索奖励不重复发放", async () => {
    player._playerdata.mainline.clue.reward["clueActivity_1"] = 1;
    const res = await call(player, { ids: ["clueActivity_1"] });
    expect(vi.mocked(res.send).mock.calls[0][0].items).toEqual([]);
  });

  it("已解锁线索数不足时（gainedRecord < clueRecord）不发放", async () => {
    const res = await call(player, { ids: ["clueActivity_2"] });
    expect(vi.mocked(res.send).mock.calls[0][0].items).toEqual([]);
    expect(player._playerdata.mainline.clue.reward["clueActivity_2"]).toBeUndefined();
  });

  it("兼容旧单 id 请求写法", async () => {
    const res = await call(player, { id: "clueActivity_1" });
    expect(vi.mocked(res.send).mock.calls[0][0].items).toEqual([{ type: "MATERIAL", id: "31024", count: 1 }]);
  });

  it("unlockClue 仍写 state[id]=2", async () => {
    const res = mockRes();
    vi.mocked(httpContext.get).mockReturnValue(player);
    const req: MockReq = { method: "POST", url: "/mainlineClue/unlockClue", body: { id: "clue_1_3" } };
    rootRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
    expect(player._playerdata.mainline.clue.state["clue_1_3"]).toBe(2);
  });
});
