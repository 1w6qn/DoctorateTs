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
    SpecialOperatorTable: {
      operatorDetailData: {
        char_4230_mcnist: {
          nodeUnlockData: { mcnist_n_skill1_6: { nodeType: "SKILL" } },
        },
      },
    },
  },
}));
import type { Response } from "express";
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";

/** 特种干员解锁请求体视图 */
interface UnlockNodeBody {
  instId?: string;
  nodeId?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: UnlockNodeBody;
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

async function call(player: MockPlayerDataManager, body: UnlockNodeBody): Promise<MockRes> {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  const req: MockReq = { method: "POST", url: "/troop/SpecialOperatorUnlockNode", body };
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  rootRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("SpecialOperatorUnlockNode", () => {
  let player: MockPlayerDataManager;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" },
      troop: { chars: { "374": { charId: "char_4230_mcnist" } }, spOperator: {} },
    });
  });

  it("写 spOperator[charId][nodeType][nodeId] 节点对象", async () => {
    await call(player, { instId: "374", nodeId: "mcnist_n_skill1_6" });
    const so = player._playerdata.troop.spOperator;
    expect(so["char_4230_mcnist"]["SKILL"]["mcnist_n_skill1_6"]).toEqual({
      id: "mcnist_n_skill1_6",
      state: 1,
      type: "SKILL",
    });
  });

  it("未知 instId 不写状态", async () => {
    await call(player, { instId: "999", nodeId: "mcnist_n_skill1_6" });
    expect(player._playerdata.troop.spOperator["char_4230_mcnist"]).toBeUndefined();
  });

  it("未知 nodeId 不写状态", async () => {
    await call(player, { instId: "374", nodeId: "nope" });
    expect(player._playerdata.troop.spOperator["char_4230_mcnist"]).toBeUndefined();
  });
});
