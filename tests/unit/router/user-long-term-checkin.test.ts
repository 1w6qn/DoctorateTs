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
    OpenServerTable: {
      longTermCheckInData: {
        groupList: [
          {
            groupId: "signin_1",
            level: 80,
            days: 180,
            rewardList: [{ id: "avatar_dyn_01", count: 1, type: "PLAYER_AVATAR" }],
          },
        ],
        constData: { startTs: 1000000000 },
      },
    },
  },
}));
import type { Response } from "express";
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";

/** 长期签到请求体视图 */
interface LongTermCheckInBody {
  groupId?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: LongTermCheckInBody;
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

async function call(player: MockPlayerDataManager, body: LongTermCheckInBody): Promise<MockRes> {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  const req: MockReq = { method: "POST", url: "/user/recvLongTermCheckInReward", body };
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  rootRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("recvLongTermCheckInReward", () => {
  let player: MockPlayerDataManager;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1", level: 90 },
      checkIn: { showCount: 200, longTermRecvRecord: {} },
    });
  });

  it("达标时发放奖励、记录领取并返回 rewards", async () => {
    const res = await call(player, { groupId: "signin_1" });
    expect(vi.mocked(res.send).mock.calls[0][0].rewards).toEqual([{ type: "PLAYER_AVATAR", id: "avatar_dyn_01", count: 1 }]);
    expect(player._playerdata.checkIn.longTermRecvRecord["signin_1"]).toBe(1234567890);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("等级不足时不发放", async () => {
    player._playerdata.status.level = 70;
    const res = await call(player, { groupId: "signin_1" });
    expect(vi.mocked(res.send).mock.calls[0][0].rewards).toEqual([]);
    expect(player._playerdata.checkIn.longTermRecvRecord["signin_1"]).toBeUndefined();
  });

  it("累计天数不足时不发放", async () => {
    player._playerdata.checkIn.showCount = 100;
    const res = await call(player, { groupId: "signin_1" });
    expect(vi.mocked(res.send).mock.calls[0][0].rewards).toEqual([]);
  });

  it("已领取时不重复发放", async () => {
    player._playerdata.checkIn.longTermRecvRecord["signin_1"] = 1;
    const res = await call(player, { groupId: "signin_1" });
    expect(vi.mocked(res.send).mock.calls[0][0].rewards).toEqual([]);
  });

  it("未知 groupId 返回空奖励", async () => {
    const res = await call(player, { groupId: "nope" });
    expect(vi.mocked(res.send).mock.calls[0][0].rewards).toEqual([]);
  });
});
