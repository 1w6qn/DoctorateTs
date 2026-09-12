import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import socialRouter from "@game/modules/social/routes";
import httpContext from "express-http-context2";

import type { Response } from "express";
/** 路由测试请求体视图（本文件各端点字段合集） */
interface SocialBody {
  id?: string;
  friendId?: string;
  action?: number;
  type?: number;
  idList?: string[];
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: SocialBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof socialRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(req: MockReq, res: MockRes): Promise<MockRes> {
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  socialRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

/**
 * 社交管理器替身
 *
 * 用例只断言委托调用与响应拼装，故按被测契约声明各入口（返回值为替身桩的约定值）。
 */
function makeMockPlayer() {
  return {
    delta: { modified: {} },
    social: {
      deleteFriend: vi.fn().mockResolvedValue(undefined),
      sendFriendRequest: vi.fn().mockResolvedValue(undefined),
      processFriendRequest: vi.fn().mockResolvedValue({ friendNum: 2 }),
      searchPlayer: vi.fn().mockResolvedValue({ result: [] }),
      getSortListInfo: vi.fn().mockResolvedValue([{ uid: "2" }]),
      getFriendList: vi.fn().mockResolvedValue({ friends: [], friendAlias: [] }),
      getFriendRequestList: vi.fn().mockResolvedValue({ result: [] }),
      setAssistCharList: vi.fn().mockResolvedValue(undefined),
      setFriendAlias: vi.fn().mockResolvedValue(undefined),
      receiveSocialPoint: vi.fn().mockResolvedValue(undefined),
      setCardShowMedal: vi.fn().mockResolvedValue(undefined),
      // Round 48：星标好友（原空桩 → 真实实现）与响应携带 starFriendList
      setStarFriendList: vi.fn().mockResolvedValue(["2"]),
      getStarFriendList: vi.fn().mockResolvedValue(["2"]),
    },
  };
}

describe("social 路由", () => {
  let mockPlayer: ReturnType<typeof makeMockPlayer>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockPlayer = makeMockPlayer();
    vi.mocked(httpContext.get).mockReturnValue(mockPlayer);
  });

  it("deleteFriend 应委托 social.deleteFriend", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/deleteFriend", body: { id: "2" } }, res);
    expect(mockPlayer.social.deleteFriend).toHaveBeenCalledWith({ id: "2" });
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("processFriendRequest 应返回 friendNum 与 delta", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/processFriendRequest", body: { friendId: "2", action: 1 } }, res);
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ friendNum: 2, modified: {} }));
  });

  it("getSortListInfo 应返回 result 与 delta", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/getSortListInfo", body: { type: 0 } }, res);
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ result: [{ uid: "2" }] }));
  });

  it("getFriendList 应返回好友数据", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/getFriendList", body: { idList: ["2"] } }, res);
    expect(mockPlayer.social.getFriendList).toHaveBeenCalledWith({ idList: ["2"] });
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ friends: [] }));
  });

  it("receiveSocialPoint 应委托调用", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/receiveSocialPoint", body: {} }, res);
    expect(mockPlayer.social.receiveSocialPoint).toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  // Round 48（审计 §5.4-10）：星标好友由空桩改为真实实现（落库并返回实际生效列表）
  it("setStarFriendList 应委托 social.setStarFriendList 并返回生效列表", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/setStarFriendList", body: { idList: ["2"] } }, res);
    expect(mockPlayer.social.setStarFriendList).toHaveBeenCalledWith({ idList: ["2"] });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 0, newIdList: ["2"], modified: {} }),
    );
  });
});
