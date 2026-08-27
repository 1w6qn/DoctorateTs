import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import socialRouter from "../../../app/game/domain/router/social";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  socialRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("social 路由", () => {
  let mockPlayer: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockPlayer = {
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
      },
    };
    (vi.mocked(httpContext.get) as any).mockReturnValue(mockPlayer);
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

  it("setStarFriendList 应返回 newIdList 与 delta（OBS 空实现）", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/setStarFriendList", body: { idList: ["2"] } }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 0, newIdList: [], modified: {} }),
    );
  });
});
