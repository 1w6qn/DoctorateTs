import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
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
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url: "/user/recvLongTermCheckInReward", body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("recvLongTermCheckInReward", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1", level: 90 } as any,
      checkIn: { showCount: 200, longTermRecvRecord: {} } as any,
    });
  });

  it("达标时发放奖励、记录领取并返回 rewards", async () => {
    const res = await call(player, { groupId: "signin_1" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([{ type: "PLAYER_AVATAR", id: "avatar_dyn_01", count: 1 }]);
    expect(player._playerdata.checkIn.longTermRecvRecord["signin_1"]).toBe(1234567890);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("等级不足时不发放", async () => {
    player._playerdata.status.level = 70;
    const res = await call(player, { groupId: "signin_1" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);
    expect(player._playerdata.checkIn.longTermRecvRecord["signin_1"]).toBeUndefined();
  });

  it("累计天数不足时不发放", async () => {
    player._playerdata.checkIn.showCount = 100;
    const res = await call(player, { groupId: "signin_1" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);
  });

  it("已领取时不重复发放", async () => {
    player._playerdata.checkIn.longTermRecvRecord["signin_1"] = 1;
    const res = await call(player, { groupId: "signin_1" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);
  });

  it("未知 groupId 返回空奖励", async () => {
    const res = await call(player, { groupId: "nope" });
    expect(res.send.mock.calls[0][0].rewards).toEqual([]);
  });
});
