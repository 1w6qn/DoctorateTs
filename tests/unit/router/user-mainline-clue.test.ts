import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
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
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() };
}
async function call(player: any, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url: "/mainlineClue/getRewards", body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("mainlineClue getRewards", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" } as any,
      mainline: { clue: { unlock: false, state: { clue_1_1: 2, clue_1_2: 2 }, reward: {} } } as any,
    });
  });

  it("ids 全部达标时发放奖励并标记已领取", async () => {
    const res = await call(player, { ids: ["clueActivity_1"] });
    const response = res.send.mock.calls[0][0];
    expect(response.items).toEqual([{ type: "MATERIAL", id: "31024", count: 1 }]);
    expect(player._playerdata.mainline.clue.reward["clueActivity_1"]).toBe(1);
    expect(player.gainItem.handle).toHaveBeenCalled();
  });

  it("已领取的线索奖励不重复发放", async () => {
    player._playerdata.mainline.clue.reward["clueActivity_1"] = 1;
    const res = await call(player, { ids: ["clueActivity_1"] });
    expect(res.send.mock.calls[0][0].items).toEqual([]);
  });

  it("已解锁线索数不足时（gainedRecord < clueRecord）不发放", async () => {
    const res = await call(player, { ids: ["clueActivity_2"] });
    expect(res.send.mock.calls[0][0].items).toEqual([]);
    expect(player._playerdata.mainline.clue.reward["clueActivity_2"]).toBeUndefined();
  });

  it("兼容旧单 id 请求写法", async () => {
    const res = await call(player, { id: "clueActivity_1" });
    expect(res.send.mock.calls[0][0].items).toEqual([{ type: "MATERIAL", id: "31024", count: 1 }]);
  });

  it("unlockClue 仍写 state[id]=2", async () => {
    const res = mockRes();
    (httpContext.get as any).mockReturnValue(player);
    rootRouter({ method: "POST", url: "/mainlineClue/unlockClue", body: { id: "clue_1_3" } } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
    expect(player._playerdata.mainline.clue.state["clue_1_3"]).toBe(2);
  });
});
