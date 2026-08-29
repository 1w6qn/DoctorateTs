import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
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
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url: "/troop/SpecialOperatorUnlockNode", body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("SpecialOperatorUnlockNode", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({
      status: { uid: "1" } as any,
      troop: { chars: { "374": { charId: "char_4230_mcnist" } }, spOperator: {} } as any,
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
