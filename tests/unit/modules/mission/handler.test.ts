import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import missionRouter from "../../../../app/game/service/mission/handler";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  missionRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("mission 路由", () => {
  let mockPlayer: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockPlayer = {
      delta: { modified: {} },
      mission: {
        confirmMission: vi.fn().mockResolvedValue([{ id: "4001", type: "GOLD", count: 100 }]),
        confirmMissionGroup: vi.fn().mockResolvedValue(undefined),
        autoConfirmMissions: vi.fn().mockResolvedValue([{ id: "30012", type: "MATERIAL", count: 5 }]),
        exchangeMissionRewards: vi.fn().mockResolvedValue(undefined),
      },
    };
    (vi.mocked(httpContext.get) as any).mockReturnValue(mockPlayer);
  });

  it("confirmMission 应返回奖励与 delta", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/confirmMission", body: { missionId: "daily_1" } }, res);
    expect(mockPlayer.mission.confirmMission).toHaveBeenCalledWith({ missionId: "daily_1" });
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ items: [{ id: "4001", type: "GOLD", count: 100 }], modified: {} }));
  });

  it("confirmMissionGroup 应委托调用", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/confirmMissionGroup", body: { missionGroupId: "g1" } }, res);
    expect(mockPlayer.mission.confirmMissionGroup).toHaveBeenCalledWith({ missionGroupId: "g1" });
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("autoConfirmMissions 应返回自动确认奖励", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/autoConfirmMissions", body: { type: "DAILY" } }, res);
    expect(mockPlayer.mission.autoConfirmMissions).toHaveBeenCalledWith({ type: "DAILY" });
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ items: [{ id: "30012", type: "MATERIAL", count: 5 }] }));
  });

  it("exchangeMissionRewards 应委托调用", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/exchangeMissionRewards", body: { targetRewardsId: "r1" } }, res);
    expect(mockPlayer.mission.exchangeMissionRewards).toHaveBeenCalledWith({ targetRewardsId: "r1" });
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
