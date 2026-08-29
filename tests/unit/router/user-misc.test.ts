import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() { return { send: vi.fn(), status: vi.fn().mockReturnThis(), type: vi.fn().mockReturnThis(), json: vi.fn() }; }
async function call(player: any, url: string, body: any) {
  const res = mockRes();
  (httpContext.get as any).mockReturnValue(player);
  rootRouter({ method: "POST", url, body } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("performanceStory / share", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({ status: { uid: "1" } as any });
  });

  it("startStory 写 performanceStory.unlock[storyId]=1", async () => {
    await call(player, "/performanceStory/startStory", { storyId: "p_story_001" });
    expect(player._playerdata.performanceStory.unlock["p_story_001"]).toBe(1);
  });

  it("confirmShareMission 递增 share.shareMissions[counter]", async () => {
    player._playerdata.share = { shareMissions: { namecardshare: { counter: 0 } } } as any;
    await call(player, "/share/confirmShareMission", { shareMissionId: "namecardshare" });
    expect(player._playerdata.share.shareMissions["namecardshare"].counter).toBe(1);
    await call(player, "/share/confirmShareMission", { shareMissionId: "namecardshare" });
    expect(player._playerdata.share.shareMissions["namecardshare"].counter).toBe(2);
  });
});
