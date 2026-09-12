import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import type { Response } from "express";
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData, asModel } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";
import type { PlayerCrossAppShare } from "@game/kernel/playerdata";

/** user 杂项请求体视图 */
interface UserMiscBody {
  storyId?: string;
  shareMissionId?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: UserMiscBody;
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

async function call(player: MockPlayerDataManager, url: string, body: UserMiscBody): Promise<MockRes> {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  const req: MockReq = { method: "POST", url, body };
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  rootRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("performanceStory / share", () => {
  let player: MockPlayerDataManager;
  beforeEach(() => {
    vi.clearAllMocks();
    player = mockPlayerData({ status: { uid: "1" } });
  });

  it("startStory 写 performanceStory.unlock[storyId]=1", async () => {
    await call(player, "/performanceStory/startStory", { storyId: "p_story_001" });
    expect(player._playerdata.performanceStory.unlock["p_story_001"]).toBe(1);
  });

  it("confirmShareMission 递增 share.shareMissions[counter]", async () => {
    player._playerdata.share = asModel<PlayerCrossAppShare>({
      shareMissions: { namecardshare: { counter: 0 } },
    });
    await call(player, "/share/confirmShareMission", { shareMissionId: "namecardshare" });
    expect(player._playerdata.share.shareMissions["namecardshare"].counter).toBe(1);
    await call(player, "/share/confirmShareMission", { shareMissionId: "namecardshare" });
    expect(player._playerdata.share.shareMissions["namecardshare"].counter).toBe(2);
  });
});
