import { describe, it, expect, vi, beforeEach } from "vitest";
const fsMock = vi.hoisted(() => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  unlinkSync: vi.fn(),
}));
vi.mock("node:fs", () => fsMock);
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import type { Response } from "express";
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";

/** CG 收藏请求体视图 */
interface CgBody {
  cgId?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: CgBody;
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

async function call(player: MockPlayerDataManager, url: string, body: CgBody): Promise<MockRes> {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  const req: MockReq = { method: "POST", url, body };
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  rootRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("CG 收藏持久化", () => {
  let player: MockPlayerDataManager;
  beforeEach(() => {
    vi.clearAllMocks();
    fsMock.existsSync.mockReset().mockReturnValue(false);
    fsMock.readFileSync.mockReset();
    fsMock.writeFileSync.mockReset();
    fsMock.mkdirSync.mockReset();
    player = mockPlayerData({ status: { uid: "1" } });
  });

  it("add 后 cgList 含新 id 并落盘", async () => {
    const res = await call(player, "/cg/addCgCollection", { cgId: "66_i02" });
    expect(vi.mocked(res.send).mock.calls[0][0].cgList).toEqual(["66_i02"]);
    const written = JSON.parse(fsMock.writeFileSync.mock.calls.at(-1)![1] as string);
    expect(written.user["1"]).toEqual(["66_i02"]);
  });

  it("get 返回该 uid 已收藏列表", async () => {
    fsMock.existsSync.mockReturnValue(true);
    fsMock.readFileSync.mockReturnValue(JSON.stringify({ user: { "1": ["66_i02"] } }));
    const res = await call(player, "/cg/getCgCollection", {});
    expect(vi.mocked(res.send).mock.calls[0][0].cgList).toEqual(["66_i02"]);
  });

  it("remove 后列表移除并落盘", async () => {
    fsMock.existsSync.mockReturnValue(true);
    fsMock.readFileSync.mockReturnValue(JSON.stringify({ user: { "1": ["66_i02", "66_i03"] } }));
    await call(player, "/cg/removeCgCollection", { cgId: "66_i02" });
    const written = JSON.parse(fsMock.writeFileSync.mock.calls.at(-1)![1] as string);
    expect(written.user["1"]).toEqual(["66_i03"]);
  });
});
