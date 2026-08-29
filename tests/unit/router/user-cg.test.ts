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

describe("CG 收藏持久化", () => {
  let player: any;
  beforeEach(() => {
    vi.clearAllMocks();
    fsMock.existsSync.mockReset().mockReturnValue(false);
    fsMock.readFileSync.mockReset();
    fsMock.writeFileSync.mockReset();
    fsMock.mkdirSync.mockReset();
    player = mockPlayerData({ status: { uid: "1" } as any });
  });

  it("add 后 cgList 含新 id 并落盘", async () => {
    const res = await call(player, "/cg/addCgCollection", { cgId: "66_i02" });
    expect(res.send.mock.calls[0][0].cgList).toEqual(["66_i02"]);
    const written = JSON.parse(fsMock.writeFileSync.mock.calls.at(-1)[1] as string);
    expect(written.user["1"]).toEqual(["66_i02"]);
  });

  it("get 返回该 uid 已收藏列表", async () => {
    fsMock.existsSync.mockReturnValue(true);
    fsMock.readFileSync.mockReturnValue(JSON.stringify({ user: { "1": ["66_i02"] } }));
    const res = await call(player, "/cg/getCgCollection", {});
    expect(res.send.mock.calls[0][0].cgList).toEqual(["66_i02"]);
  });

  it("remove 后列表移除并落盘", async () => {
    fsMock.existsSync.mockReturnValue(true);
    fsMock.readFileSync.mockReturnValue(JSON.stringify({ user: { "1": ["66_i02", "66_i03"] } }));
    await call(player, "/cg/removeCgCollection", { cgId: "66_i02" });
    const written = JSON.parse(fsMock.writeFileSync.mock.calls.at(-1)[1] as string);
    expect(written.user["1"]).toEqual(["66_i03"]);
  });
});
