import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import questRouter from "../../../app/game/service/router/quest";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

describe("quest getAssistList 路由", () => {
  let player: any;
  let res: any;
  let ctx: any;

  beforeEach(async () => {
    player = {
      delta: { modified: {}, deleted: {} },
      social: {
        getAssistList: vi.fn().mockResolvedValue([{ uid: "2", nickName: "好友" }]),
      },
    };
    res = mockRes();
    ctx = await import("express-http-context2");
    (ctx.default.get as any).mockReturnValue(player);
  });

  async function call(url: string, body: any) {
    questRouter({ method: "POST", url, body } as any, res, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /getAssistList 应调用管理器并返回列表", async () => {
    await call("/getAssistList", { profession: "WARRIOR" });
    expect(player.social.getAssistList).toHaveBeenCalledWith({ profession: "WARRIOR" });
    const arg = res.send.mock.calls[0][0];
    expect(arg).toEqual(expect.objectContaining({ list: expect.any(Array) }));
    expect(arg.list[0].uid).toBe("2");
  });
});
