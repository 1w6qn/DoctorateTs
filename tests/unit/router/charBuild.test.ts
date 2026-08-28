import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import charBuildRouter from "@game/modules/character/routes";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  charBuildRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("charBuild 路由（OBS 移植端点）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("changeSkinSpState 应写入 skin.skinSp[skinId]（对齐 OBS bp_charBuild）", async () => {
    const draft: any = { skin: { skinSp: {} } };
    const update = vi.fn(async (fn: (d: any) => void) => {
      fn(draft);
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    const res = mockRes();
    await call(
      { method: "POST", url: "/changeSkinSpState", body: { skinId: "char_1001#1", isSpecial: true } },
      res,
    );
    expect(draft.skin.skinSp["char_1001#1"]).toBe(true);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
