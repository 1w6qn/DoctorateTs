import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));

import { rootRouter } from "../../../app/game/router/user";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), sendStatus: vi.fn(), status: vi.fn().mockReturnThis(), json: vi.fn() };
}

async function call(req: any, res: any) {
  rootRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("medal 根级路由", () => {
  let mockPlayer: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockPlayer = {
      delta: { modified: {} },
      medal: {
        rewardMedal: vi.fn().mockResolvedValue([{ id: "furn_1", type: "FURN", count: 1 }]),
      },
    };
    (vi.mocked(httpContext.get) as any).mockReturnValue(mockPlayer);
  });

  it("rewardMedal 应调用 MedalManager 并返回物品与 delta", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/medal/rewardMedal", body: { medalId: "m1", group: "g1" } }, res);
    expect(mockPlayer.medal.rewardMedal).toHaveBeenCalledWith({ medalId: "m1", group: "g1" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ items: [{ id: "furn_1", type: "FURN", count: 1 }], modified: {} }),
    );
  });

  it("setCustomData 应写入 medal.custom.customs[1]（对齐 OBS misc_bp）", async () => {
    const draft: any = { medal: { custom: { customs: {} } } };
    const update = vi.fn(async (fn: (d: any) => void) => {
      fn(draft);
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    const res = mockRes();
    const customData = { layout: [{ x: 1 }] };
    await call({ method: "POST", url: "/medal/setCustomData", body: { data: customData } }, res);
    expect(draft.medal.custom.customs["1"]).toBe(customData);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("saveDiyMagazineV2 应更新 gallery.leafMap（对齐 OBS misc_bp）", async () => {
    const draft: any = { gallery: { leafMap: {} } };
    const update = vi.fn(async (fn: (d: any) => void) => {
      fn(draft);
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    const res = mockRes();
    const magazine = { leafId: "leaf_1", charSkin: "char_1001#1", decorList: [{ id: 1 }] };
    await call({ method: "POST", url: "/gallery/saveDiyMagazineV2", body: { magazine } }, res);
    expect(draft.gallery.leafMap["leaf_1"].charSkin).toBe("char_1001#1");
    expect(draft.gallery.leafMap["leaf_1"].decorList).toEqual([{ id: 1 }]);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
