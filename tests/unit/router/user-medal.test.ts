import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));

import type { Response } from "express";
import { rootRouter } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";
import type { Mock } from "vitest";

/** 奖章/相册请求体视图（本文件各端点字段合集） */
interface MedalBody {
  medalId?: string;
  group?: string;
  index?: string;
  data?: { layout: { x?: number }[] };
  magazine?: { leafId?: string; charSkin?: string | null; decorList?: { id?: number }[] };
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: MedalBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  sendStatus: Response["sendStatus"];
  status: Response["status"];
  json: Response["json"];
}

/**
 * update recipe 的 draft 夹具视图
 *
 * 本文件两个用例各自只喂一棵子树（medal.custom / gallery.leafMap），
 * 故声明为该形状的并集；运行时传给 handler 的 recipe 的就是这两个对象。
 */
interface MedalDraftFixture {
  medal?: { custom: { currentIndex?: string; customs: { [index: string]: { layout: { x?: number }[] } } } };
  gallery?: { leafMap: { [leafId: string]: { charSkin?: string; decorList?: { id?: number }[] } } };
}

/** 路由被测分支读到的玩家组合根面（medal.rewardMedal + update/delta） */
interface MedalRoutePlayer {
  delta: { modified: Record<string, never> };
  medal: { rewardMedal: Mock<(body: { medalId: string; group: string }) => Promise<{ id: string; type: string; count: number }[]>> };
  update?: Mock<(recipe: (draft: MedalDraftFixture) => void) => Promise<void>>;
}

type RouterReq = Parameters<typeof rootRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(req: MockReq, res: MockRes): Promise<MockRes> {
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  rootRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("medal 根级路由", () => {
  let mockPlayer: MedalRoutePlayer;

  beforeEach(() => {
    vi.clearAllMocks();
    mockPlayer = {
      delta: { modified: {} },
      medal: {
        rewardMedal: vi.fn().mockResolvedValue([{ id: "furn_1", type: "FURN", count: 1 }]),
      },
    };
    vi.mocked(httpContext.get).mockReturnValue(mockPlayer);
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
    const draft: MedalDraftFixture = { medal: { custom: { customs: {} } } };
    const update = vi.fn<(recipe: (d: MedalDraftFixture) => void) => Promise<void>>(async (recipe) => {
      recipe(draft);
    });
    vi.mocked(httpContext.get).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    const res = mockRes();
    const customData = { layout: [{ x: 1 }] };
    await call({ method: "POST", url: "/medal/setCustomData", body: { data: customData } }, res);
    // 深相等而非引用相等：zod 校验（z.json）会重建对象，validateBody 写入 req.body 的是
    // 解析后的新对象——handler 契约是「把 data 存进 customs[index]」，不涉及引用共享
    expect(draft.medal!.custom.customs["1"]).toStrictEqual(customData);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("setCustomData 写 currentIndex 与 customs[index]（对齐抓包 R-1707532038347.211-4603）", async () => {
    const res = mockRes();
    const player: MockPlayerDataManager = mockPlayerData({
      status: { uid: "1" },
      medal: { custom: { currentIndex: "", customs: {} } },
    });
    vi.mocked(httpContext.get).mockReturnValue(player);
    const req: MockReq = { method: "POST", url: "/medal/setCustomData", body: { index: "1", data: { layout: [] } } };
    rootRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
    expect(player._playerdata.medal.custom.currentIndex).toBe("1");
    expect(player._playerdata.medal.custom.customs["1"]).toEqual({ layout: [] });
  });

  it("saveDiyMagazineV2 应更新 gallery.leafMap（对齐 OBS misc_bp）", async () => {
    const draft: MedalDraftFixture = { gallery: { leafMap: {} } };
    const update = vi.fn<(recipe: (d: MedalDraftFixture) => void) => Promise<void>>(async (recipe) => {
      recipe(draft);
    });
    vi.mocked(httpContext.get).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    const res = mockRes();
    const magazine = { leafId: "leaf_1", charSkin: "char_1001#1", decorList: [{ id: 1 }] };
    await call({ method: "POST", url: "/gallery/saveDiyMagazineV2", body: { magazine } }, res);
    expect(draft.gallery!.leafMap["leaf_1"].charSkin).toBe("char_1001#1");
    expect(draft.gallery!.leafMap["leaf_1"].decorList).toEqual([{ id: 1 }]);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
