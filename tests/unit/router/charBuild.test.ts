import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import type { Response } from "express";
import charBuildRouter from "@game/modules/character/routes";
import httpContext from "express-http-context2";

/** 路由测试请求体视图（本文件各端点字段合集） */
interface CharBuildBody {
  skinId?: string;
  isSpecial?: boolean;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: CharBuildBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof charBuildRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(req: MockReq, res: MockRes): Promise<MockRes> {
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  charBuildRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

/** 干员皮肤存档 draft 夹具视图（只声明本用例写入的 skinSp 键） */
interface CharBuildDraftFixture {
  skin: { skinSp: { [skinId: string]: boolean } };
}

describe("charBuild 路由（OBS 移植端点）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("changeSkinSpState 应写入 skin.skinSp[skinId]（对齐 OBS bp_charBuild）", async () => {
    const draft: CharBuildDraftFixture = { skin: { skinSp: {} } };
    const update = vi.fn<(recipe: (draft: CharBuildDraftFixture) => void) => Promise<void>>(async (recipe) => {
      recipe(draft);
    });
    vi.mocked(httpContext.get).mockReturnValue({
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
