import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import type { Response } from "express";
import questRouter from "@game/modules/quest/routes";

/** 路由测试请求体视图（本文件各端点字段合集） */
interface QuestAssistBody {
  profession?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: QuestAssistBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof questRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

/** quest 玩家组合根替身（只覆盖本文件断言到的 social.getAssistList） */
function makeMockPlayer() {
  return {
    delta: { modified: {}, deleted: {} },
    social: {
      getAssistList: vi.fn().mockResolvedValue([{ uid: "2", nickName: "好友" }]),
    },
  };
}

describe("quest getAssistList 路由", () => {
  let player: ReturnType<typeof makeMockPlayer>;
  let res: MockRes;

  beforeEach(async () => {
    player = makeMockPlayer();
    res = mockRes();
    const ctx = await import("express-http-context2");
    vi.mocked(ctx.default.get).mockReturnValue(player);
  });

  async function call(url: string, body: QuestAssistBody) {
    const req: MockReq = { method: "POST", url, body };
    // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
    questRouter(req as RouterReq, res as Response, () => {});
    await new Promise((r) => setTimeout(r, 20));
  }

  it("POST /getAssistList 应调用管理器并返回列表", async () => {
    await call("/getAssistList", { profession: "WARRIOR" });
    expect(player.social.getAssistList).toHaveBeenCalledWith({ profession: "WARRIOR" });
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg).toEqual(expect.objectContaining({ list: expect.any(Array) }));
    expect(arg.list[0].uid).toBe("2");
  });
});
