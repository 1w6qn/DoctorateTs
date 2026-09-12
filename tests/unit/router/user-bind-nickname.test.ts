import { describe, it, expect, vi, beforeEach } from "vitest";
vi.mock("express-http-context2", () => ({ default: { get: vi.fn(), set: vi.fn() } }));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));
import type { Response } from "express";
import { router } from "@game/modules/user/routes";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";
import type { MockPlayerDataManager } from "../../helpers";

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: Record<string, string>;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  type: Response["type"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof router>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    type: vi.fn<Response["type"]>().mockReturnThis(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(player: MockPlayerDataManager, url: string, body: Record<string, string>): Promise<MockRes> {
  const res = mockRes();
  vi.mocked(httpContext.get).mockReturnValue(player);
  const req: MockReq = { method: "POST", url, body };
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  router(req as RouterReq, res as Response, () => {});
  await new Promise((resolve) => setTimeout(resolve, 20));
  return res;
}

describe("bindNickName 路由参数映射", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("把客户端 nickName 映射为管理器契约的 nickname（修复绑定静默失效）", async () => {
    const player = mockPlayerData();
    await call(player, "/bindNickName", { nickName: "博士" });
    expect(player.status.bindNickName).toHaveBeenCalledWith({ nickname: "博士" });
  });
});
