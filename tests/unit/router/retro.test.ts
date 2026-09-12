import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import retroRouter from "@game/modules/retro/routes";
import httpContext from "express-http-context2";

import type { Response } from "express";
/** 路由测试请求体视图（本文件各端点字段合集） */
interface RetroBody {
  data?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: RetroBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

type RouterReq = Parameters<typeof retroRouter>[0];

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
  retroRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("retro 路由（OBS 移植端点）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(httpContext.get).mockReturnValue({
      delta: { modified: {} },
    });
  });

  it("typeAct20side/competitionStart 应返回 result 0 与真实随机 battleId（对齐 OBS misc_bp）", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/retro/typeAct20side/competitionStart", body: {} }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        result: 0,
        // 真实随机 UUID（对齐官服 DefaultStartBattleResponse，非固定 stub）
        battleId: expect.stringMatching(
          /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
        ),
        modified: {},
      }),
    );
  });

  it("typeAct20side/competitionFinish 应返回评价结构（对齐 OBS misc_bp）", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/retro/typeAct20side/competitionFinish", body: { data: "x" } }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        performance: 0,
        expression: 0,
        operation: 0,
        total: 0,
        level: "SS",
        isNew: false,
        modified: {},
      }),
    );
  });
});
