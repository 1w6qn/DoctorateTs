import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import type { Response } from "express";
import questRouter from "@game/modules/quest/routes";
import httpContext from "express-http-context2";

/** 路由测试请求体视图（本文件各端点字段合集） */
interface QuestBody {
  data?: string;
  stageId?: string;
  selected?: number[];
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: QuestBody;
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

async function call(req: MockReq, res: MockRes): Promise<MockRes> {
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  questRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

/** 六星标记存档 draft 夹具视图（只声明本用例写入的 stages 键） */
interface QuestDraftFixture {
  dungeon: { sixStar: { stages: { [stageId: string]: { tagSelected?: number[] } } } };
}

describe("quest 路由（OBS 移植端点）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("battleContinue 应返回继续战斗 stub（对齐 OBS bp_quest）", async () => {
    vi.mocked(httpContext.get).mockReturnValue({
      delta: { modified: {} },
    });
    const res = mockRes();
    await call({ method: "POST", url: "/battleContinue", body: { data: "x" } }, res);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({
        result: 1,
        battleId: "00000000-0000-0000-0000-000000000000",
        apFailReturn: 0,
        modified: {},
      }),
    );
  });

  it("finishStoryStage 应委托 battle.finishStoryStage 并合并增量", async () => {
    const finishStoryStage = vi.fn().mockResolvedValue({ result: 0, rewards: [], unlockStages: [] });
    vi.mocked(httpContext.get).mockReturnValue({
      battle: { finishStoryStage },
      delta: { modified: {} },
    });
    const res = mockRes();
    await call({ method: "POST", url: "/finishStoryStage", body: { stageId: "main_01-01" } }, res);
    expect(finishStoryStage).toHaveBeenCalledWith({ stageId: "main_01-01" });
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ result: 0, rewards: [], modified: {} }),
    );
  });

  it("editStageSixStarTag 应写入 dungeon.sixStar.stages.tagSelected", async () => {
    const draft: QuestDraftFixture = { dungeon: { sixStar: { stages: { "main_01-01": {} } } } };
    const update = vi.fn<(recipe: (draft: QuestDraftFixture) => void) => Promise<void>>(async (recipe) => {
      recipe(draft);
    });
    vi.mocked(httpContext.get).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    const res = mockRes();
    await call(
      { method: "POST", url: "/editStageSixStarTag", body: { stageId: "main_01-01", selected: [1, 2] } },
      res,
    );
    expect(update).toHaveBeenCalled();
    expect(draft.dungeon.sixStar.stages["main_01-01"].tagSelected).toEqual([1, 2]);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
