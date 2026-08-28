/**
 * rlv2 请求 zod schema 校验单测
 *
 * 直接测 validateBody 中间件 + rlv2.schema 各请求 schema：
 * - 合法 body 通过（next 被调用，req.body 被 parse）
 * - 缺失必填 / 类型不符 body 返回 HTTP 4xx（默认 422）+ { result: -1, message }
 *
 * 覆盖关键必填端点（createGame/selectChoice/moveTo/gridZone/recruitChar/loseScrap 等），
 * 与服务端"缺参不再 500、改为 4xx"契约对齐。
 */
import { describe, it, expect, vi } from "vitest";
import * as ReqSchema from "@game/modules/roguelike/schemas";
import { validateBody } from "@game/kernel/http/validate-body";

function makeRes() {
  const json = vi.fn();
  const status = vi.fn().mockReturnThis();
  return { json, status };
}

/** 断言 : 校验失败返回指定状态码 + result:-1 + message */
function run(schema: any, body: unknown, status = 422) {
  const res = makeRes();
  const next = vi.fn();
  validateBody(schema, status)({ body } as any, res as any, next);
  return { res, next };
}

describe("validateBody 中间件", () => {
  it("合法 body 通过且 req.body 被 parse", () => {
    const res = makeRes();
    const next = vi.fn();
    const req: any = { body: { theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null, activityId: null } };
    validateBody(ReqSchema.createGameSchema)(req, res as any, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    // parse 后保留下发给 handler 的字段
    expect(req.body.theme).toBe("rogue_6");
  });

  it("校验失败返回默认 422 + result:-1 + message", () => {
    const { res, next } = run(ReqSchema.createGameSchema, {});
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(422);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ result: -1, message: expect.any(String) }),
    );
  });

  it("校验失败可使用自定义状态码（如 400）", () => {
    const { res } = run(ReqSchema.createGameSchema, {}, 400);
    expect(res.status).toHaveBeenCalledWith(400);
  });
});

describe("rlv2 请求 schema 必填约束", () => {
  it.each([
    ["createGame", ReqSchema.createGameSchema, { theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null }, {}],
    ["selectChoice", ReqSchema.selectChoiceSchema, { choice: "choice_leave" }, {}],
    ["moveTo", ReqSchema.moveToSchema, { to: { x: 1, y: 2 } }, { to: {} }],
    ["recruitChar", ReqSchema.recruitCharSchema, { ticketIndex: "0", optionId: "opt_1" }, { optionId: "opt_1" }],
    ["loseScrap", ReqSchema.scrapLoseSchema, { instId: "s_1" }, {}],
    ["stashRecruitTicket", ReqSchema.stashRecruitTicketSchema, { index: "0" }, {}],
    ["useStashedTicket", ReqSchema.useStashedTicketSchema, { id: "t_1" }, {}],
    ["rerollNode", ReqSchema.rollNodeSchema, { nodeIndex: "1" }, {}],
    ["upgradeNode", ReqSchema.upgradeNodeSchema, { nodeType: "REST" }, {}],
    ["gridZone/moveTo", ReqSchema.gridZoneMoveToSchema, { route: ["n_1"] }, { route: [] }],
    ["battlePass/getReward", ReqSchema.battlePassGetRewardSchema, { theme: "rogue_2", rewards: ["bp_level_1"] }, {}],
  ])("%s: 合法入参通过、缺必填字段返回 422", (_name, schema, ok, bad) => {
    const okRes = makeRes();
    const okNext = vi.fn();
    validateBody(schema)({ body: ok } as any, okRes as any, okNext);
    expect(okNext).toHaveBeenCalledTimes(1);

    const { res, next } = run(schema, bad);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(422);
  });

  it("类型不符（modeGrade 传字符串）返回 422", () => {
    const { next, res } = run(ReqSchema.createGameSchema, { theme: "x", mode: "NORMAL", modeGrade: "15" });
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(422);
  });

  it("可选字段缺失不拦截（predefinedId/buyGoods/leave 等可选）", () => {
    // buyGoods 全可选
    const r1 = makeRes();
    const n1 = vi.fn();
    validateBody(ReqSchema.buyGoodsSchema)({ body: {} } as any, r1 as any, n1);
    expect(n1).toHaveBeenCalledTimes(1);

    // shopAction 全可选
    const r2 = makeRes();
    const n2 = vi.fn();
    validateBody(ReqSchema.shopActionSchema)({ body: {} } as any, r2 as any, n2);
    expect(n2).toHaveBeenCalledTimes(1);
  });
});

describe("rlv2 响应骨架 schema（playerDeltaResponseSchema）", () => {
  it("合法响应骨架通过", () => {
    const ok = {
      playerDataDelta: {
        modified: { status: { ap: 1 }, rlv2: { current: { player: { state: "INIT" } } } },
        deleted: {},
      },
    };
    expect(ReqSchema.playerDeltaResponseSchema.safeParse(ok).success).toBe(true);
  });

  it("允许 extra 顶层字段（items/result/scrap 等）", () => {
    const ok = {
      items: [{ type: "GOLD", id: "4001", count: 1 }],
      result: 0,
      playerDataDelta: {
        modified: { rlv2: { current: {} } },
        deleted: {},
      },
    };
    expect(ReqSchema.playerDeltaResponseSchema.safeParse(ok).success).toBe(true);
  });

  it("current 为对象（空对象也合法）", () => {
    const ok = { playerDataDelta: { modified: { rlv2: { current: {} } }, deleted: {} } };
    expect(ReqSchema.playerDeltaResponseSchema.safeParse(ok).success).toBe(true);
  });

  it("缺失 playerDataDelta 时校验失败", () => {
    expect(ReqSchema.playerDeltaResponseSchema.safeParse({}).success).toBe(false);
  });

  it("rlv2.current 非对象（字符串/数组）时校验失败", () => {
    const bad = {
      playerDataDelta: { modified: { rlv2: { current: "oops" } }, deleted: {} },
    };
    expect(ReqSchema.playerDeltaResponseSchema.safeParse(bad).success).toBe(false);
  });
});