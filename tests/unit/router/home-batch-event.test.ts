import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import homeRouter from "../../../app/game/service/router/home";

function mockRes() {
  return { send: vi.fn(), sendStatus: vi.fn(), status: vi.fn().mockReturnThis(), json: vi.fn() };
}

async function call(req: any, res: any) {
  homeRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("home 路由：客户端事件批量上报", () => {
  it("POST /batch_event 应返回 200 空对象（客户端只认状态码）", async () => {
    const res = mockRes();
    await call({ method: "POST", url: "/batch_event", body: { events: [{ id: 1 }] } }, res);
    expect(res.send).toHaveBeenCalledWith({});
  });
});
