import { describe, it, expect, vi, afterEach } from "vitest";

// 临时 req/res 记录中间件单元测试（capture 存储版）
// 注意：reqres-log.ts 的 MODE 在模块加载时从 REQRES_LOG 读取——用 vi.resetModules 隔离
function loadModule(env: string) {
  vi.resetModules();
  process.env.REQRES_LOG = env;
  return import("@game/reqres-log");
}

afterEach(() => {
  delete process.env.REQRES_LOG;
  vi.restoreAllMocks();
});

describe("reqres-log 记录开关", () => {
  it("默认模式（rlv2）：仅记录 /rlv2/ 路径", async () => {
    const mod = await loadModule("rlv2");
    expect(mod.enabledFor("/rlv2/finishEvent")).toBe(true);
    expect(mod.enabledFor("/rlv2/createGame")).toBe(true);
    expect(mod.enabledFor("/other/route")).toBe(false);
    expect(mod.enabledFor("/admin/users")).toBe(false);
  });

  it("all 模式：记录全部路径", async () => {
    const mod = await loadModule("all");
    expect(mod.enabledFor("/rlv2/x")).toBe(true);
    expect(mod.enabledFor("/other")).toBe(true);
    expect(mod.enabledFor("/admin")).toBe(true);
  });

  it("关闭（0/false/off/空）：不记录", async () => {
    for (const off of ["0", "false", "off", ""]) {
      const mod = await loadModule(off);
      expect(mod.enabledFor("/rlv2/x")).toBe(false);
    }
  });

  it("自定义前缀模式", async () => {
    const mod = await loadModule("battle");
    expect(mod.enabledFor("/battle/start")).toBe(true);
    expect(mod.enabledFor("/rlv2/x")).toBe(false);
  });
});

describe("reqres-log capture 存储", () => {
  function mockRes(statusCode = 200) {
    const handlers: Record<string, Array<() => void>> = {};
    const res: any = {
      statusCode,
      send: (data: unknown) => {
        res._sent = data;
        return res;
      },
      json: (data: unknown) => {
        res._sent = data;
        return res;
      },
      getHeaders: () => ({ "content-type": "application/json" }),
      on: (ev: string, fn: () => void) => {
        (handlers[ev] = handlers[ev] || []).push(fn);
      },
      emitFinish: () => (handlers["finish"] || []).forEach((fn) => fn()),
    };
    return res;
  }

  function mockReq(over: Record<string, unknown> = {}) {
    return {
      method: "POST",
      path: "/rlv2/finishEvent",
      originalUrl: "/rlv2/finishEvent?t=1",
      headers: { "content-type": "application/json" },
      body: { ticketIndex: "t_0" },
      ...over,
    } as any;
  }

  it("命中路径：finish 后写入 captureManager（source=private, note=reqres-log）", async () => {
    const mod = await loadModule("rlv2");
    const capture = await import("@capture/capture-manager");
    const spy = vi
      .spyOn(capture.captureManager, "addRecord")
      .mockResolvedValue({} as any);

    const res = mockRes(200);
    mod.reqresLogMiddleware(mockReq(), res, () => {});
    res.send({ playerDataDelta: { ok: true } });
    res.emitFinish();
    await new Promise((r) => setTimeout(r, 0));

    expect(spy).toHaveBeenCalledTimes(1);
    const [meta, bodies] = spy.mock.calls[0];
    expect(meta.method).toBe("POST");
    expect(meta.path).toBe("/rlv2/finishEvent");
    expect(meta.query).toBe("t=1");
    expect(meta.status).toBe(200);
    expect(meta.source).toBe("private");
    expect(meta.note).toBe("reqres-log");
    expect(meta.latencyMs).toBeGreaterThanOrEqual(0);
    // bodies：req json + res json
    expect(bodies.req).toEqual({ kind: "json", data: { ticketIndex: "t_0" } });
    expect(bodies.res).toEqual({ kind: "json", data: { playerDataDelta: { ok: true } } });
  });

  it("res.json 路径同样记录（对象不被二次序列化）", async () => {
    const mod = await loadModule("rlv2");
    const capture = await import("@capture/capture-manager");
    const spy = vi
      .spyOn(capture.captureManager, "addRecord")
      .mockResolvedValue({} as any);

    const res = mockRes(200);
    mod.reqresLogMiddleware(mockReq(), res, () => {});
    res.json({ code: 0 });
    res.emitFinish();
    await new Promise((r) => setTimeout(r, 0));

    expect(spy).toHaveBeenCalledTimes(1);
    const [, bodies] = spy.mock.calls[0];
    expect(bodies.res).toEqual({ kind: "json", data: { code: 0 } });
  });

  it("rawBody（二进制请求）优先于 req.body；字符串响应体走 bin", async () => {
    const mod = await loadModule("rlv2");
    const capture = await import("@capture/capture-manager");
    const spy = vi
      .spyOn(capture.captureManager, "addRecord")
      .mockResolvedValue({} as any);

    const buf = Buffer.from([1, 2, 3]);
    const res = mockRes(404);
    mod.reqresLogMiddleware(
      mockReq({ rawBody: buf, body: {} }),
      res,
      () => {},
    );
    res.send("not found html");
    res.emitFinish();
    await new Promise((r) => setTimeout(r, 0));

    const [meta, bodies] = spy.mock.calls[0];
    expect(meta.status).toBe(404);
    expect(bodies.req).toEqual({ kind: "bin", data: buf });
    expect(bodies.res).toEqual({ kind: "bin", data: "not found html" });
  });

  it("未命中路径：不包裹不写入", async () => {
    const mod = await loadModule("rlv2");
    const capture = await import("@capture/capture-manager");
    const spy = vi
      .spyOn(capture.captureManager, "addRecord")
      .mockResolvedValue({} as any);

    const res = mockRes(200);
    let called = false;
    mod.reqresLogMiddleware(mockReq({ path: "/other", originalUrl: "/other" }), res, () => {
      called = true;
    });
    res.send({});
    res.emitFinish();
    await new Promise((r) => setTimeout(r, 0));

    expect(called).toBe(true);
    expect(spy).not.toHaveBeenCalled();
  });

  it("开关关闭：不写入", async () => {
    const mod = await loadModule("0");
    const capture = await import("@capture/capture-manager");
    const spy = vi
      .spyOn(capture.captureManager, "addRecord")
      .mockResolvedValue({} as any);

    const res = mockRes(200);
    mod.reqresLogMiddleware(mockReq(), res, () => {});
    res.send({});
    res.emitFinish();
    await new Promise((r) => setTimeout(r, 0));

    expect(spy).not.toHaveBeenCalled();
  });
});
