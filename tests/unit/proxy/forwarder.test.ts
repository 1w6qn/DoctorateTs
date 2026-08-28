/**
 * 转发中间件测试（forwarder.ts）
 *
 * 语义基线：从 official-forward.test.ts 的 createOfficialForwarder 全量迁移——
 * 命中转发不 next / 透传状态与响应体 / 头剥离 / 未命中 next / 网络错误 502 /
 * multipart rawBody 透传 / region 主机优先级。
 * 新增：自定义上游经 createProxyForwarder 生效、request/response 变换器接入转发链。
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("axios", () => ({ default: vi.fn() }));

import axios from "axios";
import { createProxyForwarder } from "@ops/proxy/forwarder";
import { OFFICIAL_AS_HOST, OFFICIAL_GS_HOST } from "@ops/proxy/upstream";
import {
  registerUpstream,
  resetUpstreams,
} from "@ops/proxy/upstream";
import {
  registerRequestTransform,
  registerResponseTransform,
  resetTransforms,
  setArkhubGatewayInfo,
} from "@ops/proxy/transform";
import { getGatewayTarget } from "@game/modules/activities/arkhub/public";
import config from "@core/config/index";

/** 保存/恢复 config 的 region 相关字段（region 主机用例隔离；支持 async fn） */
async function withCaptureRegion(
  patch: { enabled: boolean; region?: string; regions?: Record<string, any> },
  fn: () => Promise<void> | void,
): Promise<void> {
  const savedCapture = config.capture;
  const savedRegions = (config as any).regions;
  try {
    (config as any).capture = {
      ...(savedCapture ?? {}),
      enabled: patch.enabled,
      ...(patch.region !== undefined ? { region: patch.region } : {}),
    };
    if (patch.regions !== undefined) (config as any).regions = patch.regions;
    await fn();
  } finally {
    (config as any).capture = savedCapture;
    (config as any).regions = savedRegions;
  }
}

const mockAxios = axios as unknown as ReturnType<typeof vi.fn>;

/** 最小 Express req（rawBody 可覆写） */
function makeReq(partial: Record<string, unknown> = {}): any {
  return {
    method: "POST",
    url: "/account/login",
    headers: { host: "127.0.0.1:8443", "content-type": "application/json" },
    body: { uid: "1" },
    query: {},
    originalUrl: "/account/login",
    ...partial,
  };
}

describe("createProxyForwarder（转发中间件）", () => {
  beforeEach(() => {
    mockAxios.mockReset();
    resetUpstreams();
    resetTransforms();
    setArkhubGatewayInfo(null);
  });

  it("转发命中时不 next()，原样透传官服状态与响应体", async () => {
    mockAxios.mockResolvedValueOnce({ status: 200, data: { ok: true } });
    const handler = createProxyForwarder();
    const req = makeReq();
    const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith({ ok: true });
    expect(mockAxios).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        url: `${OFFICIAL_GS_HOST}/account/login`,
        data: { uid: "1" },
      }),
    );
  });

  it("剥离 host/content-length/transfer-encoding（防 content-length 透传导致官服挂起），其余头保留", async () => {
    mockAxios.mockResolvedValueOnce({ status: 200, data: {} });
    const handler = createProxyForwarder();
    const req = makeReq({
      url: "/user/oauth2/v2/grant",
      originalUrl: "/user/oauth2/v2/grant",
      headers: {
        host: "127.0.0.1:8443",
        "content-length": "94",
        "transfer-encoding": "chunked",
        "content-type": "application/json",
        "x-deviceid": "06cfbdc4f24e55eea40ef8b5cab88b0c",
      },
      body: { token: "x", type: 0 },
    });
    const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
    const next = vi.fn();

    await handler(req, res, next);

    const [call] = mockAxios.mock.calls;
    const headers = call[0].headers as Record<string, unknown>;
    expect(headers["host"]).toBeUndefined();
    expect(headers["content-length"]).toBeUndefined();
    expect(headers["transfer-encoding"]).toBeUndefined();
    // 其余业务头保留透传
    expect(headers["content-type"]).toBe("application/json");
    expect(headers["x-deviceid"]).toBe("06cfbdc4f24e55eea40ef8b5cab88b0c");
  });

  it("未命中转发目标时 next()，不改写响应", async () => {
    const handler = createProxyForwarder();
    const req = makeReq({
      method: "GET",
      url: "/config/prod/official/network_config",
      originalUrl: "/config/prod/official/network_config",
      body: {},
    });
    const res = { status: vi.fn(), send: vi.fn() } as any;
    const next = vi.fn();

    await handler(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(mockAxios).not.toHaveBeenCalled();
    expect(res.send).not.toHaveBeenCalled();
  });

  it("网络层错误（官服不可达）返回 502", async () => {
    mockAxios.mockRejectedValueOnce(new Error("ENOTFOUND"));
    const handler = createProxyForwarder();
    const req = makeReq();
    const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
    const next = vi.fn();

    await handler(req, res, next);

    expect(res.status).toHaveBeenCalledWith(502);
    expect(res.send).toHaveBeenCalledWith("Bad Gateway");
  });

  it("arkhub enterHall 转发官服并改写 endpoint/port 指向代理（网关转发器运行中）", async () => {
    mockAxios.mockResolvedValueOnce({
      status: 200,
      data: {
        result: 0,
        endpoint: "arkhub-gateway-canary.hypergryph.com",
        port: 30000,
        playerDataDelta: { modified: {}, deleted: {} },
      },
    });
    const handler = createProxyForwarder({
      arkhubGateway: { endpoint: "127.0.0.1", port: 30000 },
    });
    const req = makeReq({
      url: "/activity/arkhub/enterHall",
      originalUrl: "/activity/arkhub/enterHall",
      body: { activityId: "act1arkhub", createHall: 0 },
    });
    const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
    const next = vi.fn();

    await handler(req, res, next);

    // 转发官服 → 响应经内置变换器改写为代理地址
    expect(mockAxios).toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith({
      result: 0,
      endpoint: "127.0.0.1",
      port: 30000,
      playerDataDelta: { modified: {}, deleted: {} },
    });
    // 同时动态更新 TCP 转发器目标（跟随官服 canary 域名）
    expect(getGatewayTarget()).toEqual({
      host: "arkhub-gateway-canary.hypergryph.com",
      port: 30000,
    });
  });

  it("未传 arkhubGateway（转发器未启动）时 enterHall 响应不改写但仍更新转发目标", async () => {
    mockAxios.mockResolvedValueOnce({
      status: 200,
      data: { result: 0, endpoint: "arkhub-gateway-canary.hypergryph.com", port: 30000, playerDataDelta: {} },
    });
    const handler = createProxyForwarder(); // 无 arkhubGateway
    const req = makeReq({
      url: "/activity/arkhub/enterHall",
      originalUrl: "/activity/arkhub/enterHall",
      body: { activityId: "act1arkhub", createHall: 0 },
    });
    const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
    const next = vi.fn();

    await handler(req, res, next);

    expect(res.send).toHaveBeenCalledWith({
      result: 0,
      endpoint: "arkhub-gateway-canary.hypergryph.com",
      port: 30000,
      playerDataDelta: {},
    });
    expect(getGatewayTarget().host).toBe("arkhub-gateway-canary.hypergryph.com");
  });

  it("非 enterHall 的 arkhub 接口（syncInfo）仍转发官服（抓真实响应）", async () => {
    mockAxios.mockResolvedValueOnce({ status: 200, data: { playerDataDelta: {} } });
    const handler = createProxyForwarder({
      arkhubGateway: { endpoint: "127.0.0.1", port: 30000 },
    });
    const req = makeReq({
      url: "/activity/arkhub/syncInfo",
      originalUrl: "/activity/arkhub/syncInfo",
      body: { activityId: "act1arkhub" },
    });
    const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
    const next = vi.fn();

    await handler(req, res, next);

    expect(mockAxios).toHaveBeenCalled();
    expect(res.send).toHaveBeenCalledWith({ playerDataDelta: {} });
  });

  it("multipart（req.rawBody 存在）原样透传原始字节，不用空 req.body", async () => {
    mockAxios.mockResolvedValueOnce({ status: 200, data: {} });
    const handler = createProxyForwarder();
    const raw = Buffer.from('--C880D0B0\r\nContent-Disposition: form-data; name="test"\r\n\r\npixel-data\r\n--C880D0B0--\r\n');
    const req = makeReq({
      url: "/activity/arkhub/savePixelArt",
      originalUrl: "/activity/arkhub/savePixelArt",
      headers: {
        host: "127.0.0.1:8443",
        "content-type": 'multipart/form-data; boundary="C880D0B0"',
      },
      body: {},
      rawBody: raw,
    });
    const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
    const next = vi.fn();

    await handler(req, res, next);

    const [call] = mockAxios.mock.calls;
    // 转发体是原始 Buffer（multipart 字节原样），而不是 {}
    expect(call[0].data).toBe(raw);
    expect(call[0].data).not.toBe(req.body);
    expect(call[0].headers["content-type"]).toBe('multipart/form-data; boundary="C880D0B0"');
  });

  it("capture + region.as/gs → 转发目标使用 region 主机（yostar 登录路径 → region.as）", async () => {
    mockAxios.mockResolvedValueOnce({ status: 200, data: {} });
    await withCaptureRegion(
      {
        enabled: true,
        region: "jp",
        regions: {
          jp: {
            as: "https://as.example.jp",
            gs: "https://gs.example.jp",
            asPathPrefixes: ["/account/yostar_auth_request"],
          },
        },
      },
      async () => {
        const handler = createProxyForwarder();
        const req = makeReq({
          url: "/account/yostar_auth_request",
          originalUrl: "/account/yostar_auth_request",
          body: { account: "x", password: "y" },
        });
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
        const next = vi.fn();

        await handler(req, res, next);

        expect(mockAxios).toHaveBeenCalledWith(
          expect.objectContaining({ url: "https://as.example.jp/account/yostar_auth_request" }),
        );
      },
    );
  });

  it("capture 未启用 → 转发目标回退现状（OFFICIAL_GS_HOST）", async () => {
    mockAxios.mockResolvedValueOnce({ status: 200, data: {} });
    await withCaptureRegion(
      { enabled: false, regions: { jp: { gs: "https://gs.example.jp" } } },
      async () => {
        const handler = createProxyForwarder();
        const req = makeReq();
        const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
        const next = vi.fn();

        await handler(req, res, next);

        expect(mockAxios).toHaveBeenCalledWith(
          expect.objectContaining({ url: `${OFFICIAL_GS_HOST}/account/login` }),
        );
      },
    );
  });

  describe("自定义上游与变换器接入", () => {
    it("自定义上游（registerUpstream）命中 → 转发到自定义 baseUrl", async () => {
      mockAxios.mockResolvedValueOnce({ status: 200, data: { from: "custom" } });
      registerUpstream({
        id: "obs",
        baseUrl: "https://obs.example.com",
        rules: [{ paths: ["/arkodc"] }],
      });
      const handler = createProxyForwarder();
      const req = makeReq({
        url: "/arkodc/odp",
        originalUrl: "/arkodc/odp",
        body: { act: 1 },
      });
      const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
      const next = vi.fn();

      await handler(req, res, next);

      expect(mockAxios).toHaveBeenCalledWith(
        expect.objectContaining({ url: "https://obs.example.com/arkodc/odp", data: { act: 1 } }),
      );
      expect(res.send).toHaveBeenCalledWith({ from: "custom" });
    });

    it("request 变换器改 header/body → axios 收到修改后参数", async () => {
      mockAxios.mockResolvedValueOnce({ status: 200, data: {} });
      registerRequestTransform({
        path: "/account",
        fn: (ctx) => {
          ctx.headers = { ...ctx.headers, "x-transform": "yes" };
          ctx.body = { uid: "injected" };
          return ctx;
        },
      });
      const handler = createProxyForwarder();
      const req = makeReq();
      const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
      const next = vi.fn();

      await handler(req, res, next);

      const [call] = mockAxios.mock.calls;
      expect(call[0].headers["x-transform"]).toBe("yes");
      expect(call[0].data).toEqual({ uid: "injected" });
    });

    it("response 变换器改 status/body → res.send 收到修改后响应", async () => {
      mockAxios.mockResolvedValueOnce({ status: 200, data: { ok: true } });
      registerResponseTransform({
        path: "/account",
        fn: (ctx) => {
          ctx.status = 201;
          ctx.responseBody = { patched: true };
          return ctx;
        },
      });
      const handler = createProxyForwarder();
      const req = makeReq();
      const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
      const next = vi.fn();

      await handler(req, res, next);

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.send).toHaveBeenCalledWith({ patched: true });
    });

    it("变换器仅在命中上游时执行（upstreamId 过滤作用于转发链）", async () => {
      mockAxios.mockResolvedValueOnce({ status: 200, data: {} });
      registerResponseTransform({
        upstreamId: "custom-only",
        path: "/account",
        fn: (ctx) => {
          ctx.status = 418;
          return ctx;
        },
      });
      const handler = createProxyForwarder();
      const req = makeReq(); // 走官方 gs → 变换器不命中
      const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
      const next = vi.fn();

      await handler(req, res, next);

      expect(res.status).toHaveBeenCalledWith(200);
    });
  });
});
