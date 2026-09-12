import { describe, it, expect, vi } from "vitest";
import type { Request, Response } from "express";
import { createHostRouter } from "@core/config/host-router";

/**
 * 中间件请求窄视图
 *
 * 生产实现只读取/重写 `req.url` 与 `req.headers.host`（见 app/core/config/host-router.ts）。
 * 真实 Express `Request` 可赋给该视图，故单向断言只放宽未被使用的成员（不改变运行期对象）。
 */
interface HostRouterRequest {
  headers: { host: string };
  url: string;
}

/** 构造请求替身 */
function mockReq(host: string, url: string): HostRouterRequest {
  return { headers: { host }, url };
}

/** 请求替身 → Express Request（单向断言，见 {@link HostRouterRequest}） */
function asRequest(req: HostRouterRequest): Request {
  return req as Request;
}

/** 空响应替身（本中间件不读写 res） */
const emptyRes = {} as Response;

describe("createHostRouter（子域名分发）", () => {
  it("as.hypergryph.com 请求应保持原样（auth 挂根直接命中登录）", () => {
    const handler = createHostRouter();
    const req = mockReq("as.hypergryph.com", "/user/auth/v1/token_by_phone_password");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/user/auth/v1/token_by_phone_password");
    expect(next).toHaveBeenCalled();
  });

  it("as.hypergryph.com u8 路径应保持原样（auth 挂根直接命中 U8 渠道）", () => {
    const handler = createHostRouter();
    const req = mockReq("as.hypergryph.com", "/u8/user/v1/getToken");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/u8/user/v1/getToken");
  });

  it("ak-conf.hypergryph.com 配置路径不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("ak-conf.hypergryph.com", "/config/prod/official/network_config");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/config/prod/official/network_config");
  });

  it("ak-conf.hypergryph.com 新版 remote_config 不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("ak-conf.hypergryph.com", "/api/remote_config/1/prod/default/Windows/network_config");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/api/remote_config/1/prod/default/Windows/network_config");
  });

  it("game-config.hypergryph.com 应去掉 /game-config 前缀映射到 remote_config", () => {
    const handler = createHostRouter();
    const req = mockReq("game-config.hypergryph.com", "/game-config/api/remote_config/1/prod/default/Windows/network_config");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/api/remote_config/1/prod/default/Windows/network_config");
    expect(next).toHaveBeenCalled();
  });

  it("ak-gs-gf.hypergryph.com 游戏路径不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("ak-gs-gf.hypergryph.com", "/account/syncData");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/account/syncData");
  });

  it("ak-gs-gf.hypergryph.com 带 /game 前缀的游戏路径应去掉前缀", () => {
    const handler = createHostRouter();
    const req = mockReq("ak-gs-gf.hypergryph.com", "/game/account/login");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/account/login");
  });

  it("as.hypergryph.com 已带 /auth 前缀的路径不应重复加前缀", () => {
    const handler = createHostRouter();
    const req = mockReq("as.hypergryph.com", "/auth/user/info/v1/basic");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/auth/user/info/v1/basic");
  });

  it("game-config.hypergryph.com 远程配置路径不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("game-config.hypergryph.com", "/api/remote_config/1/prod/default/Windows/remote_config");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/api/remote_config/1/prod/default/Windows/remote_config");
  });

  it("路径级 /as/ 前缀应映射到 /auth（子域名路径化客户端）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/as/app/v1/config?appCode=7318def77669979d&platform=2");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/auth/app/v1/config?appCode=7318def77669979d&platform=2");
  });

  it("非 hypergryph 域名（localhost/私服 IP 直连）不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("localhost:8443", "/account/syncData");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/account/syncData");
  });

  // ==================== mitmweb 重定向场景（Host 被改写为 127.0.0.1:8443） ====================
  // 注：auth 已挂根路径（index.ts `app.use("/", auth)`），as 域接口（/app、/u8、/user/*）直接命中，
  //     applyPathFallback 不再需要加 /auth 前缀兜底（2026-08-07 新分发方案）

  it("mitmweb 重写 Host 后 /app 路径保持原样（auth 挂根直接命中 as 域配置）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/app/v1/config?appCode=7318def77669979d&platform=2");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/app/v1/config?appCode=7318def77669979d&platform=2");
  });

  it("mitmweb 重写 Host 后 /u8 路径保持原样（auth 挂根直接命中 U8 渠道）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/u8/user/v1/getToken");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/u8/user/v1/getToken");
  });

  it("mitmweb 重写 Host 后 /user/auth 路径保持原样（auth 挂根直接命中登录）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/user/auth/v1/login");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/user/auth/v1/login");
  });

  it("mitmweb 重写 Host 后精确 /user/auth 保持原样（auth 挂根直接命中 Token 校验）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/user/auth");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/user/auth");
  });

  it("mitmweb 重写 Host 后 /user/info 路径保持原样（auth 挂根直接命中用户信息）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/user/info/v1/basic?token=abc");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/user/info/v1/basic?token=abc");
  });

  it("mitmweb 重写 Host 后 /user/online 路径保持原样（auth 挂根直接命中心跳）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/user/online/v1/ping");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/user/online/v1/ping");
  });

  it("mitmweb 重写 Host 后 /user/oauth2 路径保持原样（auth 挂根直接命中授权）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/user/oauth2/v2/grant");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/user/oauth2/v2/grant");
  });

  it("mitmweb 重写 Host 后游戏域 /user 接口不应被误判（保持原路径）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/user/changeSecretary");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/user/changeSecretary");
  });

  it("mitmweb 重写 Host 后带 /game 基址前缀的游戏路径应剥掉", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/game/account/login");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/account/login");
  });

  it("mitmweb 重写 Host 后游戏接口路径不应重写（batch_event 等）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/batch_event");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/batch_event");
  });

  it("mitmweb 重写 Host 后已带 /auth 前缀的路径保持幂等", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/auth/user/info/v1/basic");
    const next = vi.fn();
    handler(asRequest(req), emptyRes, next);
    expect(req.url).toBe("/auth/user/info/v1/basic");
  });
});
