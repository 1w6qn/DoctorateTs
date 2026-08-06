import { describe, it, expect, vi } from "vitest";
import { createHostRouter } from "../../../app/config/host-router";

function mockReq(host: string, url: string) {
  return { headers: { host }, url } as any;
}

describe("createHostRouter（子域名分发）", () => {
  it("as.hypergryph.com 请求应加 /auth 前缀", () => {
    const handler = createHostRouter();
    const req = mockReq("as.hypergryph.com", "/user/auth/v1/token_by_phone_password");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/auth/user/auth/v1/token_by_phone_password");
    expect(next).toHaveBeenCalled();
  });

  it("as.hypergryph.com u8 路径应加 /auth 前缀", () => {
    const handler = createHostRouter();
    const req = mockReq("as.hypergryph.com", "/u8/user/v1/getToken");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/auth/u8/user/v1/getToken");
  });

  it("ak-conf.hypergryph.com 配置路径不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("ak-conf.hypergryph.com", "/config/prod/official/network_config");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/config/prod/official/network_config");
  });

  it("ak-conf.hypergryph.com 新版 remote_config 不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("ak-conf.hypergryph.com", "/api/remote_config/1/prod/default/Windows/network_config");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/api/remote_config/1/prod/default/Windows/network_config");
  });

  it("game-config.hypergryph.com 应去掉 /game-config 前缀映射到 remote_config", () => {
    const handler = createHostRouter();
    const req = mockReq("game-config.hypergryph.com", "/game-config/api/remote_config/1/prod/default/Windows/network_config");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/api/remote_config/1/prod/default/Windows/network_config");
    expect(next).toHaveBeenCalled();
  });

  it("ak-gs-gf.hypergryph.com 游戏路径不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("ak-gs-gf.hypergryph.com", "/account/syncData");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/account/syncData");
  });

  it("ak-gs-gf.hypergryph.com 带 /game 前缀的游戏路径应去掉前缀", () => {
    const handler = createHostRouter();
    const req = mockReq("ak-gs-gf.hypergryph.com", "/game/account/login");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/account/login");
  });

  it("as.hypergryph.com 已带 /auth 前缀的路径不应重复加前缀", () => {
    const handler = createHostRouter();
    const req = mockReq("as.hypergryph.com", "/auth/user/info/v1/basic");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/auth/user/info/v1/basic");
  });

  it("game-config.hypergryph.com 远程配置路径不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("game-config.hypergryph.com", "/api/remote_config/1/prod/default/Windows/remote_config");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/api/remote_config/1/prod/default/Windows/remote_config");
  });

  it("路径级 /as/ 前缀应映射到 /auth（子域名路径化客户端）", () => {
    const handler = createHostRouter();
    const req = mockReq("127.0.0.1:8443", "/as/app/v1/config?appCode=7318def77669979d&platform=2");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/auth/app/v1/config?appCode=7318def77669979d&platform=2");
  });

  it("非 hypergryph 域名（localhost/私服 IP 直连）不应重写", () => {
    const handler = createHostRouter();
    const req = mockReq("localhost:8443", "/account/syncData");
    const next = vi.fn();
    handler(req, {} as any, next);
    expect(req.url).toBe("/account/syncData");
  });
});
