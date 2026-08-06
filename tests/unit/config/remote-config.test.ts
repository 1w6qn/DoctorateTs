import { describe, it, expect, vi } from "vitest";

import {
  buildNetworkConfig,
  buildNetworkConfigContent,
  buildRemoteConfig,
  remoteConfigRouter,
} from "../../../app/config/remote-config";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(url: string, res: any) {
  remoteConfigRouter(
    { method: "GET", url, params: { version: "1", platform: "Windows" } } as any,
    res,
    () => {},
  );
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("buildNetworkConfigContent", () => {
  it("应替换 {server} 占位符为 Host:PORT", () => {
    const content = buildNetworkConfigContent();
    const parsed = JSON.parse(content);
    expect(parsed.configs.V058.network.gs).toMatch(/^http/);
    expect(parsed.configs.V058.network.gs).not.toContain("{server}");
  });
});

describe("buildNetworkConfig（官方格式）", () => {
  it("应返回官方扁平格式网络端点（an/as/gs/hu/u8 等）", () => {
    const cfg = buildNetworkConfig();
    expect(cfg.configVer).toBeDefined();
    expect(cfg.gs).toMatch(/^http/);
    expect(cfg.as).toContain("/auth");
    expect(cfg.hu).toContain("/assetbundle");
    // 内部字段不暴露
    expect(cfg.secure).toBeUndefined();
  });
});

describe("buildRemoteConfig（功能配置）", () => {
  it("应返回官方默认功能开关", () => {
    const cfg = buildRemoteConfig();
    expect(cfg.fapv2).toBe(1);
    expect(cfg.HGDownload_1).toBe(10000);
    expect(cfg.HGDownload_2).toBe(10000);
    expect(cfg.enableGameBI).toBe(true);
    expect(cfg.enableNativeLicense).toBe(true);
  });
});

describe("remoteConfigRouter", () => {
  it("network_config 应返回官方格式网络配置", async () => {
    const res = mockRes();
    await call("/1/prod/default/Windows/network_config", res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.gs).toMatch(/^http/);
    expect(arg.configVer).toBeDefined();
  });

  it("remote_config 应返回功能开关配置", async () => {
    const res = mockRes();
    await call("/1/prod/default/Windows/remote_config", res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.fapv2).toBe(1);
    expect(arg.HGDownload_1).toBe(10000);
  });
});
