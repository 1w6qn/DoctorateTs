import { describe, it, expect, vi } from "vitest";
import type { Request, Response } from "express";

import {
  buildNetworkConfig,
  buildNetworkConfigContent,
  buildRemoteConfig,
  remoteConfigRouter,
} from "@core/config/remote-config";

/** 路由测试响应视图：只声明本文件读到的四个方法 */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

/** 路由测试请求视图：remote-config 只读 method/url/params */
interface MockReq {
  method: Request["method"];
  url: Request["url"];
  params: Request["params"];
}

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(url: string, res: MockRes) {
  const req: MockReq = {
    method: "GET",
    url,
    params: { version: "1", platform: "Windows" },
  };
  remoteConfigRouter(req as Request, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("buildNetworkConfigContent", () => {
  it("应替换 {server} 占位符为 Host:PORT", () => {
    const content = buildNetworkConfigContent();
    const parsed = JSON.parse(content);
    // funcVer 动态（V058 → V070 由 syncGameVersion 自动同步）
    const funcVer = Object.keys(parsed.configs)[0];
    expect(parsed.configs[funcVer].network.gs).toMatch(/^http/);
    expect(parsed.configs[funcVer].network.gs).not.toContain("{server}");
  });
});

describe("buildNetworkConfig（官方格式）", () => {
  it("应返回官方扁平格式网络端点（an/as/gs/hu/u8 等）", () => {
    const cfg = buildNetworkConfig();
    expect(cfg.configVer).toBeDefined();
    expect(cfg.gs).toMatch(/^http/);
    // auth 路由已挂根路径：as 域保持原路径（裸服务器地址，无 /auth 前缀）
    expect(cfg.as).toMatch(/^http/);
    expect(cfg.as).not.toContain("/auth");
    expect(cfg.hu).toContain("/assetbundle");
    // 内部字段不暴露
    expect(cfg.secure).toBeUndefined();
  });

  it("hv 应保留 {0} 占位符（客户端自行替换为版本/平台）", () => {
    const cfg = buildNetworkConfig();
    expect(String(cfg.hv)).toContain("{0}");
    expect(String(cfg.hv)).toContain("/config/prod/official/");
    expect(String(cfg.hv)).toMatch(/^http/);
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
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg.gs).toMatch(/^http/);
    expect(arg.configVer).toBeDefined();
  });

  it("remote_config 应返回空对象（2026-08-08 起路由固定返回 {}，buildRemoteConfig 函数保留）", async () => {
    const res = mockRes();
    await call("/1/prod/default/Windows/remote_config", res);
    const arg = vi.mocked(res.send).mock.calls[0][0];
    expect(arg).toEqual({});
    // 否定旧行为：不再返回默认功能开关（防回归）
    expect(arg.fapv2).toBeUndefined();
  });
});
