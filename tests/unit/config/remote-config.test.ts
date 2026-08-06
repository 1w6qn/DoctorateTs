import { describe, it, expect, vi } from "vitest";

import {
  buildNetworkConfigContent,
  remoteConfigRouter,
} from "../../../app/config/remote-config";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  remoteConfigRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("buildNetworkConfigContent", () => {
  it("应替换 {server} 占位符为 Host:PORT", () => {
    const content = buildNetworkConfigContent();
    const parsed = JSON.parse(content);
    // configs.V058.network.gs 应指向实际服务器地址
    expect(parsed.configs.V058.network.gs).toMatch(/^http/);
    expect(parsed.configs.V058.network.gs).not.toContain("{server}");
    expect(parsed.configVer).toBeDefined();
  });
});

describe("remoteConfigRouter", () => {
  it("network_config 应返回 {sign, content}", async () => {
    const res = mockRes();
    await call(
      {
        method: "GET",
        url: "/1/prod/default/Windows/network_config",
        params: { version: "1", platform: "Windows" },
      },
      res,
    );
    expect(res.send).toHaveBeenCalledTimes(1);
    const arg = res.send.mock.calls[0][0];
    expect(arg.sign).toBeDefined();
    // content 是配置 JSON 字符串，含服务器地址
    expect(JSON.parse(arg.content).configs.V058.network.gs).toMatch(/^http/);
  });
});
