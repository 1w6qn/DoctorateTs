import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("os", () => ({
  default: { networkInterfaces: vi.fn() },
}));

import os from "os";
import config, { detectLocalIp, resolvePortOverride } from "@core/config/index";

describe("config Host 处理", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("默认配置不应含硬编码 192.168.0.100", () => {
    expect(String(config.Host)).not.toContain("192.168.0.100");
    expect(String(config.Host)).toBe("http://127.0.0.1");
  });

  it("detectLocalIp 应返回第一个非回环 IPv4", () => {
    (os.networkInterfaces as any).mockReturnValue({
      eth0: [{ family: "IPv4", address: "192.168.1.50", internal: false }],
      lo: [{ family: "IPv4", address: "127.0.0.1", internal: true }],
    });
    expect(detectLocalIp()).toBe("192.168.1.50");
  });

  it("无局域网 IP 时应回退 127.0.0.1", () => {
    (os.networkInterfaces as any).mockReturnValue({
      lo: [{ family: "IPv4", address: "127.0.0.1", internal: true }],
    });
    expect(detectLocalIp()).toBe("127.0.0.1");
  });

  it("Host 含 auto 时应自动检测替换", () => {
    (os.networkInterfaces as any).mockReturnValue({
      eth0: [{ family: "IPv4", address: "10.0.0.8", internal: false }],
    });
    // 模拟 auto 配置替换逻辑
    const host = "http://auto";
    const resolved = host.includes("auto") ? `http://${detectLocalIp()}` : host;
    expect(resolved).toBe("http://10.0.0.8");
  });
});

describe("resolvePortOverride（端口覆盖：--port > PORT 环境变量 > config.json）", () => {
  it("命令行 --port 优先于环境变量", () => {
    expect(resolvePortOverride(["-s", "--port", "9001"], "9000")).toBe(9001);
  });

  it("无 --port 时使用环境变量 PORT", () => {
    expect(resolvePortOverride(["-s"], "9000")).toBe(9000);
  });

  it("两者都无返回 null（用 config.json）", () => {
    expect(resolvePortOverride(["-s"], undefined)).toBeNull();
  });

  it("非法值回退 null", () => {
    expect(resolvePortOverride(["--port", "abc"], undefined)).toBeNull();
    expect(resolvePortOverride([], "99999")).toBeNull();
  });
});
