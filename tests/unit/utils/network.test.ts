import { describe, it, expect, vi, beforeEach } from "vitest";
import os from "os";

vi.mock("os", () => ({
  default: { networkInterfaces: vi.fn() },
}));

import { getIPAddress } from "@utils/network";

describe("getIPAddress", () => {
  beforeEach(() => {
    vi.mocked(os.networkInterfaces).mockReset();
  });

  it("应返回第一个非本机 IPv4 地址", () => {
    (os.networkInterfaces as any).mockReturnValue({
      eth0: [{ family: "IPv4", address: "192.168.1.5", internal: false }],
      lo: [{ family: "IPv4", address: "127.0.0.1", internal: true }],
    });
    expect(getIPAddress()).toBe("192.168.1.5");
  });

  it("应跳过 127.0.0.1 与 internal 接口", () => {
    (os.networkInterfaces as any).mockReturnValue({
      lo: [{ family: "IPv4", address: "127.0.0.1", internal: true }],
    });
    expect(getIPAddress()).toBeUndefined();
  });

  it("isIPV4=false 时应返回 IPv6 地址", () => {
    (os.networkInterfaces as any).mockReturnValue({
      eth0: [{ family: "IPv6", address: "fe80::1", internal: false }],
      lo: [{ family: "IPv6", address: "::1", internal: true }],
    });
    expect(getIPAddress(false)).toBe("fe80::1");
  });

  it("无可用接口时返回 undefined", () => {
    (os.networkInterfaces as any).mockReturnValue({});
    expect(getIPAddress()).toBeUndefined();
  });
});
