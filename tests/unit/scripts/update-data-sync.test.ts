import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../../scripts/official-api", () => ({
  getResVersion: vi.fn(),
  CONF_API: "https://ak-conf.hypergryph.com",
}));

const fsMock = vi.hoisted(() => ({
  readFileSync: vi.fn(),
  writeFileSync: vi.fn(),
  existsSync: vi.fn(() => true),
  readdirSync: vi.fn(() => []),
  mkdirSync: vi.fn(),
  statSync: vi.fn(() => ({ isFile: () => false })),
  copyFileSync: vi.fn(),
}));
vi.mock("fs", () => fsMock);
vi.mock("child_process", () => ({ execSync: vi.fn() }));

import { syncGameVersion } from "../../../scripts/update-data";
import { getResVersion } from "../../../scripts/official-api";

const CONFIG_SAMPLE = JSON.stringify({
  Host: "http://127.0.0.1",
  PORT: 8443,
  version: { clientVersion: "2.5.60", resVersion: "25-05-20-12-36-22_4803e1" },
  assets: { enableMods: false },
  NetworkConfig: {
    configVer: "5",
    funcVer: "V058",
    configs: { V058: { override: true, network: { gs: "{server}" } } },
  },
});

describe("syncGameVersion 版本同步", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fsMock.readFileSync.mockReturnValue(CONFIG_SAMPLE);
    // mock fetch：Windows version + network_config（官服）
    vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any) => {
      if (String(url).includes("/Windows/version")) {
        return { ok: true, json: async () => ({ clientVersion: "2.7.61", resVersion: "26-07-30-09-00-07_win" }) } as any;
      }
      if (String(url).includes("/network_config")) {
        return { ok: true, json: async () => ({ content: JSON.stringify({ configVer: "5", funcVer: "V070", configs: {} }) }) } as any;
      }
      return { ok: false } as any;
    });
  });

  it("应获取官服最新版本并更新 config.json", async () => {
    (getResVersion as any).mockResolvedValue({
      clientVersion: "2.6.00",
      resVersion: "26-01-01-00-00-00_newhash",
    });
    const ok = await syncGameVersion();
    expect(ok).toBe(true);
    const writeCall = fsMock.writeFileSync.mock.calls.find((c: any) =>
      String(c[0]).includes("config.json"),
    );
    expect(writeCall).toBeDefined();
    const written = JSON.parse(writeCall[1]);
    expect(written.version.clientVersion).toBe("2.6.00");
    expect(written.version.resVersion).toBe("26-01-01-00-00-00_newhash");
    // Windows 独立版本
    expect(written.version.windows.resVersion).toBe("26-07-30-09-00-07_win");
    // funcVer 网络配置同步（V058 → V070）
    expect(written.NetworkConfig.funcVer).toBe("V070");
    expect(written.NetworkConfig.configs.V070).toBeDefined();
    expect(written.NetworkConfig.configs.V058).toBeUndefined();
  });

  it("版本无变化时应保持（不报错）", async () => {
    (getResVersion as any).mockResolvedValue({
      clientVersion: "2.5.60",
      resVersion: "25-05-20-12-36-22_4803e1",
    });
    const ok = await syncGameVersion();
    expect(ok).toBe(true);
  });

  it("获取版本失败应返回 false 不崩溃", async () => {
    (getResVersion as any).mockRejectedValue(new Error("HTTP 500"));
    const ok = await syncGameVersion();
    expect(ok).toBe(false);
  });
});
