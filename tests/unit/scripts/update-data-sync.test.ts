import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../../scripts/official-api", () => ({
  getResVersion: vi.fn(),
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
  NetworkConfig: {},
});

describe("syncGameVersion 版本同步", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fsMock.readFileSync.mockReturnValue(CONFIG_SAMPLE);
  });

  it("应获取官服最新版本并更新 config.json", async () => {
    (getResVersion as any).mockResolvedValue({
      clientVersion: "2.6.00",
      resVersion: "26-01-01-00-00-00_newhash",
    });
    const ok = await syncGameVersion();
    expect(ok).toBe(true);
    // 写入 config.json（含新版本）
    const writeCall = fsMock.writeFileSync.mock.calls.find((c: any) =>
      String(c[0]).includes("config.json"),
    );
    expect(writeCall).toBeDefined();
    const written = JSON.parse(writeCall[1]);
    expect(written.version.clientVersion).toBe("2.6.00");
    expect(written.version.resVersion).toBe("26-01-01-00-00-00_newhash");
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
