import { describe, it, expect, vi } from "vitest";

vi.mock("@utils/file", () => ({
  readJsonSync: vi.fn(() => ({
    Host: "http://127.0.0.1",
    PORT: 8443,
    version: {
      clientVersion: "2.5.60",
      resVersion: "25-05-20-12-36-22_4803e1",
      windows: { clientVersion: "2.5.60", resVersion: "26-07-30-09-00-07_win" },
    },
    assets: { enableMods: false },
    NetworkConfig: {},
  })),
  readJson: vi.fn().mockResolvedValue({ announcement: "test" }),
}));

import prod from "../../../app/config/prod";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(url: string, res: any) {
  prod({ method: "GET", url } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("prod 版本路由（多平台）", () => {
  it("Windows 平台版本应返回独立 windows resVersion", async () => {
    const res = mockRes();
    await call("/official/Windows/version", res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.resVersion).toBe("26-07-30-09-00-07_win");
  });

  it("Android 平台版本应返回默认 resVersion", async () => {
    const res = mockRes();
    await call("/official/Android/version", res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.resVersion).toBe("25-05-20-12-36-22_4803e1");
  });

  it("clientVersion 路径版本应返回默认版本", async () => {
    const res = mockRes();
    await call("/official/2.5.60/version", res);
    const arg = res.send.mock.calls[0][0];
    expect(arg.clientVersion).toBe("2.5.60");
    expect(arg.resVersion).toBe("25-05-20-12-36-22_4803e1");
  });

  it("Windows 平台公告元数据应返回公告（平台参数化）", async () => {
    const res = mockRes();
    await call("/announce_meta/Windows/preannouncement.meta.json", res);
    expect(res.send).toHaveBeenCalledWith(expect.any(Object));
  });

  it("客户端拼接路径（announce_meta + gate meta）应容错返回公告", async () => {
    const res = mockRes();
    await call(
      "/announce_meta/Windows/preannouncement.meta.json/api/gate/meta/Windows",
      res,
    );
    expect(res.send).toHaveBeenCalledWith(expect.any(Object));
  });
});
