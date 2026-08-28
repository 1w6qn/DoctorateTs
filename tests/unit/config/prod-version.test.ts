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

import prod from "@core/config/prod";
import config from "@core/config/index";

/** 保存/恢复 config 的 region 相关字段（version 伪装用例隔离；支持 async fn） */
async function withCaptureRegion(
  patch: { enabled: boolean; region?: string; regions?: Record<string, any> },
  fn: () => Promise<void> | void,
): Promise<void> {
  const savedCapture = config.capture;
  const savedRegions = (config as any).regions;
  try {
    (config as any).capture = {
      ...(savedCapture ?? {}),
      enabled: patch.enabled,
      ...(patch.region !== undefined ? { region: patch.region } : {}),
    };
    if (patch.regions !== undefined) (config as any).regions = patch.regions;
    await fn();
  } finally {
    (config as any).capture = savedCapture;
    (config as any).regions = savedRegions;
  }
}

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(url: string, res: any) {
  prod({ method: "GET", url } as any, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("prod 版本路由（region 伪装）", () => {
  it("capture + region.version 配置 → version 端点返回伪装值", async () => {
    await withCaptureRegion(
      {
        enabled: true,
        region: "jp",
        regions: {
          jp: {
            version: {
              clientVersion: "2.9.01",
              resVersion: "26-08-17-11-25-42_dbc172",
              windows: { clientVersion: "2.9.01", resVersion: "26-07-30-09-00-07_win" },
            },
          },
        },
      },
      async () => {
        const android = mockRes();
        await call("/official/Android/version", android);
        const arg = android.send.mock.calls[0][0];
        expect(arg.clientVersion).toBe("2.9.01");
        expect(arg.resVersion).toBe("26-08-17-11-25-42_dbc172");

        const windows = mockRes();
        await call("/official/Windows/version", windows);
        expect(windows.send.mock.calls[0][0].resVersion).toBe("26-07-30-09-00-07_win");
      },
    );
  });

  it("region.version 部分字段 → 缺省字段回退 config.version（字段级伪装）", async () => {
    await withCaptureRegion(
      {
        enabled: true,
        region: "jp",
        regions: { jp: { version: { clientVersion: "2.9.01" } } },
      },
      async () => {
        const res = mockRes();
        await call("/official/Android/version", res);
        const arg = res.send.mock.calls[0][0];
        expect(arg.clientVersion).toBe("2.9.01");
        expect(arg.resVersion).toBe("25-05-20-12-36-22_4803e1");
      },
    );
  });

  it("refresh_config 端点返回伪装版本", async () => {
    await withCaptureRegion(
      {
        enabled: true,
        region: "jp",
        regions: {
          jp: { version: { clientVersion: "2.9.01", resVersion: "26-08-17-11-25-42_dbc172" } },
        },
      },
      async () => {
        const res = mockRes();
        await call("/official/refresh_config", res);
        const arg = res.send.mock.calls[0][0];
        expect(arg.clientVersion).toBe("2.9.01");
      },
    );
  });

  it("capture 未启用 → 不伪装（现状回归）", async () => {
    await withCaptureRegion(
      { enabled: false, regions: { jp: { version: { clientVersion: "2.9.01" } } } },
      async () => {
        const res = mockRes();
        await call("/official/Android/version", res);
        expect(res.send.mock.calls[0][0].clientVersion).toBe("2.5.60");
      },
    );
  });
});

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
