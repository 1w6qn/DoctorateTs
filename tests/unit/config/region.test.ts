import { describe, it, expect, vi } from "vitest";

vi.mock("@utils/file", () => ({
  readJsonSync: vi.fn(() => ({
    Host: "http://127.0.0.1",
    PORT: 8443,
    capture: { enabled: false },
    region: "cn",
    version: { clientVersion: "2.7.61", resVersion: "26-08-17-11-25-42_dbc172" },
    assets: {},
    NetworkConfig: {},
  })),
}));

import config from "@core/config/index";
import {
  resolveRegion,
  resolveRegionId,
  resolveRegionAsPrefixes,
  resolveRegionCdn,
  resolveRegionCdnVersion,
  resolveRegionHosts,
  resolveRegionVersion,
  DEFAULT_CDN,
  RegionConfig,
} from "@core/config/region";

/** 测试间隔离：保存/恢复 config 的 region 相关字段 */
function withRegionConfig(
  patch: {
    captureEnabled: boolean;
    captureRegion?: string;
    region?: string;
    regions?: Record<string, RegionConfig>;
  },
  fn: () => void,
): void {
  const savedCapture = config.capture;
  const savedRegion = config.region;
  const savedRegions = config.regions;
  try {
    config.capture = {
      ...(savedCapture ?? {}),
      enabled: patch.captureEnabled,
      ...(patch.captureRegion !== undefined ? { region: patch.captureRegion } : {}),
    };
    if (patch.region !== undefined) config.region = patch.region;
    if (patch.regions !== undefined) config.regions = patch.regions;
    fn();
  } finally {
    config.capture = savedCapture;
    config.region = savedRegion;
    config.regions = savedRegions;
  }
}

const JP: RegionConfig = {
  version: { clientVersion: "2.9.01", resVersion: "26-08-17-11-25-42_dbc172" },
  cdn: "https://cdn.example.jp",
  cdnVersion: "26-08-07-14-53-29_30b8f0",
  as: "https://as.example.jp",
  gs: "https://gs.example.jp",
  asPathPrefixes: ["/account/yostar_auth_request", "/user/yostar_createlogin"],
};

describe("resolveRegionId（region 选择）", () => {
  it("capture 未启用 → null（region 特性仅 capture 模式生效）", () => {
    withRegionConfig({ captureEnabled: false }, () => {
      expect(resolveRegionId()).toBeNull();
    });
  });

  it("capture 启用 + capture.region 指定 → 该 region（capture 优先于全局）", () => {
    withRegionConfig({ captureEnabled: true, captureRegion: "jp", regions: { jp: JP } }, () => {
      expect(resolveRegionId()).toBe("jp");
    });
  });

  it("capture 启用 + 无 capture.region → 全局 region（缺省 cn）", () => {
    withRegionConfig({ captureEnabled: true, region: "cn" }, () => {
      expect(resolveRegionId()).toBe("cn");
    });
  });

  it("capture 启用 + 未知 region（regions 表无条目）→ null", () => {
    withRegionConfig({ captureEnabled: true, captureRegion: "zz" }, () => {
      expect(resolveRegionId()).toBeNull();
    });
  });
});

describe("resolveRegion（当前 region 配置）", () => {
  it("返回 regions 表中的配置对象", () => {
    withRegionConfig({ captureEnabled: true, captureRegion: "jp", regions: { jp: JP } }, () => {
      expect(resolveRegion()).toEqual(JP);
    });
  });

  it("无生效 region → null", () => {
    withRegionConfig({ captureEnabled: false }, () => {
      expect(resolveRegion()).toBeNull();
    });
  });
});

describe("resolveRegionVersion（版本伪装，字段级回退）", () => {
  const fallback = { clientVersion: "2.7.61", resVersion: "26-08-17-11-25-42_dbc172" };

  it("region.version 全值 → 全量伪装", () => {
    const r: RegionConfig = { version: { clientVersion: "2.9.01", resVersion: "26-07-24-10-43-30_d453ab" } };
    expect(resolveRegionVersion(r, fallback)).toEqual({
      clientVersion: "2.9.01",
      resVersion: "26-07-24-10-43-30_d453ab",
    });
  });

  it("region.version 部分字段 → 缺省字段回退 fallback", () => {
    const r: RegionConfig = { version: { resVersion: "26-07-24-10-43-30_d453ab" } };
    expect(resolveRegionVersion(r, fallback)).toEqual({
      clientVersion: "2.7.61",
      resVersion: "26-07-24-10-43-30_d453ab",
    });
  });

  it("region 无 version → fallback 原样", () => {
    expect(resolveRegionVersion(null, fallback)).toEqual(fallback);
    expect(resolveRegionVersion({ cdn: "https://x" }, fallback)).toEqual(fallback);
  });

  it("windows 字段级回退：region.windows 优先，缺省回退 fallback.windows，再回退主字段", () => {
    const r: RegionConfig = {
      version: {
        clientVersion: "2.9.01",
        resVersion: "26-07-24-10-43-30_d453ab",
        windows: { resVersion: "26-07-30-09-00-07_win" },
      },
    };
    expect(resolveRegionVersion(r, fallback)).toEqual({
      clientVersion: "2.9.01",
      resVersion: "26-07-24-10-43-30_d453ab",
      windows: { clientVersion: "2.9.01", resVersion: "26-07-30-09-00-07_win" },
    });
  });
});

describe("resolveRegionCdn / resolveRegionCdnVersion（资源通道）", () => {
  it("region.cdn 优先，缺省 DEFAULT_CDN", () => {
    expect(resolveRegionCdn(JP)).toBe("https://cdn.example.jp");
    expect(resolveRegionCdn(null)).toBe(DEFAULT_CDN);
    expect(resolveRegionCdn({})).toBe(DEFAULT_CDN);
  });

  it("cdnVersion 优先，缺省用解析后版本的 resVersion（指定资源版本）", () => {
    expect(
      resolveRegionCdnVersion(JP, { clientVersion: "2.9.01", resVersion: "26-08-17-11-25-42_dbc172" }),
    ).toBe("26-08-07-14-53-29_30b8f0");
    expect(
      resolveRegionCdnVersion(null, { clientVersion: "2.7.61", resVersion: "26-08-17-11-25-42_dbc172" }),
    ).toBe("26-08-17-11-25-42_dbc172");
  });
});

describe("resolveRegionHosts / resolveRegionAsPrefixes（转发目标）", () => {
  it("region.as/gs 优先，缺省回退 fallback", () => {
    expect(resolveRegionHosts(JP, "https://as.cn", "https://gs.cn")).toEqual({
      as: "https://as.example.jp",
      gs: "https://gs.example.jp",
    });
    expect(resolveRegionHosts(null, "https://as.cn", "https://gs.cn")).toEqual({
      as: "https://as.cn",
      gs: "https://gs.cn",
    });
  });

  it("asPathPrefixes 与默认列表合并；region 无扩展时仅默认列表", () => {
    const defaults = ["/user/auth", "/u8"];
    expect(resolveRegionAsPrefixes(JP, defaults)).toEqual([
      "/user/auth",
      "/u8",
      "/account/yostar_auth_request",
      "/user/yostar_createlogin",
    ]);
    expect(resolveRegionAsPrefixes(null, defaults)).toEqual(["/user/auth", "/u8"]);
  });
});
