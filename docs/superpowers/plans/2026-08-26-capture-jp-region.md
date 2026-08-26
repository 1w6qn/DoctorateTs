# Capture 日服支持（RegionProvider 抽象层）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 扩展 capture 模式支持日服客户端：新增 region 抽象层，version 伪装（clientVersion/resVersion 可指定）、资源通道参数化（CDN/版本可指定）、转发目标与 as 域路径前缀可配，全部字段级回退保证零迁移。

**Architecture:** `app/config/region.ts` 提供 `RegionConfig` 类型 + `resolveRegionId()`（capture 未启用/未知 region → null）+ 5 个解析纯函数（字段级回退）。三个消费方（prod.ts version 伪装、asset.ts CDN/版本、official-forward.ts 转发目标/路径前缀）读 region 解析结果，region 为 null 时走现状分支。region 特性仅在 capture 模式生效。

**Tech Stack:** TypeScript / Express 5 / vitest（globals off，显式 import describe/it/expect；node env）

**设计文档：** `docs/superpowers/specs/2026-08-26-capture-jp-region-design.md`

**提交策略：** 遵循项目 AGENTS.md —— 不主动 git commit；每个 Task 以 tsc + 相关测试通过为完成标准。

---

## 文件结构

| 文件 | 责任 | 动作 |
|---|---|---|
| `app/config/region.ts` | RegionConfig 类型 + resolveRegionId + 5 个解析纯函数 | 新建 |
| `app/config.ts` | UserConfig 接口扩展（region / regions / capture.region） | 修改 |
| `app/config/prod.ts` | version 端点（Android/Windows/:version）与 refresh_config 返回伪装版本 | 修改 |
| `app/asset.ts` | CDN 基址 3 处参数化 + officialResVersion region-aware | 修改 |
| `app/proxy/official-forward.ts` | 转发主机数据源 region 优先 + resolveForwardTarget 支持 asPathPrefixes | 修改 |
| `tests/unit/config/region.test.ts` | region 解析纯函数 + resolveRegionId 全部用例 | 新建 |
| `tests/unit/config/prod-version.test.ts` | version 伪装用例（mutate config） | 扩展 |
| `tests/unit/proxy/official-forward.test.ts` | asPathPrefixes 参数 + region 主机用例 | 扩展 |

**测试基建关键事实**（先读再动手）：
- `prod-version.test.ts` 模式：`vi.mock("@utils/file")` 提供 config 数据源；`config.ts` 顶层 `const config = readJsonSync(...)` 在 import 时加载一次，之后**可运行时 mutate config 对象**驱动不同场景（region 解析每次调用时读当前值）。
- `official-forward.test.ts` 未 mock config（读真实 `data/config.json`，`capture.enabled=false`）；`createOfficialForwarder` 在**创建时**解析主机，mutate config 后再创建 handler 即生效。
- `asset.ts` 无既有测试文件；`officialResVersion` 的 region 行为由 region.test.ts 纯函数用例覆盖（避免 import asset.ts 连带 express/yauzl/asset-service 的副作用风险），asset.ts 改动以 tsc + 全量回归验证。

---

### Task 1: region 抽象层（app/config/region.ts）+ 单元测试

**Files:**
- Create: `app/config/region.ts`
- Test: `tests/unit/config/region.test.ts`

- [ ] **Step 1: 写失败测试 `tests/unit/config/region.test.ts`**

```typescript
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

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

import config from "../../../app/config";
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
} from "../../../app/config/region";

/** 测试间隔离：保存/恢复 config 的 region 相关字段 */
function withRegionConfig(
  patch: { captureEnabled: boolean; captureRegion?: string; region?: string; regions?: Record<string, RegionConfig> },
  fn: () => void,
): void {
  const savedCapture = config.capture;
  const savedRegion = config.region;
  const savedRegions = (config as any).regions;
  try {
    (config as any).capture = {
      ...(savedCapture ?? {}),
      enabled: patch.captureEnabled,
      ...(patch.captureRegion !== undefined ? { region: patch.captureRegion } : {}),
    };
    if (patch.region !== undefined) config.region = patch.region;
    if (patch.regions !== undefined) (config as any).regions = patch.regions;
    fn();
  } finally {
    (config as any).capture = savedCapture;
    config.region = savedRegion;
    (config as any).regions = savedRegions;
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
    expect(resolveRegionCdnVersion(JP, { clientVersion: "2.9.01", resVersion: "26-08-17-11-25-42_dbc172" }))
      .toBe("26-08-07-14-53-29_30b8f0");
    expect(resolveRegionCdnVersion(null, { clientVersion: "2.7.61", resVersion: "26-08-17-11-25-42_dbc172" }))
      .toBe("26-08-17-11-25-42_dbc172");
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
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm exec vitest run tests/unit/config/region.test.ts`
Expected: FAIL — "Failed to resolve import"（`app/config/region` 不存在）

- [ ] **Step 3: 实现 `app/config/region.ts`**

```typescript
/**
 * region 抽象层（RegionProvider）
 *
 * 多服维度配置解析：capture 模式下按 region 提供伪装版本、资源通道（CDN/版本）、
 * 转发目标与 as 域路径前缀。字段级回退保证零迁移——region 未配置/字段缺失时
 * 全部回退现状（config.version / 国服 CDN / 现有转发主机）。
 *
 * 作用域：region 特性仅在 capture 模式生效（config.capture.enabled）；非 capture
 * 的私服游玩场景保持现状，避免伪装版本破坏正常更新链路。
 */
import config from "./config";
import { logger } from "@utils/logger";

/** region 版本伪装（字段级可选，缺省回退 config.version 对应字段） */
export interface RegionVersion {
  clientVersion?: string;
  resVersion?: string;
  windows?: { clientVersion?: string; resVersion?: string };
}

/** 单 region 配置（对齐《多服支持》方案 A 字段：as/gs/cdn/version） */
export interface RegionConfig {
  /** 版本伪装（version 端点响应字段级回退 config.version） */
  version?: RegionVersion;
  /** 资源 CDN 基址（缺省国服 CDN DEFAULT_CDN） */
  cdn?: string;
  /** CDN 下载用资源版本（缺省 version.resVersion；「指定资源版本」） */
  cdnVersion?: string;
  /** capture 转发 as 目标（缺省 OFFICIAL_AS_HOST / capture.asHost） */
  as?: string;
  /** capture 转发 gs 目标（缺省 OFFICIAL_GS_HOST / capture.gsHost） */
  gs?: string;
  /** 额外 as 域路径前缀（yostar 登录链路等，可选；与默认 AS_PATH_PREFIXES 合并） */
  asPathPrefixes?: string[];
}

/** 国服资源 CDN 基址（region 未配置时的缺省值） */
export const DEFAULT_CDN = "https://ak.hycdn.cn";

/** 解析后版本（字段已回退，非可选） */
export interface ResolvedVersion {
  clientVersion: string;
  resVersion: string;
  windows?: { clientVersion: string; resVersion: string };
}

/**
 * 当前生效 region id（capture 模式专用）
 *
 * capture.region ?? config.region ?? "cn"；capture 未启用或 region 名不在
 * regions 表中（cn 缺条目属正常——回退 config.version 现状）→ null。
 */
export function resolveRegionId(): string | null {
  if (!config.capture?.enabled) return null;
  const id = config.capture.region ?? config.region ?? "cn";
  if (!config.regions?.[id]) {
    if (id !== "cn") {
      logger.warn("region", `region "${id}" 未在 regions 表配置，回退现状`);
    }
    return null;
  }
  return id;
}

/** 当前生效的 region 配置（null = 现状行为） */
export function resolveRegion(): RegionConfig | null {
  const id = resolveRegionId();
  if (!id) return null;
  return config.regions?.[id] ?? null;
}

/** 伪装版本：region.version 字段级回退 fallback（config.version） */
export function resolveRegionVersion(
  region: RegionConfig | null,
  fallback: ResolvedVersion,
): ResolvedVersion {
  if (!region?.version) return fallback;
  return {
    clientVersion: region.version.clientVersion ?? fallback.clientVersion,
    resVersion: region.version.resVersion ?? fallback.resVersion,
    windows: region.version.windows
      ? {
          clientVersion:
            region.version.windows.clientVersion ??
            fallback.windows?.clientVersion ??
            fallback.clientVersion,
          resVersion:
            region.version.windows.resVersion ??
            fallback.windows?.resVersion ??
            fallback.resVersion,
        }
      : fallback.windows,
  };
}

/** 资源 CDN 基址：region.cdn 优先，缺省 fallbackCdn（DEFAULT_CDN） */
export function resolveRegionCdn(
  region: RegionConfig | null,
  fallbackCdn: string = DEFAULT_CDN,
): string {
  return region?.cdn ?? fallbackCdn;
}

/** CDN 下载用资源版本：region.cdnVersion 优先，缺省解析后版本的 resVersion */
export function resolveRegionCdnVersion(region: RegionConfig | null, resolved: ResolvedVersion): string {
  return region?.cdnVersion ?? resolved.resVersion;
}

/** 转发目标：region.as/gs 优先，缺省回退 fallback */
export function resolveRegionHosts(
  region: RegionConfig | null,
  fallbackAs: string,
  fallbackGs: string,
): { as: string; gs: string } {
  return { as: region?.as ?? fallbackAs, gs: region?.gs ?? fallbackGs };
}

/** as 域路径前缀：默认列表 + region.asPathPrefixes 扩展 */
export function resolveRegionAsPrefixes(
  region: RegionConfig | null,
  defaults: readonly string[],
): string[] {
  return [...defaults, ...(region?.asPathPrefixes ?? [])];
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pnpm exec vitest run tests/unit/config/region.test.ts`
Expected: PASS（13 个用例）

---

### Task 2: UserConfig 类型扩展（app/config.ts）

**Files:**
- Modify: `app/config.ts`

- [ ] **Step 1: 在 `UserConfig` 接口加入 region 字段**

在 `capture` 配置块（第 86-98 行）内新增 `region` 字段，并在 `version` 字段（第 54 行）之后新增 `region` 与 `regions`：

```typescript
  /** 登录响应主版本号（客户端校验用——去硬编码，缺省 "446"） */
  majorVersion?: string;
  /** 当前 region（缺省 "cn"；仅 capture 模式消费，见 config/region.ts） */
  region?: string;
  /**
   * region 配置表（capture 模式下按 region 伪装版本/资源通道/转发目标；
   * 字段级回退，零迁移——未配置任何 region 时行为与现状一致）。
   * 结构见 app/config/region.ts 的 RegionConfig。
   */
  regions?: Record<string, import("./config/region").RegionConfig>;
```

```typescript
  capture?: {
    /** 是否开启官服转发（客户端连接私服，as/gs 请求转发官服；config/asset/admin 仍本地响应）。
     *  开启时强制禁用 assets.enableMods——抓包须还原官服原生资源，mod 污染抓包流量 */
    enabled?: boolean;
    /** capture 专用 region 覆盖（可选；优先于全局 region；缺省跟随 config.region） */
    region?: string;
    /** 官服 as 主机（缺省 https://as.hypergryph.com） */
    asHost?: string;
    /** 官服 gs 主机（缺省 https://ak-gs-gf.hypergryph.com） */
    gsHost?: string;
```

- [ ] **Step 2: 类型检查**

Run: `pnpm exec tsc --noEmit`
Expected: PASS（0 errors；`import("./config/region")` 类型引用因 Task 1 已实现而可解析，type-only 引用运行时擦除，无循环依赖）

---

### Task 3: version 伪装（app/config/prod.ts）+ 测试扩展

**Files:**
- Modify: `app/config/prod.ts`
- Test: `tests/unit/config/prod-version.test.ts`

- [ ] **Step 1: 写失败测试（扩展 `tests/unit/config/prod-version.test.ts`）**

在文件顶部 import 块后新增 config 导入与恢复辅助；文件底部追加新 describe：

```typescript
import config from "../../../app/config";

/** 保存/恢复 config 的 region 相关字段（version 伪装用例隔离） */
function withCaptureRegion(
  patch: { enabled: boolean; region?: string; regions?: Record<string, any> },
  fn: () => void,
): void {
  const savedCapture = config.capture;
  const savedRegions = (config as any).regions;
  try {
    (config as any).capture = { ...(savedCapture ?? {}), enabled: patch.enabled, ...(patch.region !== undefined ? { region: patch.region } : {}) };
    if (patch.regions !== undefined) (config as any).regions = patch.regions;
    fn();
  } finally {
    (config as any).capture = savedCapture;
    (config as any).regions = savedRegions;
  }
}
```

文件末尾追加：

```typescript
describe("prod 版本路由（region 伪装）", () => {
  it("capture + region.version 配置 → version 端点返回伪装值", async () => {
    withCaptureRegion(
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
    withCaptureRegion(
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
    withCaptureRegion(
      {
        enabled: true,
        region: "jp",
        regions: { jp: { version: { clientVersion: "2.9.01", resVersion: "26-08-17-11-25-42_dbc172" } } },
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
    withCaptureRegion(
      { enabled: false, regions: { jp: { version: { clientVersion: "2.9.01" } } } },
      async () => {
        const res = mockRes();
        await call("/official/Android/version", res);
        expect(res.send.mock.calls[0][0].clientVersion).toBe("2.5.60");
      },
    );
  });
});
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm exec vitest run tests/unit/config/prod-version.test.ts`
Expected: FAIL — 新增 4 个用例失败（Android/Windows 仍返回 mock 的 config.version 值）

- [ ] **Step 3: 实现 `app/config/prod.ts` 的 version 伪装**

文件顶部 import 区新增：

```typescript
import { resolveRegion, resolveRegionVersion } from "./region";
```

在 `withModSig` 函数后新增（三个端点与 refresh_config 共用）：

```typescript
/**
 * 生效版本：capture + region 伪装（region.version 字段级回退 config.version）；
 * 无生效 region 时返回 config.version（现状）。仅 capture 模式消费——非 capture
 * 的私服游玩场景不伪装，避免破坏客户端正常更新链路。
 */
function servedVersion() {
  const region = resolveRegion();
  return region ? resolveRegionVersion(region, config.version) : config.version;
}
```

替换三个 version 端点与 refresh_config 的 `config.version` 引用（注意 Windows 端点的 `win` 变量同步改用 servedVersion 结果）：

```typescript
// Windows 端点
router.get("/official/Windows/version", async (req, res) => {
  const version = servedVersion();
  const win = (version as any).windows;
  let modPatch: { resVersion?: string } = {};
  if (config.assets.enableMods) {
    await ensureModsLoaded("Windows");
    await refreshModsIfChanged("Windows");
    const sig = getModVersionSuffix("Windows");
    if (sig) modPatch = { resVersion: withModSig(win?.resVersion || version.resVersion, sig) };
  }
  traceVersionIssued("Windows", modPatch.resVersion ?? (win?.resVersion || version.resVersion));
  res.send(Object.assign({}, win || version, modPatch));
});

// Android 端点
router.get("/official/Android/version", async (req, res) => {
  const version = servedVersion();
  let modPatch: { resVersion?: string } = {};
  if (config.assets.enableMods) {
    await ensureModsLoaded("Android");
    await refreshModsIfChanged("Android");
    const sig = getModVersionSuffix("Android");
    if (sig) modPatch = { resVersion: withModSig(version.resVersion, sig) };
  }
  traceVersionIssued("Android", modPatch.resVersion ?? version.resVersion);
  res.send(Object.assign({}, version, modPatch));
});

// :version 通配端点
router.get("/official/:version/version", async (req, res) => {
  const version = servedVersion();
  let modPatch: { resVersion?: string } = {};
  if (config.assets.enableMods) {
    await ensureModsLoaded("Android");
    await refreshModsIfChanged("Android");
    const sig = getModVersionSuffix("Android");
    if (sig) modPatch = { resVersion: withModSig(version.resVersion, sig) };
  }
  traceVersionIssued("Android", modPatch.resVersion ?? version.resVersion);
  res.send(Object.assign({}, version, modPatch));
});

// refresh_config 端点
router.get("/official/refresh_config", async (req, res) => {
  res.send(servedVersion());
});
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pnpm exec vitest run tests/unit/config/prod-version.test.ts`
Expected: PASS（原有 5 用例 + 新增 4 用例全绿）

---

### Task 4: 转发目标与 as 路径前缀（app/proxy/official-forward.ts）+ 测试扩展

**Files:**
- Modify: `app/proxy/official-forward.ts`
- Test: `tests/unit/proxy/official-forward.test.ts`

- [ ] **Step 1: 写失败测试（扩展 `tests/unit/proxy/official-forward.test.ts`）**

文件顶部 import 块追加 config 导入与恢复辅助（放在现有 import 之后）：

```typescript
import config from "../../../app/config";

/** 保存/恢复 config 的 region 相关字段（region 主机用例隔离） */
function withCaptureRegion(
  patch: { enabled: boolean; region?: string; regions?: Record<string, any> },
  fn: () => void,
): void {
  const savedCapture = config.capture;
  const savedRegions = (config as any).regions;
  try {
    (config as any).capture = { ...(savedCapture ?? {}), enabled: patch.enabled, ...(patch.region !== undefined ? { region: patch.region } : {}) };
    if (patch.regions !== undefined) (config as any).regions = patch.regions;
    fn();
  } finally {
    (config as any).capture = savedCapture;
    (config as any).regions = savedRegions;
  }
}
```

在「主机覆写（opts.asHost/gsHost）」describe 内追加：

```typescript
    it("opts.asPathPrefixes 额外前缀 → as 域（yostar 登录链路）", () => {
      const opts = {
        asHost: "https://as.example.jp",
        gsHost: "https://gs.example.jp",
        asPathPrefixes: ["/account/yostar_auth_request", "/user/yostar_createlogin", "/yostar/get-auth"],
      };
      expect(resolveForwardTarget("POST", "/account/yostar_auth_request", "127.0.0.1", opts)).toEqual({
        baseUrl: "https://as.example.jp",
        path: "/account/yostar_auth_request",
      });
      expect(resolveForwardTarget("POST", "/yostar/get-auth", "127.0.0.1", opts)).toEqual({
        baseUrl: "https://as.example.jp",
        path: "/yostar/get-auth",
      });
    });

    it("未传 asPathPrefixes → 默认列表行为不变（/account/login 仍走 gs 兜底）", () => {
      const opts = { asHost: "https://as.example.jp", gsHost: "https://gs.example.jp" };
      expect(resolveForwardTarget("POST", "/account/login", "127.0.0.1", opts)).toEqual({
        baseUrl: "https://gs.example.jp",
        path: "/account/login",
      });
    });
```

在「createOfficialForwarder（axios 转发）」describe 内追加（region 主机数据源）：

```typescript
    it("capture + region.as/gs → 转发目标使用 region 主机（yostar 登录路径 → region.as）", async () => {
      mockAxios.mockResolvedValueOnce({ status: 200, data: {} });
      withCaptureRegion(
        {
          enabled: true,
          region: "jp",
          regions: {
            jp: {
              as: "https://as.example.jp",
              gs: "https://gs.example.jp",
              asPathPrefixes: ["/account/yostar_auth_request"],
            },
          },
        },
        () => {
          const handler = createOfficialForwarder();
          const req = {
            method: "POST",
            url: "/account/yostar_auth_request",
            headers: { host: "127.0.0.1:8443" },
            body: { account: "x", password: "y" },
            query: {},
            originalUrl: "/account/yostar_auth_request",
          } as any;
          const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
          const next = vi.fn();
          void handler(req, res, next).then(() => {
            expect(mockAxios).toHaveBeenCalledWith(
              expect.objectContaining({ url: "https://as.example.jp/account/yostar_auth_request" }),
            );
          });
        },
      );
      await new Promise((r) => setTimeout(r, 10));
    });

    it("capture 未启用 → 转发目标回退现状（OFFICIAL_GS_HOST）", async () => {
      mockAxios.mockResolvedValueOnce({ status: 200, data: {} });
      withCaptureRegion(
        { enabled: false, regions: { jp: { gs: "https://gs.example.jp" } } },
        () => {
          const handler = createOfficialForwarder();
          const req = {
            method: "POST",
            url: "/account/login",
            headers: { host: "127.0.0.1:8443" },
            body: {},
            query: {},
            originalUrl: "/account/login",
          } as any;
          const res = { status: vi.fn().mockReturnThis(), send: vi.fn() } as any;
          const next = vi.fn();
          void handler(req, res, next).then(() => {
            expect(mockAxios).toHaveBeenCalledWith(
              expect.objectContaining({ url: `${OFFICIAL_GS_HOST}/account/login` }),
            );
          });
        },
      );
      await new Promise((r) => setTimeout(r, 10));
    });
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pnpm exec vitest run tests/unit/proxy/official-forward.test.ts`
Expected: FAIL — 新增 4 个用例失败（`asPathPrefixes` 未实现 / region 主机未生效）

- [ ] **Step 3: 实现 `app/proxy/official-forward.ts`**

文件顶部 import 区新增：

```typescript
import { resolveRegion, resolveRegionAsPrefixes, resolveRegionHosts } from "../config/region";
```

`ForwardHostOptions` 接口新增字段：

```typescript
/** 主机覆写配置（缺省用 OFFICIAL_AS_HOST / OFFICIAL_GS_HOST） */
export interface ForwardHostOptions {
  asHost?: string;
  gsHost?: string;
  /** 额外 as 域路径前缀（region 扩展——yostar 登录链路等；缺省不扩展） */
  asPathPrefixes?: string[];
}
```

`resolveForwardTarget` 函数体（路径级兜底循环）替换：

```typescript
  const asHost = opts.asHost || OFFICIAL_AS_HOST;
  const gsHost = opts.gsHost || OFFICIAL_GS_HOST;
  const asPathPrefixes = [...AS_PATH_PREFIXES, ...(opts.asPathPrefixes ?? [])];
  const path = (url.split("?")[0] || "/").replace(/^\/+/, "/");
```

```typescript
  for (const prefix of asPathPrefixes) {
    if (hasPathPrefix(path, prefix)) {
      // 注意：path 保留完整原路径（含 /u8），baseUrl 只给 as 域根地址——若 baseUrl 再拼 /u8 基址
      // 会与 path 里的 /u8 双写（实测 as.hypergryph.com/u8/u8/user/v1/getToken → 404），
      // 与 Host 分支（as.* → baseUrl=asHost + 全路径）保持一致
      return { baseUrl: asHost, path };
    }
  }
```

`createOfficialForwarder` 函数体头部替换（region 主机数据源，优先级 region.as/gs → capture.asHost/gsHost → OFFICIAL_*_HOST）：

```typescript
export function createOfficialForwarder(opts: OfficialForwarderOptions = {}): RequestHandler {
  // region 主机数据源：region.as/gs → capture.asHost/gsHost（现状）→ OFFICIAL_*_HOST
  const region = resolveRegion();
  const fallbackAs = config.capture?.asHost || OFFICIAL_AS_HOST;
  const fallbackGs = config.capture?.gsHost || OFFICIAL_GS_HOST;
  const hosts = region
    ? resolveRegionHosts(region, fallbackAs, fallbackGs)
    : { as: fallbackAs, gs: fallbackGs };
  const asPathPrefixes = resolveRegionAsPrefixes(region, AS_PATH_PREFIXES);
  const { arkhubGateway } = opts;

  return async (req, res, next) => {
    const target = resolveForwardTarget(req.method, req.url, req.headers.host || "", {
      asHost: hosts.as,
      gsHost: hosts.gs,
      asPathPrefixes,
    });
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pnpm exec vitest run tests/unit/proxy/official-forward.test.ts`
Expected: PASS（原有用例 + 新增 4 用例全绿）

---

### Task 5: 资源通道参数化（app/asset.ts）

**Files:**
- Modify: `app/asset.ts`

> 说明：asset.ts 无既有测试文件，本任务改动为 URL 常量替换 + officialResVersion 读取 region，逻辑由 region.test.ts 纯函数用例覆盖；验证以 tsc + 全量回归为准。

- [ ] **Step 1: 实现 CDN 基址与版本参数化**

文件顶部 import 区新增：

```typescript
import {
  resolveRegion,
  resolveRegionCdn,
  resolveRegionCdnVersion,
  resolveRegionVersion,
} from "./config/region";
```

`officialResVersion` 函数整体替换（region 优先级：cdnVersion → 伪装 resVersion → 现状；Windows 平台分支保留）：

```typescript
/**
 * 官方（无 mod 签名）资源版本：按平台取 config 中登记的官方 resVersion（CDN 下载用）。
 * 客户端请求的 assetsHash 是替换过 hash 的 mod 版本，需还原官方版本才能命中官方 CDN。
 * region 生效时：region.cdnVersion 显式指定则用之（「指定资源版本」），否则用伪装后的
 * region.version.resVersion（version 端点下发的值），最后回退 config.version 现状。
 * @param platform - 平台键（Windows/Android），未知平台回退默认版本
 */
export function officialResVersion(platform: string): string {
  const region = resolveRegion();
  const version = region ? resolveRegionVersion(region, config.version) : config.version;
  const win = (version as any).windows;
  if (platform === "Windows" && win?.resVersion) return win.resVersion;
  return region ? resolveRegionCdnVersion(region, version) : version.resVersion;
}
```

新增模块级辅助函数（放在 `officialResVersion` 之后）：

```typescript
/**
 * 资源 CDN 基址：region.cdn 可配（缺省国服 CDN）——downloadPeoxy 代理转发、
 * downloadLocally=false 重定向与 exportFile 下载共用。
 */
function resolveCdnBase(): string {
  return resolveRegionCdn(resolveRegion());
}
```

替换 3 处硬编码 CDN URL（保持其余 URL 结构不变）：

1. proxy 代理模式（约第 64 行）：
```typescript
      const resp = await fetch(
        `${resolveCdnBase()}/assetbundle/official/${cdnPlatform}/assets/${cdnVersion}/${fileName}`,
        { headers: forwardHeaders, signal: AbortSignal.timeout(CDN_TIMEOUT) },
      );
```

2. downloadLocally=false 重定向（约第 83 行）：
```typescript
        return res.redirect(
          `${resolveCdnBase()}/assetbundle/official/${cdnPlatform}/assets/${version}/${fileName}`,
        );
```

3. exportFile 调用处（约第 170 行）：
```typescript
    const fp = await exportFile(
      `${resolveCdnBase()}/assetbundle/official/${cdnPlatform}/assets/${cdnVersion}/${fileName}`,
      basePath,
      fileName,
      filePath,
      assetsHash,
      wrongSize,
      mods,
      cdnPlatform,
    );
```

- [ ] **Step 2: 类型检查**

Run: `pnpm exec tsc --noEmit`
Expected: PASS（0 errors）

---

### Task 6: 全量验证

**Files:**
- 无新增

- [ ] **Step 1: 全量类型检查**

Run: `pnpm exec tsc --noEmit`
Expected: PASS（0 errors）

- [ ] **Step 2: 全量测试回归**

Run: `pnpm exec vitest run`
Expected: PASS（全量用例绿，含新增 region.test.ts 13 用例 + prod-version 4 用例 + official-forward 4 用例）

- [ ] **Step 3: 手工验证清单（供用户验收，非自动化）**

1. 在 `data/config.json` 按设计文档 §2 添加 `regions.jp`（as/gs 填日服官服地址、version 填日服客户端版号与本地存在的国服 resVersion、cdn/cdnVersion 按需），设 `capture.enabled=true`、`capture.region="jp"`，重启服务
2. 请求 `GET http://127.0.0.1:8443/config/prod/official/Android/version` → 返回伪装 clientVersion/resVersion
3. 请求 `GET http://127.0.0.1:8443/assetbundle/official/Android/assets/{伪装resVersion}/hot_update_list.json` → 本地版本目录命中或按 cdnVersion 下载
4. 日服客户端经 mitmweb 代理接入 → 登录请求（`/account/yostar_auth_request` 等）转发到 region.as
5. 移除 `regions`/`capture.region` 后重启 → 所有响应与旧行为一致（零迁移回归）

---

## Self-Review

**1. Spec 覆盖核对**：
- §2 配置结构 → Task 1（RegionConfig）+ Task 2（UserConfig 类型）✓
- §3 RegionProvider 抽象（5 个解析函数 + resolveRegionId）→ Task 1 ✓
- §4 version 伪装（三端点 + refresh_config + traceVersionIssued）→ Task 3 ✓
- §5 资源通道（CDN 3 处 + officialResVersion）→ Task 5 ✓
- §6 转发目标 + asPathPrefixes → Task 4 ✓
- §7 兼容性（零迁移/未知 region warn/字段级回退）→ Task 1（resolveRegionId warn + 回退）+ 各 Task 现状分支 ✓
- §8 测试计划 → Task 1/3/4 测试 + Task 6 全量回归 ✓（asset.ts 无单测的取舍已在 Task 5 说明）

**2. 占位符扫描**：无 TBD/TODO；所有步骤含完整代码。数据文件 `data/config.json` 不自动修改（用户按验收清单自行添加 region 配置，与设计文档一致）。

**3. 类型一致性**：
- `resolveRegionVersion(region, fallback)` / `resolveRegionCdn(region, fallbackCdn?)` / `resolveRegionCdnVersion(region, resolved)` / `resolveRegionHosts(region, fallbackAs, fallbackGs)` / `resolveRegionAsPrefixes(region, defaults)` — 各 Task 引用签名一致 ✓
- `RegionConfig` / `ResolvedVersion` 在 Task 1 定义、Task 2 引用、Task 3-5 消费，字段名一致 ✓
- `ForwardHostOptions.asPathPrefixes` 在 Task 4 定义并贯穿测试与实现 ✓
