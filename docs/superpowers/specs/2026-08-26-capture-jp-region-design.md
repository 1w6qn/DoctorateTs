# capture 日服支持：RegionProvider 抽象层设计

> 日期：2026-08-26 · 状态：已确认（用户批准实现）
> 目标：扩展 capture 模式支持「使用国服资源游玩日服」——日服客户端（YoStarJP）经代理/mitmweb 接入私服，gs/as 流量转发日服官服，conf/版本/资源本地响应；支持伪装客户端版本与资源版本、支持指定资源版本。

## 1. 需求确认（用户选择）

| 决策点 | 结论 |
|---|---|
| gs/as 去向 | 转发日服官服（账号/游戏流量转发日服 as/gs，配置项指定） |
| 资源（hu）角色 | 本地响应/可配：本地 `assets/` 优先，CDN 基址与下载版本可指定 |
| 版本伪装 | clientVersion = 日服客户端内置版号（不触发强更）；resVersion = 指定国服资源版本（本地存在） |
| 客户端接入 | 代理/mitmweb（Host 头被改写，走路径级兜底分发；host-router 域名识别不在本次范围） |
| 配置形态 | 独立 region 配置表（预瞻《多服支持》方案 A 的 regions 维度），capture 引用之 |
| 架构形态 | 方案 B：完整 RegionProvider 抽象层（version/资产/转发路径映射全走抽象接口） |

## 2. 配置结构（data/config.json）

```jsonc
{
  "region": "cn",                       // 全局当前 region（缺省 "cn"；仅 capture 链路消费）
  "capture": {
    "enabled": false,
    "region": "jp",                     // capture 专用 region 覆盖（可选，优先于全局 region）
    "gatewayPort": 30001
  },
  "regions": {                          // region 配置表（新增；字段级回退，零迁移）
    "cn": {                             // 国服基线（可选；不配则回退 config.version 等现状）
      "version": { "clientVersion": "2.7.61", "resVersion": "26-08-17-11-25-42_dbc172" },
      "cdn": "https://ak.hycdn.cn",
      "as": "https://as.hypergryph.com",
      "gs": "https://ak-gs-gf.hypergryph.com"
    },
    "jp": {                             // 日服（YoStarJP）
      "version": {                      // 版本伪装（字段级可选）
        "clientVersion": "<日服客户端版号>",
        "resVersion": "<指定资源版本>"    // 本地 assets 存在的版本
      },
      "cdn": "https://ak.hycdn.cn",     // 资源 CDN 基址（缺省国服 CDN）
      "cdnVersion": "<版本>",           // CDN 下载用版本（缺省 version.resVersion）——「指定资源版本」
      "as": "https://account.yostar.co.jp",  // capture 转发目标（日服账号域）
      "gs": "https://<日服 gs>",        // capture 转发目标（日服游戏域）
      "asPathPrefixes": [               // 额外 as 域路径前缀（yostar 登录链路，可选）
        "/account/yostar_auth_request", "/user/yostar_createlogin", "/yostar/get-auth"
      ]
    }
  }
}
```

**作用域决策**：region 特性仅在 capture 模式生效（`capture.enabled`）。非 capture 的私服游玩场景保持现状，避免伪装版本破坏正常更新链路。

## 3. RegionProvider 抽象（新文件 app/config/region.ts）

- `RegionConfig` 类型：`version?`（clientVersion/resVersion/windows 字段级可选）、`cdn?`、`cdnVersion?`、`as?`、`gs?`、`asPathPrefixes?`
- `resolveRegionId()`：capture 未启用 → null；否则 `capture.region ?? config.region ?? "cn"`；未知 region → warn + null
- 解析纯函数（独立于 config 实例，可单测）：
  - `resolveRegionVersion(region, fallback)` → 字段级回退 `config.version`
  - `resolveRegionCdn(region, fallbackCdn)` → `region.cdn ?? fallbackCdn`（fallbackCdn = `https://ak.hycdn.cn`）
  - `resolveRegionCdnVersion(region, resolvedVersion)` → `region.cdnVersion ?? resolvedVersion.resVersion`
  - `resolveRegionHosts(region, fallbackAs, fallbackGs)` → `{ as, gs }`
  - `resolveRegionAsPrefixes(region, defaultPrefixes)` → `[...default, ...(region.asPathPrefixes ?? [])]`
- `RegionConfig` 类型加入 `app/config.ts` 的 `UserConfig`（`region?`、`regions?`、`capture.region?`）

## 4. version 伪装（app/config/prod.ts）

- 三个 version 端点（Android / Windows / `:version`）：`resolveRegion()` 非空时用 `resolveRegionVersion` 结果替换 `config.version` 作为响应体（mod 签名逻辑不变，capture 已禁用 mod）
- `refresh_config` 端点同样返回伪装版本
- `traceVersionIssued` 溯源沿用伪装值
- hv 端点路径参数（`:version`）保持通配，不校验

## 5. 资源通道（app/asset.ts）

- CDN 基址 3 处硬编码（downloadPeoxy 代理转发 / downloadLocally=false 302 重定向 / exportFile 下载）→ `resolveRegionCdn` 结果
- `officialResVersion(platform)`：`region.cdnVersion` → `region.version.resVersion` → 现状（config.version / windows 分支保留）
- 本地 `assets/{请求hash}/redirect/` 命中与回退链不变（请求 hash = version 端点伪装值）

## 6. 转发目标与路径映射（app/proxy/official-forward.ts）

- `createOfficialForwarder` 主机数据源：`region.as/gs` → `capture.asHost/gsHost`（现状）→ `OFFICIAL_*_HOST`（缺省）
- `resolveForwardTarget` 新增可选 `opts.asPathPrefixes?: string[]`：路径级兜底并入额外前缀（yostar 登录路径 → as 域）；默认列表不变
- Host 优先分发规则、arkhub 网关适配、warmup 逻辑不动

## 7. 兼容性与错误处理

- 零迁移：无 regions / region 缺失 / capture 未启用 → `resolveRegion()` 返回 null → 消费方全部现状分支
- 未知 region 名 / regions 缺条目 → `logger.warn("region", ...)` + 回退现状
- 伪装 cdnVersion 在指定 CDN 404 → 走既有 asset-backfill 回退链

## 8. 测试计划

| 文件 | 用例 |
|---|---|
| `tests/unit/config/region.test.ts`（新） | capture 优先、缺省回退、字段级回退、未知 region、非 capture null |
| `tests/unit/config/prod-version.test.ts`（扩展） | regions.jp 伪装 version 端点；未配置 region → 现状 |
| `tests/unit/proxy/official-forward.test.ts`（扩展） | opts.asPathPrefixes → as 域；region 主机优先级 |
| `tests/unit/config/region.test.ts`（含 cdn） | resolveRegionCdnVersion 平台分支回退 |

验证顺序：`pnpm exec tsc --noEmit` → `pnpm exec vitest run`。
