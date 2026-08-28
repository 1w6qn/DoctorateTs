# Proxy 通用转发管线重构设计（自定义上游 + 变换器管线）

- 日期：2026-08-28
- 范围：`app/ops/proxy/`（不迁移目录，原地增强）
- 目标：把 capture 专用官服转发器重构为通用转发管线——支持自定义上游（config + 代码 API 双通道）、可链式修改请求/响应内容、capture 开关直接驱动、旧 `official-forward.ts` 删除。

## 1. 背景与目标

### 现状

`app/ops/proxy/official-forward.ts`（291 行）是唯一 HTTP 转发实现，仅 `--capture` 模式挂载：

- **上游硬编码**：`OFFICIAL_AS_HOST` / `OFFICIAL_GS_HOST`，仅 `config.capture.asHost/gsHost` + region 覆写；
- **纯透传**：唯一响应改写是 arkhub enterHall 硬编码特例（`adaptArkhubEnterHallResponse`）；
- **能力不通用**：无法定义任意上游、无法在转发链上插入自定义修改逻辑。

### 目标（用户决策四项）

1. **不迁移目录**：`ops/proxy` 原地增强（不搬进 `game/`）；
2. **自定义上游**：config 声明 + `registerUpstream()` 代码 API 双通道；
3. **变换器管线**：request/response 链式变换（类似 mitmproxy addon）；
4. **替换 capture 转发逻辑**：capture 开关直接驱动新 proxy，旧 forwarder 删除。

### 「集成到 game」的落位说明

目录不迁移（遵决策 1），集成体现在三处：

- 挂载于游戏服务中间件链（`app/server.ts` 中 `game` 路由之前的转发位，capture 时生效）；
- 官方硬编码路由规则收敛为**数据**（上游表），可由 config/代码增补覆盖；
- 变换器注册 API 与模块无关，ops→game 方向已有先例（`handlers/` 即 ops 导入 game 活动模块），后续任一 game 模块可从 `public.ts` 暴露钩子由 server 接线——本设计不为此预设专属机制。

## 2. 文件结构

```
app/ops/proxy/
  upstream.ts     # 上游模型/注册表/通用解析器 resolveProxyTarget/官方内置上游构建
  transform.ts    # 变换器管线（register/apply，request/response 双阶段）
  forwarder.ts    # createProxyForwarder 中间件 + 共享 keep-alive agent + warmUpOfficialConnections
  index.ts        # public 出口（server.ts 与外部消费统一入口）
  arkhub-gateway*.ts  # 不动
  handlers/           # 不动
```

旧 `official-forward.ts` 删除，其导出按归属迁移：

| 旧导出 | 去向 |
|---|---|
| `resolveForwardTarget` | `upstream.ts`（重构为 `resolveProxyTarget`） |
| `createOfficialForwarder` | `forwarder.ts`（重构为 `createProxyForwarder`） |
| `officialHttpAgent` / `officialHttpsAgent` | `forwarder.ts` |
| `warmUpOfficialConnections` | `forwarder.ts` |
| `OFFICIAL_AS_HOST` / `OFFICIAL_GS_HOST` | `upstream.ts` |
| `ForwardTarget` / `ForwardHostOptions` | 类型并入 `upstream.ts` |

## 3. 上游模型与注册表（upstream.ts）

### 3.1 数据模型

```ts
/** 单条匹配规则：匹配 + 路径改写一体 */
interface ProxyRule {
  /** Host 通配匹配（小写，支持 * 段通配：如 "ak-gs-*"、"as.*.hypergryph.com"）；阶段 1 */
  hosts?: string[];
  /** 路径前缀匹配（hasPathPrefix 语义：精确或 前缀/）；阶段 2 */
  paths?: string[];
  /** HTTP 方法（大写）；缺省 = POST+GET 全匹配 */
  methods?: Array<"GET" | "POST" | "PUT" | "DELETE" | "PATCH">;
  /** 本规则转发前剥除的路径前缀（如 "/game" → 转发 /account/login） */
  stripPrefix?: string;
  /** 阶段 3 兜底（任意未命中路径；配合 methods 限制，如 official-gs 仅 POST） */
  catchAll?: boolean;
}

interface ProxyUpstream {
  /** 唯一 id */
  id: string;
  /** 目标主机（如 https://as.hypergryph.com） */
  baseUrl: string;
  /** 有序规则（同一上游内按序求值） */
  rules: ProxyRule[];
}
```

### 3.2 通用解析器（三阶段，与现状语义一一对应）

```ts
function resolveProxyTarget(
  method: string, url: string, host: string,
  upstreams: ProxyUpstream[],
): { upstream: ProxyUpstream; path: string } | null
```

流程：

1. **路径归一化**：去 query、前导多斜杠收敛为单斜杠（防官服 `//` 404，沿用现状）；
2. **全局守卫**：`LOCAL_ONLY_PREFIXES` 命中 → `null`（永不转发）。语义修正：现状 as-host 分支不查本地前缀（`/admin` 带 `as.*` host 会转发官方 404），收敛为全局守卫后此类请求保持本地——不破坏任何既有测试，行为更正确；
3. **阶段 1 host 规则**：`upstreams` 中所有 `rules[].hosts` 按序匹配（忽略 methods），命中即返回（应用 stripPrefix）；
4. **阶段 2 path 规则**：`rules[].paths` 按序匹配，需命中 methods；
5. **阶段 3 catchAll**：`rules[].catchAll` 按序匹配，需命中 methods；
6. 无命中 → `null`（保持本地路由 `next()`）。

**求值序**：`upstreams` 数组顺序即优先级——自定义上游（config + API 注册）在前、官方内置在后，自定义可覆盖官方兜底（例：自定义 `{id:"obs-arkodc", paths:["/arkodc"]}` 可截获本会落到官方 gs POST 兜底的请求）。

### 3.3 官方内置上游（行为与现 resolveForwardTarget 完全等价）

```ts
function buildOfficialUpstreams(opts: {
  asHost?: string; gsHost?: string; asPathPrefixes?: string[];
}): ProxyUpstream[]
```

- **official-as**（baseUrl = asHost，缺省 `https://as.hypergryph.com`）：
  1. `{ hosts: ["as.*.hypergryph.com"] }`（原样转发，含 GET）
  2. `{ paths: ["/as"], stripPrefix: "/as" }`（路径化前缀）
  3. `{ paths: [AS_PATH_PREFIXES..., ...asPathPrefixes] }`（`/user/auth`、`/user/info`、`/user/online`、`/user/oauth2`、`/u8`、`/app`、`/general` + region 扩展；`/u8` 路径保留防双写）
- **official-gs**（baseUrl = gsHost，缺省 `https://ak-gs-gf.hypergryph.com`）：
  1. `{ hosts: ["ak-gs-*"], stripPrefix: "/game" }`
  2. `{ paths: ["/game"], stripPrefix: "/game" }`（POST/GET 均转发）
  3. `{ catchAll: true, methods: ["POST"] }`（根路径 POST 兜底）

现状的 `opts.asHost/gsHost/asPathPrefixes` 覆写能力完整保留（region 主机优先级 `region.as/gs → capture.asHost/gsHost → OFFICIAL_*_HOST` 逻辑移入 `buildOfficialUpstreams` 或保持调用方传参）。

### 3.4 注册表 API（config + 代码双通道）

```ts
/** config 通道：批量注册静态上游（server 启动时调用；幂等——同名 id 覆盖） */
function registerUpstreams(list: ProxyUpstream[]): void;
/** 代码通道：注册单个上游 */
function registerUpstream(u: ProxyUpstream): void;
/** 代码通道：按 id 移除；返回是否命中 */
function unregisterUpstream(id: string): boolean;
/** 只读快照：当前全部上游（自定义在前、官方内置在后） */
function listUpstreams(): ProxyUpstream[];
/** 构建默认上游表：官方内置 + 已注册自定义（解析器实际使用的源） */
function resolveAllUpstreams(): ProxyUpstream[];
```

新 config 字段（`app/core/config/index.ts` UserConfig）：

```ts
proxy?: {
  /** 静态自定义上游（capture 模式生效；优先于官方内置上游求值） */
  upstreams?: ProxyUpstream[];
};
```

## 4. 变换器管线（transform.ts）

### 4.1 上下文与类型

```ts
interface ProxyTransformContext {
  method: string;
  originalUrl: string;      // 含 query 原样
  path: string;             // 剥 query、剥 /game 后的转发路径
  upstream: ProxyUpstream;  // 命中的上游
  // —— 请求阶段（转发前，可改）——
  headers: RawAxiosRequestHeaders;
  body?: unknown;           // 转发体（JSON 对象或原始 Buffer）
  // —— 响应阶段（回写前，可改）——
  status: number;
  responseBody: unknown;    // axios data（JSON 对象/字符串/Buffer）
}

type ProxyTransform = (ctx: ProxyTransformContext)
  => Promise<ProxyTransformContext> | ProxyTransformContext;

interface ProxyTransformRule {
  /** 缺省 = 任意上游 */
  upstreamId?: string;
  /** 路径匹配：字符串前缀 或 正则 */
  path?: string | RegExp;
  fn: ProxyTransform;
}
```

### 4.2 注册与执行

```ts
function registerRequestTransform(rule: ProxyTransformRule): void;
function registerResponseTransform(rule: ProxyTransformRule): void;
function applyRequestTransforms(ctx: ProxyTransformContext): Promise<ProxyTransformContext>;
function applyResponseTransforms(ctx: ProxyTransformContext): Promise<ProxyTransformContext>;
```

- **链式**：按注册序执行所有匹配规则，前一规则输出喂给后一规则输入；
- 匹配：`upstreamId`（精确）+ `path`（前缀字符串或正则）双条件 AND，缺省即放行；
- 变换器内可改 headers/body（请求阶段）或 status/responseBody（响应阶段）。

### 4.3 内置响应变换器：arkhub enterHall

从 `official-forward.ts` 迁移（行为不变）：

- 匹配 `{ path: "/activity/arkhub/enterHall" }`；
- 副作用 1：`updateGatewayTarget(endpoint, port)`（跟随官服网关域名变化）；
- 副作用 2：`arkhubGateway` 存在时改写 `endpoint/port` 指向本代理（转发器地址）；
- `arkhubGateway` 状态由 `forwarder.ts` 创建时注入（`setArkhubGatewayInfo`，模块级单一来源）。

## 5. 转发中间件（forwarder.ts）

```ts
interface ProxyForwarderOptions {
  arkhubGateway?: ArkhubGatewayInfo | null;
}
function createProxyForwarder(opts?: ProxyForwarderOptions): RequestHandler;
```

执行流程（保持现状既有行为）：

1. `resolveProxyTarget(req.method, req.url, req.headers.host)`（源 = `resolveAllUpstreams()`：自定义 + 官方内置）；
2. 未命中 → `next()`（本地路由）；
3. 构造转发请求：剥 `host` / `content-length` / `transfer-encoding`（防官服挂起），其余头透传；POST 转发体优先 `req.rawBody`（multipart 原始字节）回退 `req.body`（JSON）；
4. `applyRequestTransforms(ctx)`（可改 headers/body）；
5. axios 转发（共享 keep-alive agent 池，`validateStatus: () => true` 原样透传 4xx/5xx）；
6. `applyResponseTransforms(ctx)`（可改 status/responseBody）；
7. `res.status(ctx.status).send(ctx.responseBody)`；
8. 网络层错误 → `502 Bad Gateway`（仅官方主机不可达）。

共享 agent 与预热函数原样迁入本文件（`officialHttpAgent` / `officialHttpsAgent` / `warmUpOfficialConnections`）。

## 6. server.ts 集成与删除

capture 分支（`app/server.ts` 239-267 行区块）改造：

```ts
if (capture) {
  const { createProxyForwarder, warmUpOfficialConnections, registerUpstreams } =
    await import("@ops/proxy");
  // 静态自定义上游（config.proxy.upstreams），优先于官方内置求值
  registerUpstreams(config.proxy?.upstreams ?? []);
  // 预热官服连接（共享 keep-alive 池）
  const asHost = config.capture?.asHost ?? "https://as.hypergryph.com";
  const gsHost = config.capture?.gsHost ?? "https://ak-gs-gf.hypergryph.com";
  await warmUpOfficialConnections(asHost, gsHost).catch(() => undefined);
  // arkhub 网关转发器（TCP）——不变
  const { startArkhubGatewayProxy } = await import("@ops/proxy/arkhub-gateway");
  const gatewayPort = config.capture?.gatewayPort ?? 30000;
  const gw = await startArkhubGatewayProxy({ port: gatewayPort });
  const proxyHost = String(config.Host).replace(/^https?:\/\//, "");
  const arkhubGateway = gw.server || gw.exhausted ? { endpoint: proxyHost, port: gw.port } : null;
  // 通用转发管线（替换旧 createOfficialForwarder）
  app.use(createProxyForwarder({ arkhubGateway }));
  logger.info("index", "抓包官服转发模式已开启：proxy 通用转发管线（自定义上游 + 变换器）");
}
```

删除：`app/ops/proxy/official-forward.ts`。

## 7. 测试迁移与新增（TDD 先行）

现有 `tests/unit/proxy/official-forward.test.ts`（527 行）拆分迁移：

### 7.1 `tests/unit/proxy/upstream.test.ts`

原样迁移（语义不变，断言不改）：

- Host 优先分发（as.* / ak-gs-* / 配置域保持本地 / 其余官方子域）；
- 路径级兜底（/as 剥前缀、as 前缀、/u8 防双写、/game 剥前缀、POST 根兜底、本地挂载点排除、GET 非 as 不转发、/asset 边界）；
- 主机覆写（opts.asHost/gsHost、asPathPrefixes、缺省回退）；
- query 与多斜杠归一化；
- region 主机优先级（capture.region → capture.asHost/gsHost → 缺省）。

新增：

- 自定义上游命中优先于官方 gs POST 兜底（`{paths:["/arkodc"]}` 自定义 → 自定义 baseUrl）；
- `registerUpstream` / `unregisterUpstream` / `listUpstreams` 增删改查；
- `registerUpstreams` 同名 id 覆盖（幂等）；
- host 通配匹配（`"ak-gs-*"` 命中 `ak-gs-gf` / 不命中 `ak-gs-extra` 之外的 `as-*`）；
- 每规则独立 stripPrefix（同上游两规则不同 strip）。

### 7.2 `tests/unit/proxy/transform.test.ts`

新增：

- 链式按注册序执行，前一输出喂后一输入；
- `upstreamId` 过滤（仅命中指定上游）；
- `path` 前缀字符串与正则匹配；
- request 变换器改 headers/body → 反映到最终转发参数；
- response 变换器改 status/responseBody → 反映到 res.send；
- enterHall 内置变换器（迁移原 2 个 enterHall 用例：改写 endpoint/port + 更新网关目标；无 arkhubGateway 时仅更新目标不改写）。

### 7.3 `tests/unit/proxy/forwarder.test.ts`

原样迁移：

- 转发命中不 next()，透传状态与响应体；
- 剥离 host/content-length/transfer-encoding，其余头保留；
- 未命中 next() 不改写；
- 网络错误 502；
- multipart rawBody 原样透传；
- region 主机经 buildOfficialUpstreams 生效。

## 8. 明确不在范围（YAGNI）

- **arkhub TCP 网关与 handlers 不迁移**（活动特性基础设施，另议）；
- **变换器不支持短路**（不调上游直接回本地响应——本地应答是另一能力，需要时另设计）；
- **proxy-harness 路由表双源整合**（`docs/重复实现审查-整合清单.md` 第 13 项已记录：`scripts/proxy-harness.ts` 与官方路由表双源硬编码；本次 upstream.ts 将官方规则收敛为数据后，harness 后续可复用 `buildOfficialUpstreams`——中优先级，不在本迭代）；
- **非 capture 模式启用 proxy**（决策 4：capture 开关直接驱动，不新增独立开关）。

## 9. 验证标准

1. `pnpm exec tsc --noEmit` 通过（删除旧文件、新增三模块无类型错误）；
2. `tests/unit/proxy/*.test.ts` 全绿（含迁移语义 + 新增用例）；
3. `pnpm exec vitest run tests/unit/architecture/module-boundary.test.ts` 通过（无新越界 import）；
4. 冒烟：`--capture` 启动，客户端登录请求经 proxy 转发官方正常回包，`config.proxy.upstreams` 声明自定义上游命中后走自定义目标。
