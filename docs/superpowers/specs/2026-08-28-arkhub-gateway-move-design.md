# arkhub 网关迁入活动模块设计（TCP 协议/路由/功能 → arkhub 模块）

- 日期：2026-08-28
- 范围：`app/ops/proxy/arkhub-gateway*.ts` + `app/ops/proxy/handlers/` 共 8 文件 4201 行迁入 `app/game/modules/activities/arkhub/`
- 决策（用户四项）：全部迁入 / capture-manager 抽象为注入 / ops 侧统一走 public.ts / 精简重命名

## 1. 背景与目标

### 现状

arkhub（奇象巡展）活动的基础设施全部寄居在 `app/ops/proxy/`：

| 文件 | 行数 | 角色 |
|---|---|---|
| `arkhub-gateway.ts` | 342 | TCP 转发器（capture 模式 30000 端口透传官服网关）+ enterHall 适配函数 |
| `arkhub-gateway-codec.ts` | 271 | protobuf 帧编解码（encodeVarint/buildFrame/ProtoReader） |
| `arkhub-gateway-protocol.ts` | 744 | 网关帧协议解析（splitGatewayFrames/decodeProtobuf/MSG_NAMES…） |
| `arkhub-gateway-router.ts` | 380 | ArkhubFrameRouter 帧路由 + 类型（options/context/frame） |
| `arkhub-gateway-local.ts` | 269 | 本地网关应答器（私服模式空广场） |
| `handlers/{play,session,shop}.ts` | 2195 | 网关帧逻辑层（依赖 `@game/modules/activities/arkhub/*`） |

依赖链：`protocol ← codec ← router ← local ← handlers`；`gateway.ts` 依赖 `protocol` 与 `@capture/capture-manager`（ops）。
活动模块侧 `logic.ts` 动态 import `@ops/proxy/arkhub-gateway-local`（isArkhubLocalGatewayActive/getArkhubLocalGatewayPort）。

### 目标

1. **8 文件全部迁入** `arkhub` 模块 `gateway/` 子目录（含 TCP 转发器与本地应答器——它们是活动特性宿主）；
2. **capture-manager 依赖抽象为注入**：`gateway.ts` 不再 import ops，抓包记录提交改为 server.ts 注入回调（game 模块零 ops 依赖）；
3. **ops 侧统一走 public.ts**：新建 `arkhub/public.ts` 聚合网关对外符号，forwarder/transform/admin/server.ts/scripts 改走 public；
4. **精简重命名**：去 `arkhub-gateway-` 前缀（模块内冗余）。

## 2. 目标文件结构

```
app/game/modules/activities/arkhub/
  gateway/
    gateway.ts      # ← arkhub-gateway.ts（TCP 转发器 + enterHall 适配；capture 注入化）
    codec.ts        # ← arkhub-gateway-codec.ts
    protocol.ts     # ← arkhub-gateway-protocol.ts
    router.ts       # ← arkhub-gateway-router.ts
    local.ts        # ← arkhub-gateway-local.ts（本地网关应答器）
    handlers/
      play.ts       # ← handlers/play.ts
      session.ts    # ← handlers/session.ts
      shop.ts       # ← handlers/shop.ts
  public.ts         # 新建：模块出口（仅网关符号 + 协议工具，不聚合活动业务）
  arkhub.ts / arkdex.ts / arkpixel.ts / logic.ts / router.ts   # 不动
```

- 用 `git mv` 保留历史；文件名精简 + 相对导入改前缀（`./arkhub-gateway-protocol` → `./protocol` 等）。
- 活动业务符号（arkhubOnDuelSettle/arkdex 等）**不**入本次 public.ts——server.ts 顶部既有 import 不动，避免改动面膨胀（后续单独收敛）。

## 3. capture-manager 注入设计（gateway/gateway.ts）

现状 `gateway.ts` 中 captureManager 仅 2 处使用（连接关闭时提交抓包记录）：

```ts
if (captureManager.isReady()) {
  await captureManager.commitRecord(connectionId, { ts, path, source, direction, status, latencyMs, reqSize, resSize, note }, dir, { targetAddr, clientAddr, upBytes, downBytes, reason });
}
```

改造为注入回调（gateway.ts 内定义结构类型，与 `@ops/capture/capture-manager` 的 `CaptureRecordInput` 字段结构化兼容，不 import ops）：

```ts
/** 网关抓包记录提交回调（server.ts 注入 captureManager；缺省 no-op——文件仍落盘，仅不索引） */
export interface GatewayRecordSink {
  isReady(): boolean;
  commitRecord(
    rid: string,
    input: {
      ts: number; path: string; source: string; direction: string;
      status: number | null; latencyMs: number; reqSize: number; resSize: number; note: string;
    },
    dir: string,
    extraMeta?: Record<string, unknown>,
  ): Promise<unknown>;
}
let recordSink: GatewayRecordSink | null = null;
export function setGatewayRecordSink(sink: GatewayRecordSink | null): void { recordSink = sink; }
```

连接关闭处改为 `recordSink?.isReady() && (await recordSink.commitRecord(...))`（同 try/catch 语义：失败不影响抓包文件）。server.ts capture 分支接线 `setGatewayRecordSink(captureManager)`。

## 4. public.ts 导出清单（模块出口）

```ts
// gateway（TCP 转发器 + enterHall 适配）
export {
  startArkhubGatewayProxy, ArkhubGatewayProxyOptions, ArkhubGatewayProxyResult,
  updateGatewayTarget, getGatewayTarget, adaptArkhubEnterHallResponse, isArkhubEnterHall,
  ArkhubGatewayInfo, setGatewayRecordSink, GatewayRecordSink,
  OFFICIAL_ARKHUB_GATEWAY_HOST, OFFICIAL_ARKHUB_GATEWAY_PORT, OFFICIAL_ARKHUB_GATEWAY_CANARY_HOST,
} from "./gateway/gateway";
// local（本地网关应答器）
export {
  startArkhubLocalGateway, isArkhubLocalGatewayActive, setArkhubLocalGatewayActive,
  getArkhubLocalGatewayPort, ArkhubLocalGatewayOptions, ArkdexDocsData,
} from "./gateway/local";
// router（帧路由 + 类型）
export { GW_CODE_OK, ArkhubFrameRouter, ArkhubFrameHandler, ArkhubGatewayFrame, ArkhubGatewayHandlerContext, ArkhubGatewayConnectionState } from "./gateway/router";
// protocol（帧协议解析——admin/scripts 消费）
export * from "./gateway/protocol";
// codec（帧编解码）
export * from "./gateway/codec";
```

## 5. 消费方改接线

| 消费方 | 现状 | 改后 |
|---|---|---|
| `app/server.ts` capture 分支 | `@ops/proxy/arkhub-gateway` startArkhubGatewayProxy | public 导入 + `setGatewayRecordSink(captureManager)` |
| `app/server.ts` 私服分支 | `@ops/proxy/arkhub-gateway-local` startArkhubLocalGateway | public 导入 |
| `app/game/.../arkhub/logic.ts` | 动态 import `@ops/proxy/arkhub-gateway-local` | 改 `./gateway/local`（模块内） |
| `app/ops/proxy/forwarder.ts` | `./arkhub-gateway` type ArkhubGatewayInfo | `@game/modules/activities/arkhub`（public） |
| `app/ops/proxy/transform.ts` | `./arkhub-gateway` updateGatewayTarget/adaptArkhubEnterHallResponse/ArkhubGatewayInfo | public 导入 |
| `app/ops/admin/arkhub-pets.ts` | `../proxy/arkhub-gateway-protocol` | public 导入 |
| `scripts/dump-gateway-dict.ts` / `parse-arkhub-gateway.ts` | `@ops/proxy/arkhub-gateway-protocol` | public 导入 |

依赖方向检查：ops → game public（合法）；game 内部（logic → gateway/local、handlers → arkhub.ts/arkdex.ts）同模块；gateway.ts 仅 @utils/logger + 自身 protocol——零 ops 依赖。无循环。

## 6. 测试迁移

按 `tests/unit/**` 镜像 `app/` 约定：

| 现状 | 迁移后 |
|---|---|
| `tests/unit/proxy/arkhub-gateway.test.ts` | `tests/unit/game/modules/activities/arkhub/gateway/gateway.test.ts`（TCP 转发器） |
| `tests/unit/proxy/arkhub-gateway-local.test.ts` | `.../gateway/local.test.ts` |
| `tests/unit/proxy/arkhub-gateway-protocol.test.ts` | `.../gateway/protocol.test.ts` |
| `tests/unit/proxy/arkhub-gateway-router.test.ts` | `.../gateway/router.test.ts` |
| `tests/unit/proxy/forwarder.test.ts` / `transform.test.ts` | getGatewayTarget 等导入改 public（文件留 proxy 位） |
| `tests/unit/admin/arkhub-pets.test.ts` | protocol 导入改 public |

新增测试：capture 注入（`setGatewayRecordSink` 注入 mock sink → 连接关闭后回调被调用；未注入时 no-op 不抛）。

## 7. 实施步骤

1. `git mv` 搬迁 8 文件到 `gateway/` + `handlers/`，修正内部相对导入（codec/protocol/router/local/handlers 互相 + logic.ts）——纯机械；
2. capture 注入改造（gateway.ts：GatewayRecordSink/setGatewayRecordSink + 连接关闭处替换）——TDD：先写注入用例；
3. 新建 `public.ts` 聚合导出；
4. 消费方改接线（server.ts/forwarder/transform/admin/scripts）；
5. 测试迁移 + 全量回归（tsc + proxy/architecture/admin/game 相关套件 + --capture 冒烟）。

## 8. 验证标准

1. `pnpm exec tsc --noEmit` 通过；
2. 迁移后测试全绿（gateway 4 件套 + forwarder/transform + admin 相关 + module-boundary 守卫）；
3. `grep -rn "ops/proxy/arkhub" app/ tests/ scripts/` 无残留（除 docs）；
4. `--capture` 冒烟：proxy 管线 + 网关转发器 + 注入 sink 正常起服。

## 9. 明确不在范围（YAGNI）

- 活动业务符号（arkhubOnDuelSettle/arkdex/arkpixel 导出）不收敛进 public.ts（后续单独迭代）；
- handlers 与 arkhub.ts/arkdex.ts 的**代码合并**（handler 是协议帧逻辑、业务在活动模块，职责已分，不合并）；
- 网关协议文档（docs/arkhub-gateway-protocol.md）路径不改（仅注释引用）。
