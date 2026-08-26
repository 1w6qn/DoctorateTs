# app/game/domain — 领域层

DDD 分层的**领域层**：只允许存放纯类型与纯函数规则，零 IO、零副作用。

## 依赖规则

- ✅ 允许依赖：`@excel/*`（启动期一次性加载的只读配置表，视为领域规则参数表）、`@utils/*` 纯工具、同层 domain 文件
- ❌ 禁止依赖：`service/` 下任何模块（`import type` 类型引用除外，无运行时耦合）、根基础设施（request-context/routes/app/resp-schema/auth-strategy）、express/httpContext 等框架设施
- ❌ 禁止 IO：读文件/落盘/网络请求一律归 `service/`

## 目录构成

| 目录/文件 | 内容 |
|---|---|
| `playerdata.ts` + 8 领域模型 | 纯类型（生成模型 re-export、character/battle/gacha/mail/social/user/activity/rlv2） |
| `events/` | 事件契约（EventMap 组合，纯类型；运行时总线在 service/manager/events.ts） |
| `contracts/` | 协议契约（对外 DTO + zod schema + validate-body，零行为） |
| `building/` | 9 个纯函数规则引擎（buff/mood/clue-speed/mastery/unlocks/dorm-special/hire-contacts/trade-orders/special） |
| `rlv2/` | theme-rules（纯规则）+ data/blackstream-data（纯数据） |
| `util/` | 纯函数工具（char-skills/stage-unlock/purchase-record/maxout） |
| `data/` | 纯数据（vhalfidle） |

边界由 `tests/unit/architecture/decoupling.test.ts` 守卫固化（domain 不得依赖 service）。
