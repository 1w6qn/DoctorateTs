# 设计模式分析（2026-09-11）

对 `app/` 全域做的一次模式勘察。结论按「模式 → 落点 → 它解决的真实约束」组织，
最后单列一节**模式纪律的破口**——那部分比罗列模式更有行动价值。

规模基线：`app/game/modules/` 共 42 个模块目录（31 个 `routes.ts` / 5 个 `handler.ts` /
6 个 `public.ts`），组合根装配 25 个子管理器。

---

## 1. 模式总览

| 模式 | 落点 | 解决的真实约束 |
|---|---|---|
| 组合根 Composition Root | `kernel/PlayerDataManager.ts` | 玩家数据是一棵 25 节点的对象图，必须单点组装 |
| 工厂 Factory | `kernel/player-composition.ts` | 构造顺序 = 事件订阅顺序 = 派发顺序，顺序本身是契约 |
| 两阶段提交 / 工作单元 | `kernel/PlayerStatus.ts` | 变更既要立刻生效，又要能算出增量下发给客户端 |
| 观察者 Observer（类型安全） | `kernel/events/{core,runtime}.ts` | 42 个模块不能互相 import，只能靠事件解耦 |
| 策略 Strategy | `modules/gacha/gacha.ts`、`dialect.ts`、`auth-strategy.ts` | 概率曲线 / SQL 方言 / 认证模式三处「同接口多实现」 |
| 适配器 Adapter | `core/db/drivers/*`、`core/db/schema.ts` | SQLite / MySQL / PostgreSQL 三后端同构 |
| 注册表 + 模板方法 | `modules/building/buff-tpl.ts` + `buffs/index.ts` | 基建技能效果无限扩张，引擎不能跟着改 |
| 门面 Facade | `modules/<mod>/public.ts` | 跨模块依赖必须收窄到最小面 |
| 建造者 Builder | `kernel/inventory-pipeline.ts` | 一次请求内多笔物品增减要原子成批 |
| 中间件链 / 装饰器式分离 | `game/app.ts`、`kernel/http/validate-body.ts` | 认证、锁、校验、错误映射与业务正交 |
| 单例 Singleton | `captureManager` / `logService` / `assetRegistry` / `pluginConfigService` / `accountManager` / `globalEventBus` | 跨请求共享有状态设施 |
| 端口注入 Ports & Adapters | `kernel/excel-port.ts`、`http/auth-strategy.ts#AuthAccountPort` | 全局单例导致测试只能 `vi.mock` 模块打桩 |
| 棘轮 Ratchet（架构即测试） | `tests/unit/architecture/*.test.ts`（9 个） | 约定写在文档里没人守，写成测试才会红 |

---

## 2. 分层与边界

三层 `core/` → `game/` → `ops/`，依赖**单向向内**：`ops` 可用 `game`+`core`，`game` 只能用 `core`，
`core` 禁止反向 import。

这套边界不是靠 code review 维持的，靠 **9 个架构守卫测试**（`tests/unit/architecture/`）：

- `module-boundary.test.ts` — 纯函数静态扫描 import 图谱，强制 R1（core 不依赖 game/ops）、
  R2（kernel/excel 不依赖 modules）、R3（跨模块只准 import 对方 `public.ts`）。
  存量越界逐条登记在 `EXEMPTIONS` 并附 `reason`，新增越界直接红灯。
- `composition-order.test.ts` — 源码扫描锁定 `player-composition.ts` 的 `new` 顺序。
- `excel-singleton-ratchet.test.ts` / `type-debt-ratchet.test.ts` — 棘轮：既有文件的
  `any`/`unknown`/`object` 计数与 excel 单例直连次数**只允许下降**，基线在 `*-baseline.json`。
- `schema-first-guard.test.ts` — 所有 POST 路由必须经 `validateBody`。
- `file-size-guard.test.ts` — 单文件 ≤ 1500 行。`errors-guard.test.ts` — 业务校验必须抛
  `GameError` 子类。另有 `decoupling.test.ts`。

> 这是本项目最值得学的一处：**把架构约定编译成会红的测试**。文档会腐烂，测试不会。

---

## 3. 状态层：两阶段提交 + 补丁聚合

`PlayerStatus.update(recipe)` 用 mutative 的 `create(base, { enablePatches: true })`
拿到 `[draft, finish]`，recipe 跑完后 `finish()` 一次性提交并产出 patches。

三个细节值得单独指出：

1. **嵌套 draft 复用**（`PlayerStatus.ts:132`）。事件处理器在 recipe 内 `await emit` 时，
   下游 manager 会再次调 `update()`。若内层新建 draft，`finish()` 会先按旧 base 整体覆盖
   `_playerdata`，外层 `finish()` 再按更旧的 base 覆盖回去 → **嵌套变更从存档丢失，但 delta 里
   有补丁**，表现为「客户端看到奖励、下次同步消失」。复用同一 draft 后嵌套变更随外层一并提交。
2. **补丁正序展开**（`PlayerStatus.ts:63` 注释）。补丁必须正序拼，倒序会让同一路径的旧值后写
   覆盖新值（十连后 `cnt` 收到 1 而非 10）。
3. **`forcePatch` 逃逸口**（`PlayerStatus.ts:117`）。Immer 对未变化的值不产补丁，但业务有时
   必须让某字段进 delta（如 `building.event` 用于客户端调度下次 sync）。

`delta` getter 语义是**一次性**的：读它 = 算增量 + 清 `_changes` + 触发 `save`。
`AGENTS.md` 明写「Never read `player.delta` twice in one request」——这是把隐式副作用
写进契约的典型，代价是调用方必须懂这个规矩。

`PlayerDataManager` 本身退化为组合根：25 个子模块挂 `modules`，平铺字段都是转发 getter
（`get dungeon() { return this.modules.dungeon }`）。**注意：类注释仍写「全部 23 个子模块」，
实际 25 个，注释已漂移。**

---

## 4. 事件总线：类型安全 Observer

契约在 `kernel/events/core.ts` 的 `EventMap`，形如
`"char:get": [string, {...}, ((res) => void)?]`；运行层 `EventBus extends TypedEventEmitter
extends Emittery<EventMap>`。事件名与载荷类型由编译期约束，`emit` 写错参数直接编译失败。

`EventBus` 在 Emittery 上叠了三样东西：

- **优先级派发**：覆写 `on/off/emit`，按 HIGH → MEDIUM → LOW 顺序 await，同级按注册序。
- **中间件**：`before` 返回 `false` 可拦截派发（`after` 做收尾）。
- **验证器**：`addValidator`，配 `strictValidation` 开关决定拦截还是仅告警。

⚠️ **潜在陷阱**：`emit` 末尾调 `Emittery.prototype.emit.call(this, eventName, args[0])`
**只透传第一个参数**。走 `on()` 注册的监听器都进 `priorityListeners` 分支，参数完整；
但若有代码绕过 `on` 直接用 Emittery 原生订阅路径，多参数事件会拿到残缺载荷。
当前 `on/off/once` 全被覆写，所以尚未暴露——属潜伏坑，建议加注释或断言固化。

---

## 5. 数据层：策略 + 适配器 + 工厂

`core/db/` 的收敛方式很清楚：

- `types.ts` 定义 `SqlDatabase` 契约（`prepare`/`exec`/`transaction`，**全异步**）。
- `drivers/{sqlite,mysql,postgres}.ts` 三个适配器。`mysql2`/`pg` 是 optionalDependencies，
  **禁止顶层 import**，由 `drivers/load.ts` 运行时动态加载。
- `dialect.ts` 把四类方言差异收成纯函数（零 IO）：`insertIgnoreSql` / `insertReplaceSql` /
  `convertPlaceholders`（`?` → `$n`，且会跳过字符串字面量与行注释）/ `normalizeParams` / `toCount`。
  仓储层因此只写 `?` 占位符和公共 SQL，**看不见方言分支**。
- `database.ts` 是工厂 + 单例：`createDatabase(options)` 按 backend 分派；`openDatabase()`
  维护全局单例，并用 `_opening` promise 把并发建连收敛到一次。
- `schema.ts` 的 `TABLES` 是唯一表结构声明，DDL 由 `buildSchemaSql(backend)` 生成。

> 这层是「把变化隔离到一个纯函数文件」的教科书案例——加第四种后端只需扩 `dialect.ts`
> 三个 `switch` 各加一个 case。

---

## 6. 扩展点：策略表、注册表、模板方法

三种「加需求不改引擎」的写法并存，按场景选：

**a) 纯函数策略**（`modules/gacha/gacha.ts:52`）
```ts
export function resolveGachaRank(params: { per6Base; beforeNonHitCnt; nextCnt; maxCnt?; ranks; weights; rand? }): number
```
概率计算从 `GachaManager._getRarityRank` 拆出，`rand` 可注入 → 可单测。
注释里记着一次真实修复：官方曲线是「连续 50 抽未出 6★ 后，第 51 抽起每抽 +2%」，
原实现用 `(cnt-50)*0.02` 让整条曲线晚一抽。

**b) 模板方法 + 注册表**（`modules/building/buff-tpl.ts` + `buffs/index.ts:26`）
```ts
abstract class BaseBuffTpl { abstract kind: string; static matches(buff: any): boolean }
const TPLS = [ControlGlobalTpl, RoomSpeedTpl, DormRecoveryTpl, MoodCostTpl];
export function buffTplFor(buff) { for (const T of TPLS) if (T.matches(buff)) return new T(buff); return null; }
```
新增基建技能 = 新建模板类 + 加入 `TPLS`，引擎调用点不动；未命中回退既有引擎。
这是**注册表 + 多态分发**，不是简单的策略表。

**c) 查表分发**（`excel/building_excel.ts:164`）`Record<string, any>` 按 `roomType` 直查。

**d) 认证策略**（`kernel/http/auth-strategy.ts`）——最规范的一处：
`AuthStrategy` 接口 + `SingleAccountStrategy` / `RealAccountStrategy` 两实现 +
`createAuthStrategy(cfg)` 工厂是**唯一**读 `config.authMode` 做决策的地方。
`RealAccountStrategy` 的账号能力收在 `AuthAccountPort` 端口里（只 2 个方法），
缺省绑 `accountManager` 单例、可注入替身 → 测试不必 `vi.mock` 模块。

---

## 7. 请求管线

`app.ts` 的装配顺序是刻意的：
`httpContext` → `bodyParser.json()` → `authMiddleware`（策略解析 uid，注入 player）→
`responseSchemaMiddleware`（骨架校验，失败只告警）→ **每 uid 互斥锁** → 路由 → `gameErrorHandler`。

那把锁值得注意：`acquireLock(player.uid)` 挂在 `res.on("finish"/"close")`，
让同一账号的请求串行——直接服务于 `update()` 的「补丁不丢」目标。
`/admin` 路径显式豁免，否则 single 模式下外层 admin 持锁、内层自代理等同一把锁会死锁。

路由注册是**声明式表 + 懒加载**（`game/routes.ts`）：`routes: RouteRegistration[]` 按序迭代，
`module` 字段是字符串路径，运行期 `import()` 才加载 42 个模块。数组顺序即挂载顺序，
连客户端别名 URL 重写（`crisisV2Rewrite` / `sandboxPermRewrite`）都表达成表里的 `rewrite` 字段。

---

## 8. 模式纪律的破口（重点）

以下不是「模式不够漂亮」，是**约定与代码已经脱节**，会误导后来者。

### 8.1 物品管道约定形同虚设

`AGENTS.md` 明确写：「物品增减统一经 `player.gainItem.setTarget(...).use()/handle()` 管道
（`inventory-pipeline.ts`），**不直发** `items:get`/`items:use` 事件」。

实际：`_trigger.emit("items:get"|"items:use")` 直发**约 84 处、跨 29 个文件**
（`battle.ts` 8 处、`shop/logic/misc.ts` 10 处、`mission/logic.ts` 4 处、
`activities/milestone/logic.ts` 7 处、`depot/routes.ts` 6 处……）。
`GainItemPipeline` 自身只有 3 处 emit（它就是管道本体），`inventory.ts` 的 3 处是管道的下游订阅者——
这两类不算违规，其余都是。管道被真实使用的文件寥寥。

**根因**：这条约定**没有守卫测试**。上面 9 个守卫覆盖了边界/顺序/类型/契约，
唯独漏了这一条 —— 于是它停留在文档里。

### 8.2 路由层长出了业务（`modules/depot/routes.ts`）

落位规则是「薄路由 + 模块内 manager」，但该文件 546 行里塞了：

- `hasVoucherStock()` 等业务校验函数（:63）；
- `class VoucherDataManager` + `static _voucherTable` 静态可变缓存（:113）——
  隐式全局状态，跨测试会串；
- 直接用 `((player as any)?._playerdata?.consumable as any)` 穿透访问私有状态（:69）；
- 在路由里直接 emit 物品事件而非委派 manager。

文件头的修复注释（2026-09-09）显示这里连出过**凭空复制凭证**（`count=-5` 走反向入账分支）、
**零成本刷奖励**（实例不存在时消耗被静默跳过但仍发放）等漏洞。这些正是
「业务逻辑写在薄路由里、绕过统一管道」直接付出的代价。

### 8.3 其他

- `PlayerDataManager` 类注释「23 个子模块」与实际 25 个不符（注释漂移）。
- 单例面偏大，且存在**默认参数绑单例**的写法（`RealAccountStrategy(accounts = accountManager)`）。
  可注入是好设计，但默认值让「谁在用全局态」变得不显眼。
  `EXEMPTIONS` 里已登记 `core/auth` → `AccountManager`、`core/config/prod` → `ops/assets` 等
  多条 `core → game/ops` 反向依赖为技术上债——**R1 规则目前是靠豁免表维持的**。
- `PlayerStatus.delta` 里 `this._changes.reduce((pre, acc) => pre.concat(acc), [])`
  是 O(n²) 拼接，请求批次多时有优化空间（小问题，不影响正确性）。

---

## 9. 取向总结

这个代码库的模式选择有一个统一倾向：**把「变化」和「约定」都变成显式的、可执行的东西**。

- 变化 → 纯函数策略 / 适配器 / 注册表（`dialect.ts`、`resolveGachaRank`、`buffs/index.ts`）。
  加东西只加文件，不动引擎。
- 约定 → 架构守卫测试（9 个），顺序、边界、契约、类型债全部量化成棘轮基线。
- 跨模块协作 → 类型安全的 `EventMap` 观察者 + `public.ts` 门面，双层约束。

真正的短板也一致地出在同一处：**凡是没被守卫测试覆盖的约定，最终都会失效**（§8.1）。
物品管道这条约定就是活样本。

如果只做一件事：给 `items:get|items:use` 直发加一条棘轮守卫（基线固化现有 84 处，
只减不增），与 `excel-singleton-ratchet` 同款。这比再写一份文档有效得多。

---

## 附：模式 → 文件速查

| 想改什么 | 去哪 |
|---|---|
| 状态提交 / 增量语义 | `app/game/kernel/PlayerStatus.ts` |
| 加子模块 / 改构造顺序 | `app/game/kernel/player-composition.ts` |
| 加事件 | `app/game/kernel/events/core.ts`（契约）+ 各 manager 构造器订阅 |
| 加 SQL 后端 | `app/core/db/dialect.ts` + `drivers/` + `schema.ts#TABLES` |
| 加基建技能 | `app/game/modules/building/buffs/` 新建模板类 + 加入 `TPLS` |
| 加抽卡规则 | `app/game/modules/gacha/gacha.ts#resolveGachaRank` + gacha 策略表 |
| 加认证模式 | `app/game/kernel/http/auth-strategy.ts` 新增实现 + 工厂映射 |
| 加路由 / 客户端别名 | `app/game/routes.ts` 加一条 `RouteRegistration` |
| 新增游戏配置表 | `app/game/kernel/excel-port.ts` 显式加成员（编译期棘轮） |
| 加架构约束 | `tests/unit/architecture/` 新守卫 + 基线 json |
