# 类型系统审计与收敛策略

> 生成物守卫：`tests/unit/architecture/type-debt-ratchet.test.ts`（棘轮，只减不增）
> 度量 CLI：`pnpm run type:debt` / `pnpm run type:debt -- --write`
> 扫描器：`scripts/lib/type-debt-scan.ts`（守卫与 CLI 共用，口径一致）
> **扫描范围（2026-09-11 起）**：`app/` + `scripts/` + `tests/` + `hook/` + 根 `index.ts`
> （`SCAN_DIRS`）；范围扩容用 `--write --expand-scope`（只放行新文件，既有文件仍禁止上升）。

## 1. 审计结论（证据）

审计范围 `app/**/*.ts` + `index.ts`（403 文件 / 13.8 万行），以「裸类型关键字」为口径
（剥离注释、字符串、模板与正则字面量后统计；排除成员访问，故 `z.object({...})` 不计）：

| 阶段 | any | unknown | object | 合计 |
| --- | --- | --- | --- | --- |
| 初始基线（228 文件） | 1520 | 469 | 236 | 2225 |
| 修复后（226 文件） | 1518 | 469 | **73** | **2060** |

**核心结论：`object` 债有 69% 来自两个生成文件，根因在生成器而非业务代码。**

### 1.1 全范围现状（2026-09-11，扫描范围扩容后）

| 范围 | any | unknown | object | 是否在 tsc 覆盖内 |
| --- | --- | --- | --- | --- |
| `app/**` + `index.ts` | 1516 | 468 | 72 | ✅ `tsconfig.json` |
| `tests/**` | 5511 | 62 | 15 | ❌（纳入后暴露 1260 个既有错误） |
| `scripts/**` | 104 | 34 | 14 | ❌（纳入后暴露 19 个既有错误） |
| `hook/` | 0 | 1 | 0 | ❌（`hook/main.ts` 由 frida-compile 构建） |
| **合计** | **7131** | **565** | **101** | — |

`any` 的形态分布（app）：`: any` 648、`as any` 683、`any[]` 80、`Record<string, any>` 66、
`z.any()` 122（20 文件）、`Promise<any>` 13。测试侧 `any` 主要来自无类型的测试桩
（`mockPlayerData` 的 `gainItem/delta/_trigger/excel`）导致的调用点 `as any`。

**收敛路线（2026-09-11 批准）**：`any` 一律清零（app → scripts → tests 分阶段），
每条 `any` 的归宿只有四种——① 精确手写类型；② 生成器覆盖表登记 + 重生成；③ I/O 边界
改 `unknown` + 就地收窄；④ 路由契约用 `z.json()`/精确 schema。

### 1.2 终局结果（2026-09-12，全仓 `any` = 0）

| 范围 | any 起始 → 终局 | unknown | object | tsc 配置 |
| --- | --- | --- | --- | --- |
| `app/**` + `index.ts` | 1516 → **0** | 376 | 26 | ✅ `tsconfig.json`（0 错误） |
| `tests/**` | 5511 → **0** | 26 | 0 | ✅ `tsconfig.tests.json`（0 错误） |
| `scripts/**` | 104 → **0** | 10 | 0 | ✅ `tsconfig.scripts.json`（0 错误） |
| `hook/` | 0 → **0** | 1 | 0 | ❌（`hook/main.ts` 由 frida-compile 构建） |
| **合计** | **7131 → 0** | **413** | **26** | — |

`any` 已由守卫固化：`tests/unit/architecture/type-debt-ratchet.test.ts` 的
「全仓 `any === 0`」用例（`totalOf(scanTypeDebt(REPO_ROOT)).any === 0`）在任何位置
重新引入 `any` 时红灯。`unknown`/`object` 尚未清零，仍走逐文件棘轮（只减不增 +
新文件必须零模糊类型）。

**扫描器口径修正（假阳性）**：`scripts/lib/type-debt-scan.ts` 的裸关键字正则
`(?<![\w$.])kw\b(?!\s*:)` 中，`(?!\s*:)` 排除**属性名**位置（`{ any: 0 }`、
`interface X { object: string }` 不是类型债；负样本见守卫的
「负样本自证：注释、字符串、正则中的关键字不计为类型债」用例）。此前扫描器自身的
`const any = …` 与简写属性 `return { any, unknown, object }` 会被自计（属假阳性），
现已把局部变量改名 `cntAny`/`cntUnknown`/`cntObject`、返回语句写显式属性名，
**公开键名 `TypeDebtCounts.any/unknown/object` 保持不变**（基线与消费点依赖）。
遗留边界：简写属性 `{ any }` 仍会被计入（无 `:` 可判），故扫描器自身及新代码避免
用这三个词做局部标识符。

**集中 suppression 政策**：全仓 `any` 清零后，`as any` / `as unknown as` 一律不再允许
直接出现在调用点。仅存的两处「替身 → 契约」硬边界集中在 `tests/helpers`：
`asPlayerManager`（`PlayerDataManager` 含私有实现，鸭子替身不可结构兼容）与
`asExcelPort`（`ExcelData` 是 32 个成员全必填的 `Pick<Excel, …>`）；两者均带 JSDoc 说明
断言方向与运行期同一对象引用，禁止用它掩盖字段名/字段类型不匹配（后者必须就地修夹具）。
`asChildModules`（子模块注入视图）方向合法，**无需** suppression。

| 文件 | 初始 object |
| --- | --- |
| `app/game/excel/types_excel_gen.ts` | 86 |
| `app/game/excel/types-playerdata.ts` | 77 |
| 其余 226 个文件合计 | 73 |

`any` 债则相反：高度集中在少数业务文件（medal 事件分发、roguelike、admin 运维层），
属「就地逃生」而非生成器问题，需要逐个按领域建模。

## 2. 策略：三类表述的处置

### 2.1 `any` —— 一律禁止

`any` 关闭类型检查且会沿赋值链**传染**，是唯一没有任何合理用途的表述。
唯一历史豁免是生成的 `[key: string]: any` 索引签名（已改为 `JsonValue`）。

### 2.2 `object` —— 一律禁止，改为可检查的具体类型

TS 的 `object` 关键字**既不可索引也不可取属性**，调用方唯一出路是 `as any`——
它不表达「未知」而表达「不可用」，是把类型洞藏在字段声明里的形式。本仓库
`object` 的真实语义有两类，分别替换：

1. **形状可知** → 直接写精确类型（首选）。如 `PlayerAvatar.avatar_icon` 改为
   `{ [key: string]: { ts: number; src: string } }`。
2. **确实未建模的服务端 payload** → 用严格 JSON 域类型替代（见 §3）。

### 2.3 `unknown` —— 不禁止，但必须「就地收窄」

`unknown` 在**不可信输入的边界**上是唯一正确的类型（`catch (e: unknown)`、
未校验的外部 JSON），把它换成 `any` 是**倒退**。构造性要求：

- 允许：I/O 边界、`catch`、三方库回调。
- 要求：`unknown` 必须在同一个小函数内被收窄（`typeof` / zod `safeParse` / 类型守卫）
  后才可外流；**不允许**把 `unknown` 存进领域模型或跨模块传递。
- 已有约定：POST 路由必须经 `validateBody(zodSchema)`
  （守卫 `tests/unit/architecture/schema-first-guard.test.ts`）——这就是「边界收窄」的范式。

> 棘轮把 `unknown` 一并计数，是为了**驱动逐处复核**，而不是把 469 处清零。
> 复核结论若为「边界上的正确用法」，应在 `SERVER_*_ADAPT` 或代码注释中说明，
> 而不是把它改成 `any`。

## 3. 根因修复：生成器不再产出 `object`

### 3.1 哨兵归一化

`scripts/playerdata-parser.ts#CSHARP_TO_TS_TYPE_MAP` 与两张 override 表
（`SERVER_ADD_FIELDS` / `EXCEL_FIELD_TYPES` 等）里的 `"object"` 是**哨兵**，
表示「C# 类型无对应具名结构」。生成器现在在输出阶段统一归一化
（`scripts/types-builder.ts#normalizeJsonType`），按域分流：

| 域 | 归一化目标 | 位置 | 理由 |
| --- | --- | --- | --- |
| excel 表数据（只读） | `JsonValue`（递归联合） | `app/game/excel/json-value.ts` | 表数据层次深，递归联合可精确表达 |
| 玩家存档 | `ServerPayload`（**非递归**，两层） | 同上 | `Draft<PlayerDataModel>` 无法承受递归类型 |

### 3.2 为什么玩家存档必须用非递归类型

mutative 的 `Draft<T>` 会**递归映射** T 的每个属性。把递归类型放进
`PlayerDataModel` 会让 `Draft` 无限展开，触发
`TS2589: Type instantiation is excessively deep and possibly infinite`——
实测 4 处（inventory / unlockActivity / construction / misc）当场合不上。

`ServerPayload` 显式展开两层（标量 / 标量数组 / 一层嵌套对象），仍是严格类型，
但保证 `Draft` 可终结。**新增玩家存档字段时不要用 `JsonValue`。**

### 3.3 服务端活动字典的精确化配方（2026-09-11 验证）

`PlayerActivity` 是服务端独有的形状：`{ [类型key]: { [actId]: 活动数据 } }`
（客户端模型是 60 个分列表字段），此前整接口覆盖为 `{ [typeKey: string]: { [actId: string]: object } }`
→ 归一成两层 `ServerPayload`，**任何第三层访问都要 `as any`**（全仓 `draft.activity as any` 51 处、
`_playerdata.activity as any` 6 处的主要根因）。

配方（登记在 `scripts/playerdata-server-adapt.ts` 的 `SERVER_OVERRIDE_FIELDS.PlayerActivity["[server]"]`）：

1. **只给服务端真正读写的类型键**写具名成员，其余键继续走兜底索引签名；
2. 具名成员**一律可选（`?:`）**——索引签名语义下键不保证存在（存档惰性建键），
   写必填会让 `draft.activity = {}` 这类赋值直接报错，访问侧也必须用 `?.`；
3. 兜底索引签名必须用**交叉类型**挂载：具名成员与索引签名写在同一个对象字面量里会
   触发 **TS2411**（具名值类型不可赋给索引签名值类型）；交叉写法绕开该检查，
   且**不会**让 `Draft` 深度爆炸（已实测：交叉写法 + `--playerdata` 重生成后
   `tsc -p tsconfig.json` 全绿）；
4. 成员内部**保持非递归**（禁止 `JsonValue`，兜底类型用 `ServerPayload`）；
5. 重生成：`pnpm run generate:playerdata`（本仓等价 `tsx scripts/generate-types.ts --playerdata`），
   然后删掉访问点的 cast；生成文件不得手改。

已登记（首例，2026-09-11）：`BOSS_RUSH`（`milestone` / `relic` / `bestWaveDic`）。

### 3.4 顺带修出的真实缺陷

- **`StoryReviewTable` 声明为单行类型**（`app/game/excel/excel.ts`）：
  该表实际是 `{ [groupId]: StoryReviewGroupClientData }`（已用
  `data/excel/story_review_table.json` 核对），原先误标为单行对象，使
  `StoryReviewTable[groupId]` 落到索引签名上返回 `any`，`?.rewards` 完全失去检查。
  已改为字典类型。
- **`[key: string]: any` 索引签名**：`CharacterData` / `StoryReviewGroupClientData`
  在 interface 上挂索引签名与具名字段冲突（TS2411）。改为交叉类型
  `{ ...具名字段 } & { [key: string]: JsonValue }`，既保留精确字段又保留字典访问。
- **索引签名掩盖具名字段**：`StoryReviewGroupClientData.rewards` 曾被索引签名吞掉。

## 4. 剩余债务与后续专项轮

`any` 已归零（§1.2），本节的「Top 违规文件」清单随之作废。剩余工作分两类：

### 4.1 `unknown` / `object` 存量（继续棘轮）

按「权重 = unknown×1 + object×2」的现存量（实测）：`app` unknown 376 / object 26、
`tests` unknown 26 / object 0、`scripts` unknown 10 / object 0、`hook` unknown 1。
集中在：`activities/shared/activity.ts` 19、`activities/arkhub/gateway/protocol.ts` 14、
`battle.ts` 9、`building/models.ts` 7、`user/routes.ts` 6 等——多为可信边界（zod/I-O）
或未建模 JSON 域。**不设清零期限**：`unknown` 在不信任输入边界是正确类型，只在
「确实已收窄」时才下降；`object` 按 §2.2 两条替换（精确类型 / 严格 JSON 域）。

### 4.2 两个专项轮（不混入 any 清零提交，单独立项）

- **轮 A：生成器登记回收**——把「生成类型未覆盖服务端真值 → 测试只能就地收窄/局部视图」
  的登记缺口一次性补进 `scripts/playerdata-server-adapt.ts` / `excel-server-adapt.ts` 后重生成。
  清单见 `tmp/probe/PROGRESS.md` 台账 **#28**（PlayerGacha.classic、CampaignsV2State.missions、
  MissionPlayerDataGroup.confirmed、BattleStats.packedRuneDataList/idList、pinned、ItemBundle.type）
  与 **#32**（BattleData、RoguelikeStageEarn、Game.mode、OuterData.Record、Blackboard_DataPair、
  PlayerRoguelikePendingEvent、cursor.position、Buff.capsule、Troop.expeditionReturn、Inventory.trap、
  RecruitChar.instId、eventChoices.incidents、PlayerSkinShopData）。
- **轮 B：helpers 替身补全 + R1 配方复核**——补齐 `MockBattleManager.finish`（改可选）/
  `getActiveBattle`、`MockPlayerDataManager.modules/bossRush`；按 R1 配方（`SERVER_OVERRIDE_FIELDS.PlayerActivity`）
  具名登记三层活动子树（halfidle / act44 / act24 / bossrush）与 `PlayerCrisisSeason`，消除种子
  `Object.assign` 绕行与两层 `ServerPayload` 的类型不可达。

两轮的已知真实缺陷台账同见 `tmp/probe/PROGRESS.md`（#6~#32），修缺陷需「补测试 + 说明行为差异」。

## 5. 工作流

```bash
pnpm run type:debt                            # 报告总量 / delta / Top 违规文件
pnpm run type:debt -- --write                 # 刷新基线（棘轮只紧不松，上升即拒绝并退出 1）
pnpm run type:debt -- --write --expand-scope  # 扫描范围扩容时刷新（只放行新增文件）
pnpm exec vitest run tests/unit/architecture/type-debt-ratchet.test.ts
pnpm run typecheck                            # app + index（tsconfig.json）
pnpm run typecheck:scripts                    # app + index + scripts（tsconfig.scripts.json）
pnpm run typecheck:tests                      # app + index + tests（tsconfig.tests.json）
pnpm exec vitest run
```

三份 tsc 配置均为 0 错误；**注意增量模式**：`tsc` 的 `.tsbuildinfo` 会吞掉未变更文件的错误，
判「0 错误」时加 `--incremental false`（或先删 `.tsbuildinfo`），否则可能得到假绿。

修复一个文件后，该文件计数下降无需手工改基线；**清零后必须**从
`tests/unit/architecture/type-debt-baseline.json` 移除该条目（守卫会红灯提醒）。
禁止用 `--force` 放宽棘轮。
