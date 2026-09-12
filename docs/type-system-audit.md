# 类型系统审计与收敛策略

> 生成物守卫：`tests/unit/architecture/type-debt-ratchet.test.ts`（棘轮，只减不增）
> 度量 CLI：`pnpm run type:debt` / `pnpm run type:debt -- --write`
> 扫描器：`scripts/lib/type-debt-scan.ts`（守卫与 CLI 共用，口径一致）

## 1. 审计结论（证据）

审计范围 `app/**/*.ts` + `index.ts`（403 文件 / 13.8 万行），以「裸类型关键字」为口径
（剥离注释、字符串、模板与正则字面量后统计；排除成员访问，故 `z.object({...})` 不计）：

| 阶段 | any | unknown | object | 合计 |
| --- | --- | --- | --- | --- |
| 初始基线（228 文件） | 1520 | 469 | 236 | 2225 |
| 修复后（226 文件） | 1518 | 469 | **73** | **2060** |

**核心结论：`object` 债有 69% 来自两个生成文件，根因在生成器而非业务代码。**

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

### 3.3 顺带修出的真实缺陷

- **`StoryReviewTable` 声明为单行类型**（`app/game/excel/excel.ts`）：
  该表实际是 `{ [groupId]: StoryReviewGroupClientData }`（已用
  `data/excel/story_review_table.json` 核对），原先误标为单行对象，使
  `StoryReviewTable[groupId]` 落到索引签名上返回 `any`，`?.rewards` 完全失去检查。
  已改为字典类型。
- **`[key: string]: any` 索引签名**：`CharacterData` / `StoryReviewGroupClientData`
  在 interface 上挂索引签名与具名字段冲突（TS2411）。改为交叉类型
  `{ ...具名字段 } & { [key: string]: JsonValue }`，既保留精确字段又保留字典访问。
- **索引签名掩盖具名字段**：`StoryReviewGroupClientData.rewards` 曾被索引签名吞掉。

## 4. 剩余债务与优先级

按「权重 = any×3 + unknown×1 + object×2」排序的 Top 违规文件：

| 文件 | any | unknown | object | 建议 |
| --- | --- | --- | --- | --- |
| `app/game/modules/medal/medal.ts` | 179 | 1 | 0 | 事件分发表 `{ [k: string]: (args: any) => void }` 与 `(this as any)[template]` —— 应为每个模板定义具名 handler 类型 + 映射表 |
| `app/ops/admin/AdminService.ts` | 62 | 25 | 3 | 运维层动态路径读写 `(cur as any)[key]`，应抽 `JsonPath` 工具函数统一收窄 |
| `app/game/modules/roguelike/settle.ts` | 62 | 0 | 0 | `excel.RoguelikeTopicTable.details[theme] as any` 类；多数可由生成类型直接覆盖 |
| `app/game/modules/roguelike/incident.ts` | 56 | 0 | 0 | 同上 |
| `app/game/modules/roguelike/logic.ts` | 53 | 5 | 0 | 同上 |
| `app/game/modules/activities/act1vhalfidle/logic.ts` | 37 | 0 | 0 | 活动状态建模 |

优先级：**medal 事件分发**（模式可复用、收益最大）→ **roguelike 三件套**（同一根因）
→ **admin 运维层**（可抽统一工具）→ 活动模块。

## 5. 工作流

```bash
pnpm run type:debt            # 报告总量 / delta / Top 违规文件
pnpm run type:debt -- --write # 刷新基线（棘轮只紧不松，上升即拒绝并退出 1）
pnpm exec vitest run tests/unit/architecture/type-debt-ratchet.test.ts
pnpm exec tsc --noEmit && pnpm exec vitest run
```

修复一个文件后，该文件计数下降无需手工改基线；**清零后必须**从
`tests/unit/architecture/type-debt-baseline.json` 移除该条目（守卫会红灯提醒）。
禁止用 `--force` 放宽棘轮。
