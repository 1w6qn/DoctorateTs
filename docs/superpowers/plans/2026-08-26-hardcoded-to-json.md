# 提取硬编码整理到 JSON 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将代码中 7 处冗长硬编码按「excel 可推导则运行时推导、推导不出则落 JSON」策略整理，产出 4 个 JSON 数据文件 + 一致性守护测试。

**Architecture:** 数据文件按业务模块放 `data/shop/`、`data/building/`、`data/rlv2/`（跟随 `SocialGoodList.json`/`choices.json` 先例）；加载方式跟随模块现状（shop.ts 构造器 `readJsonSync`、rlv2.ts 构造器 `readFileSync`、纯函数模块顶层同步加载）。excel 可推导项（职业券）改为从 `RoguelikeTopicTable.details[theme].recruitTickets` 键存在性过滤推导，不再硬编码 ticket id 列表。

**Tech Stack:** TypeScript / Express 5 / Node 24 / vitest（node env, globals on）

**设计文档:** `docs/superpowers/specs/2026-08-26-hardcoded-to-json-design.md`

---

## 前置说明（实现者必读）

- **不改行为**：本次是提取重构，所有数值/列表内容与现状逐字一致，只换存储位置与加载方式。
- **路径规则**：`__dirname` 相对路径——`app/game/controller/` → 上 3 级到根；`app/game/modules/building/`、`app/game/modules/mission/` → 上 4 级到根；`tests/unit/data/` → 上 3 级到根；shop.ts 用 `./data/...`（跟随 SocialGoodList.json 的 CWD 相对先例）。
- **导出名保持**：`GOLD_ORDER_DISTRIBUTION`、`WARMUP_ALPHA_HOURS`、`WARMUP_BETA_HOURS` 必须保持导出（`tests/unit/manager/building-trade-orders.test.ts` 引用）。
- **验证命令**：`pnpm exec tsc --noEmit`、`pnpm exec vitest run tests/<path>`、`pnpm exec vitest run`。

---

### Task 1: 创建 4 个 JSON 数据文件

**Files:**
- Create: `data/shop/credit-shop-rows.json`
- Create: `data/building/trade-order-dist.json`
- Create: `data/rlv2/recruit-groups.json`
- Create: `data/rlv2/mission-node-values.json`

- [ ] **Step 1: 创建 `data/shop/credit-shop-rows.json`**

数据逐字来自 `app/game/controller/shop.ts` 的 `CREDIT_SHOP_ROWS`（77~122 行），去掉 name/type（运行时从 item_table 推导）：

```json
{
  "rows": [
    [
      { "id": "4001", "count": 1800, "originPrice": 100, "allow95": true },
      { "id": "2001", "count": 9, "originPrice": 100, "allow95": true },
      { "id": "30011", "count": 2, "originPrice": 80 },
      { "id": "30012", "count": 3, "originPrice": 200 }
    ],
    [
      { "id": "4001", "count": 3600, "originPrice": 200, "allow99": true },
      { "id": "2002", "count": 9, "originPrice": 200, "allow99": true },
      { "id": "30021", "count": 2, "originPrice": 100 },
      { "id": "30022", "count": 2, "originPrice": 200 }
    ],
    [
      { "id": "3401", "count": 20, "originPrice": 160 },
      { "id": "3301", "count": 5, "originPrice": 160 },
      { "id": "30031", "count": 2, "originPrice": 100 },
      { "id": "30032", "count": 2, "originPrice": 200 }
    ],
    [
      { "id": "3401", "count": 25, "originPrice": 200 },
      { "id": "3302", "count": 3, "originPrice": 200 },
      { "id": "30041", "count": 2, "originPrice": 120 },
      { "id": "30042", "count": 2, "originPrice": 240 }
    ],
    [
      { "id": "7001", "count": 1, "originPrice": 160 },
      { "id": "3112", "count": 5, "originPrice": 160 },
      { "id": "30051", "count": 2, "originPrice": 120 },
      { "id": "30052", "count": 2, "originPrice": 240 }
    ],
    [
      { "id": "7002", "count": 1, "originPrice": 160 },
      { "id": "3113", "count": 3, "originPrice": 200 },
      { "id": "30061", "count": 2, "originPrice": 160 },
      { "id": "30062", "count": 1, "originPrice": 160 }
    ],
    [
      { "id": "3003", "count": 6, "originPrice": 160 }
    ]
  ]
}
```

- [ ] **Step 2: 创建 `data/building/trade-order-dist.json`**

数据逐字来自 `app/game/modules/building/trade-orders.ts`（24~58 行 + 38~39 行）：

```json
{
  "warmupAlphaHours": 3,
  "warmupBetaHours": 5,
  "goldOrderDistribution": {
    "1": [{ "gold": 2, "weight": 100 }],
    "2": [
      { "gold": 2, "weight": 60 },
      { "gold": 3, "weight": 40 }
    ],
    "3": [
      { "gold": 2, "weight": 30 },
      { "gold": 3, "weight": 50 },
      { "gold": 4, "weight": 20 }
    ]
  },
  "distAlpha": [
    { "gold": 4, "weight": 55 },
    { "gold": 3, "weight": 30 },
    { "gold": 2, "weight": 15 }
  ],
  "distBeta": [
    { "gold": 4, "weight": 85 },
    { "gold": 3, "weight": 10 },
    { "gold": 2, "weight": 5 }
  ],
  "distAlphaAlpha": [
    { "gold": 4, "weight": 65 },
    { "gold": 3, "weight": 22 },
    { "gold": 2, "weight": 13 }
  ]
}
```

- [ ] **Step 3: 创建 `data/rlv2/recruit-groups.json`**

数据逐字来自 `app/game/controller/rlv2.ts` 的 `GROUP_PROFESSIONS`（624~630 行）：

```json
{
  "recruit_group_1": ["pioneer", "sniper", "special"],
  "recruit_group_2": ["tank", "caster", "sniper"],
  "recruit_group_3": ["warrior", "support", "medic"],
  "recruit_group_4": ["pioneer", "support", "special"],
  "recruit_group_5": ["tank", "caster", "medic"]
}
```

- [ ] **Step 4: 创建 `data/rlv2/mission-node-values.json`**

数据逐字来自 `app/game/modules/mission/logic.ts` 的 `RLV2_MISSION_NODE_VALUES`（984~1004 行）：

```json
{
  "BATTLE_NORMAL": 1,
  "BATTLE_ELITE": 2,
  "BATTLE_BOSS": 4,
  "SHOP": 8,
  "REST": 16,
  "INCIDENT": 32,
  "TREASURE": 64,
  "ENTERTAINMENT": 128,
  "UNKNOWN": 256,
  "WISH": 512,
  "SACRIFICE": 1024,
  "EXPEDITION": 2048,
  "BATTLE_SHOP": 4096,
  "PORTAL": 8192,
  "MISSION": 16384,
  "STORY": 32768,
  "STORY_HIDDEN": 65536,
  "ALCHEMY": 131072,
  "DUEL": 262144,
  "EMPLOY": 33554432,
  "BATTLE_SAVAGE": 134217728,
  "SCRAP_SHOP": 2097152,
  "BATTLE": 1,
  "BATTLE_HARD": 2
}
```

注意：原代码 24 项中有 2 项与 excel `nodeTypeData` 名称/位值不同源（跨主题不一致，见设计文档矩阵），JSON 固化原语义名→位值，由 Task 7 测试守护位值 ∈ 某主题 `nodeTypeData` 键。

- [ ] **Step 5: 验证 4 个 JSON 均可解析**

Run: `node -e "for (const f of ['data/shop/credit-shop-rows.json','data/building/trade-order-dist.json','data/rlv2/recruit-groups.json','data/rlv2/mission-node-values.json']) { JSON.parse(require('fs').readFileSync(f,'utf8')); console.log('OK', f); }"`
Expected: 4 行 `OK <path>`，无异常。

---

### Task 2: `shop.ts` — 候选池改 JSON 加载 + name/type 由 item_table 推导

**Files:**
- Modify: `app/game/controller/shop.ts`（删 77~122 行字面量；构造器加加载；新增推导方法；`_buildSocialNormalGoods` 用 `this._creditRows`）

- [ ] **Step 1: 替换 `CREDIT_SHOP_ROWS` 字面量（77~122 行）为接口 + 构造器加载**

将 77~122 行的 `const CREDIT_SHOP_ROWS: CreditShopMaterial[][] = [...]` 整体替换为：

```ts
/** 信用交易所候选池条目（rows JSON 原始结构；name/type 由 item_table 运行时推导） */
interface CreditShopRowEntry {
  /** 物品 id（ItemTable itemId） */
  id: string;
  /** 单次购买数量 */
  count: number;
  /** 原价（信用） */
  originPrice: number;
  /** 是否可刷 -95% 特价 */
  allow95?: boolean;
  /** 是否可刷 -99% 特价 */
  allow99?: boolean;
}
```

- [ ] **Step 2: 构造器加载候选池（跟随 SocialGoodList.json 先例，同步读取避免竞态）**

在 `ShopController` 构造器（137 行起）的 socialGoodList 加载块之后追加：

```ts
    // 信用交易所候选池（7 行「并列随机抽取项」；name/type 由 item_table 推导）。
    // 修复：同步读取——原异步 readJson 与首次 getSocialGoodList 请求竞态（同 socialGoodList）
    try {
      const cfg = readJsonSync<{ rows: CreditShopRowEntry[][] }>(
        "./data/shop/credit-shop-rows.json",
      );
      this._creditRows = cfg.rows ?? [];
    } catch {
      this._creditRows = [];
    }
```

并在类字段区（构造器前）声明：

```ts
  /** 信用交易所候选池（rows JSON，行式并列随机抽取配置） */
  private _creditRows: CreditShopRowEntry[][] = [];
```

- [ ] **Step 3: 新增 `_materialFromEntry` 方法（item_table 推导 name/type）**

在 `_creditDiscount` 方法（451 行）之前插入：

```ts
  /**
   * 候选池条目 → 信用交易所物资（name/type 由 item_table 推导）
   *
   * 修复：候选池原硬编码 name/type（与 item_table 重复）——现按 id 查询
   * ItemTable 推导，缺失时告警并以 id 兜底名称（不跳过，避免候选池缩水）。
   * @param entry - rows JSON 条目
   * @returns 完整物资（含推导的 name/type）
   */
  private _materialFromEntry(entry: CreditShopRowEntry): CreditShopMaterial {
    const item = (excel.ItemTable as any)?.items?.[entry.id] ?? {};
    if (!item.name) {
      logger.warn("shop", `信用交易所候选池条目 ${entry.id} 不在 item_table，按 id 兜底`);
    }
    return {
      id: entry.id,
      count: entry.count,
      type: (item.itemType as string) ?? "MATERIAL",
      name: (item.name as string) ?? entry.id,
      originPrice: entry.originPrice,
      ...(entry.allow95 ? { allow95: true } : {}),
      ...(entry.allow99 ? { allow99: true } : {}),
    };
  }
```

- [ ] **Step 4: `_buildSocialNormalGoods` 改用 `this._creditRows`**

将 477 行：

```ts
      const row = CREDIT_SHOP_ROWS[Math.floor(rand() * CREDIT_SHOP_ROWS.length)];
      picked.push({
        m: row[Math.floor(rand() * row.length)],
        discount: 0,
      });
```

替换为：

```ts
      const row = this._creditRows[Math.floor(rand() * this._creditRows.length)];
      picked.push({
        m: this._materialFromEntry(row[Math.floor(rand() * row.length)]),
        discount: 0,
      });
```

- [ ] **Step 5: 验证**

Run: `pnpm exec tsc --noEmit`
Expected: 0 错误（无 `CREDIT_SHOP_ROWS` 残留引用）。

Run: `pnpm exec vitest run tests/unit/controller/shop.test.ts tests/unit/router/shop.test.ts`
Expected: 全绿。

---

### Task 3: `trade-orders.ts` — 概率表改 JSON 顶层加载

**Files:**
- Modify: `app/game/modules/building/trade-orders.ts`（删 24~58 行字面量；加 import + 顶层加载）

- [ ] **Step 1: 加 import + 顶层配置加载**

在文件头注释后、`GoldDistEntry` 接口前，加：

```ts
import { readJsonSync } from "@utils/file";

/**
 * 贸易站订单概率配置（data/building/trade-order-dist.json，启动时一次性加载）。
 * 数值来自 PRTS 贸易站页（见文件头注释），excel building_data.tradingData 无此数据。
 */
const ORDER_CONFIG = readJsonSync<{
  warmupAlphaHours: number;
  warmupBetaHours: number;
  goldOrderDistribution: Record<string, GoldDistEntry[]>;
  distAlpha: GoldDistEntry[];
  distBeta: GoldDistEntry[];
  distAlphaAlpha: GoldDistEntry[];
}>(`${__dirname}/../../../../data/building/trade-order-dist.json`);
```

- [ ] **Step 2: 替换 24~58 行的 5 个字面量**

将 `GOLD_ORDER_DISTRIBUTION`、`WARMUP_ALPHA_HOURS`、`WARMUP_BETA_HOURS`、`DIST_ALPHA`、`DIST_BETA`、`DIST_ALPHA_ALPHA` 的字面量定义整体替换为：

```ts
/** 站级基础概率表（贸易站页；JSON 键为字符串，此处转型保持既有数字索引类型） */
export const GOLD_ORDER_DISTRIBUTION = ORDER_CONFIG.goldOrderDistribution as unknown as Record<
  number,
  GoldDistEntry[]
>;

/** 暖机激活所需累积工时（小时）：α 小幅提升 3h、β 提升 5h（贸易站页） */
export const WARMUP_ALPHA_HOURS = ORDER_CONFIG.warmupAlphaHours;
export const WARMUP_BETA_HOURS = ORDER_CONFIG.warmupBetaHours;

/** α 激活分布：4金55% / 3金30% / 2金15%（贸易站页） */
const DIST_ALPHA: GoldDistEntry[] = ORDER_CONFIG.distAlpha;
/** β 激活分布：4金85% / 3金10% / 2金5%（贸易站页） */
const DIST_BETA: GoldDistEntry[] = ORDER_CONFIG.distBeta;
/** 双 α 叠加分布：4金65% / 3金22% / 2金13%（玩家实测期望 3.46，中置信） */
const DIST_ALPHA_ALPHA: GoldDistEntry[] = ORDER_CONFIG.distAlphaAlpha;
```

- [ ] **Step 3: 更新模块头注释**

将文件头第 2 行 `贸易站订单生成引擎（纯函数，无 IO）` 改为：
`贸易站订单生成引擎（纯函数，无 IO——概率配置启动时从 data/building/trade-order-dist.json 一次性加载）`

- [ ] **Step 4: 验证**

Run: `pnpm exec vitest run tests/unit/manager/building-trade-orders.test.ts`
Expected: 全绿（`GOLD_ORDER_DISTRIBUTION` 导出名保持，测试直接引用）。

---

### Task 4: `rlv2.ts` — 职业券 excel 推导 + recruit-groups.json 加载

**Files:**
- Modify: `app/game/controller/rlv2.ts`（`RoguelikeV2Config` 加 `recruitGroups` 字段；`chooseInitialRecruitSet` 内改 3 处）

- [ ] **Step 1: `RoguelikeV2Config` 加 `recruitGroups` 字段 + 构造器加载**

在 `RoguelikeV2Config` 类（约 49 行起）的 `eventChoices` 字段声明后、构造器前加：

```ts
  recruitGroups: { [key: string]: string[] };
```

在构造器（约 69 行起）的 `this.eventChoices = ...` 块后加：

```ts
    this.recruitGroups = JSON.parse(
      readFileSync(`${__dirname}/../../../data/rlv2/recruit-groups.json`, "utf-8"),
    );
```

- [ ] **Step 2: `chooseInitialRecruitSet` 内 `PROFESSIONS` 改 excel 推导**

将 613~622 行：

```ts
    const PROFESSIONS = [
      "pioneer",
      "warrior",
      "tank",
      "sniper",
      "caster",
      "support",
      "medic",
      "special",
    ];
```

替换为：

```ts
    // 标准职业列表（从 excel recruitTickets 键推导：`_recruit_ticket_<职业>` 后缀；
    // 顺序即 excel 键顺序，实证与职业枚举顺序一致）
    const CLASS_TICKET_RE =
      /_recruit_ticket_(pioneer|warrior|tank|sniper|caster|support|medic|special)$/;
    const recruitTickets = (excel.RoguelikeTopicTable.details[theme] as any)?.recruitTickets ?? {};
    const PROFESSIONS = Object.keys(recruitTickets)
      .filter((t) => CLASS_TICKET_RE.test(t))
      .map((t) => CLASS_TICKET_RE.exec(t)![1]);
```

- [ ] **Step 3: `GROUP_PROFESSIONS` 改用 `this._data.recruitGroups`**

将 624~630 行：

```ts
    const GROUP_PROFESSIONS: { [key: string]: string[] } = {
      recruit_group_1: ["pioneer", "sniper", "special"], // 先手必胜：先锋、狙击、特种
      recruit_group_2: ["tank", "caster", "sniper"], // 稳扎稳打：重装、术师、狙击
      recruit_group_3: ["warrior", "support", "medic"], // 取长补短：近卫、辅助、医疗
      recruit_group_4: ["pioneer", "support", "special"], // 灵活部署：先锋、辅助、特种
      recruit_group_5: ["tank", "caster", "medic"], // 坚不可摧：重装、术师、医疗
    };
```

替换为：

```ts
    // 招募组 → 具体职业券映射（官方 recruitGrps 仅带 desc 文本"XX、YY、ZZ招募券各一张"，
    // 按 desc 中职业顺序映射到标准职业券；组合表在 data/rlv2/recruit-groups.json）
    const GROUP_PROFESSIONS: { [key: string]: string[] } = this._data.recruitGroups;
```

- [ ] **Step 4: `GROUP_TICKETS` 改用 excel 存在性过滤**

将 633~639 行：

```ts
    const GROUP_TICKETS: { [key: string]: string[] } = {
      recruit_group_random: [
        `${theme}_recruit_ticket_5star`,
        `${theme}_recruit_ticket_quad_melee`,
        `${theme}_recruit_ticket_quad_ranged`,
      ],
    };
```

替换为：

```ts
    // 随心所欲专用券（5star/quad_melee/quad_ranged）——ticket 存在性由 excel 校验
    const GROUP_TICKETS: { [key: string]: string[] } = {
      recruit_group_random: ["5star", "quad_melee", "quad_ranged"]
        .map((kind) => `${theme}_recruit_ticket_${kind}`)
        .filter((t) => recruitTickets[t]),
    };
```

- [ ] **Step 5: 验证**

Run: `pnpm exec tsc --noEmit`
Expected: 0 错误。

Run: `pnpm exec vitest run tests/unit/router/rlv2.test.ts tests/unit/controller/rlv2-bugfix-20260826.test.ts`
Expected: 全绿。

---

### Task 5: `battle.ts` — ROGUE6_CLASS_TICKETS 改 excel 推导

**Files:**
- Modify: `app/game/controller/rlv2/battle.ts`（删 65~74 行字面量；改 `pickRogue6ClassTicket`）

- [ ] **Step 1: 替换 `ROGUE6_CLASS_TICKETS` 字面量与 `pickRogue6ClassTicket`**

将 65~83 行：

```ts
/** 黑流树海基础职业招募券列表（官服 battleFinish 奖励为职业券而非通用 _all） */
const ROGUE6_CLASS_TICKETS = [
  "rogue_6_recruit_ticket_pioneer",
  "rogue_6_recruit_ticket_warrior",
  "rogue_6_recruit_ticket_tank",
  "rogue_6_recruit_ticket_sniper",
  "rogue_6_recruit_ticket_caster",
  "rogue_6_recruit_ticket_support",
  "rogue_6_recruit_ticket_medic",
  "rogue_6_recruit_ticket_special",
] as const;

/**
 * 随机抽取一张黑流树海职业招募券（8 职业等概率）
 * @returns 一个职业招募券 id
 */
function pickRogue6ClassTicket(): string {
  return ROGUE6_CLASS_TICKETS[
    Math.floor(Math.random() * ROGUE6_CLASS_TICKETS.length)
  ];
}
```

替换为：

```ts
/** 黑流树海标准职业枚举（ticket 存在性由 excel recruitTickets 校验） */
const ROGUE6_CLASSES = [
  "pioneer",
  "warrior",
  "tank",
  "sniper",
  "caster",
  "support",
  "medic",
  "special",
] as const;

/**
 * 随机抽取一张黑流树海职业招募券（8 职业等概率）
 *
 * 修复：ticket id 列表原硬编码——现按职业枚举从 excel recruitTickets 过滤存在性
 * （官服 battleFinish 奖励为职业券而非通用 _all）。
 * @returns 一个职业招募券 id
 */
function pickRogue6ClassTicket(): string {
  const tickets =
    excel.RoguelikeTopicTable.details.rogue_6?.recruitTickets ?? {};
  const valid = ROGUE6_CLASSES.filter(
    (c) => tickets[`rogue_6_recruit_ticket_${c}`],
  );
  if (valid.length === 0) {
    logger.warn("rlv2", "rogue_6 recruitTickets 缺失标准职业券，回退先锋券");
    return "rogue_6_recruit_ticket_pioneer";
  }
  return `rogue_6_recruit_ticket_${valid[Math.floor(Math.random() * valid.length)]}`;
}
```

- [ ] **Step 2: 验证**

Run: `pnpm exec tsc --noEmit`
Expected: 0 错误。

Run: `pnpm exec vitest run tests/unit/controller/rlv2-battle-reward-blackstream.test.ts tests/unit/controller/rlv2-battle-finish-data.test.ts`
Expected: 全绿。

---

### Task 6: `mission/logic.ts` — RLV2_MISSION_NODE_VALUES 改 JSON 加载

**Files:**
- Modify: `app/game/modules/mission/logic.ts`（加 import；替换 984~1004 行字面量）

- [ ] **Step 1: 加 import**

在现有 import 区（`import { logger } from "@utils/logger";` 之后）加：

```ts
import { readJsonSync } from "@utils/file";
```

- [ ] **Step 2: 替换 `RLV2_MISSION_NODE_VALUES` 字面量**

将 984~1004 行的 `const RLV2_MISSION_NODE_VALUES: Record<string, number> = {...};` 整体替换为：

```ts
/**
 * 肉鸽节点类型语义名 → 位值（data/rlv2/mission-node-values.json）。
 *
 * 注意：excel nodeTypeData 分主题且同名节点位值跨主题不一致（如「诡意行商」
 * rogue_1~5=8、rogue_6=4096），无法从单一主题推出全局映射——JSON 固化，
 * 一致性由 tests/unit/data/mission-node-values.test.ts 守护（每个位值 ∈ 某主题键）。
 * 数值与 TorappuRoguelikeEventType / ROGUE6_NODE 对齐。
 * 岁兽残识"祸乱"节点（BATTLE / BATTLE_HARD）后端未实现专属机制，按作战/紧急作战近似。
 */
const RLV2_MISSION_NODE_VALUES: Record<string, number> = readJsonSync(
  `${__dirname}/../../../../data/rlv2/mission-node-values.json`,
);
```

- [ ] **Step 3: 验证**

Run: `pnpm exec tsc --noEmit`
Expected: 0 错误。

Run: `pnpm exec vitest run tests/unit/modules/mission/`
Expected: 全绿（mission 测试涉及 Rlv2PassNodeSpec 若 mock excel 不提供 nodeTypeData 仍通过——本改动不读 excel，仅读 JSON）。

---

### Task 7: 一致性守护测试（4 个新测试文件）

**Files:**
- Create: `tests/unit/data/credit-shop-rows.test.ts`
- Create: `tests/unit/data/trade-order-dist.test.ts`
- Create: `tests/unit/data/recruit-groups.test.ts`
- Create: `tests/unit/data/mission-node-values.test.ts`

- [ ] **Step 1: 创建 `tests/unit/data/credit-shop-rows.test.ts`**

```ts
import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

/** 信用交易所候选池 vs item_table 一致性守护（data/shop/credit-shop-rows.json） */
describe("credit-shop-rows.json 一致性", () => {
  const cfg = JSON.parse(
    readFileSync(`${__dirname}/../../../data/shop/credit-shop-rows.json`, "utf-8"),
  ) as { rows: { id: string; count: number; originPrice: number; allow95?: boolean; allow99?: boolean }[][] };
  const items = JSON.parse(
    readFileSync(`${__dirname}/../../../data/excel/item_table.json`, "utf-8"),
  ).items as Record<string, { name?: string; itemType?: string }>;

  it("候选池为 7 行（并列随机抽取项）", () => {
    expect(cfg.rows).toHaveLength(7);
  });

  it("每个条目 id 均存在于 item_table 且字段完整", () => {
    for (const row of cfg.rows) {
      for (const entry of row) {
        expect(items[entry.id], `id=${entry.id} 缺失于 item_table`).toBeDefined();
        expect(entry.count).toBeGreaterThan(0);
        expect(entry.originPrice).toBeGreaterThan(0);
      }
    }
  });

  it("特价标记仅出现在允许特价的条目（-95% 行1、-99% 行2）", () => {
    const flagged = cfg.rows.flat().filter((e) => e.allow95 || e.allow99);
    expect(flagged).toHaveLength(4);
    for (const e of flagged) {
      expect(["4001", "2001", "2002"]).toContain(e.id);
    }
  });
});
```

- [ ] **Step 2: 创建 `tests/unit/data/trade-order-dist.test.ts`**

```ts
import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

/** 贸易站订单概率配置结构守护（data/building/trade-order-dist.json） */
describe("trade-order-dist.json 结构", () => {
  const cfg = JSON.parse(
    readFileSync(`${__dirname}/../../../data/building/trade-order-dist.json`, "utf-8"),
  ) as {
    warmupAlphaHours: number;
    warmupBetaHours: number;
    goldOrderDistribution: Record<string, { gold: number; weight: number }[]>;
    distAlpha: { gold: number; weight: number }[];
    distBeta: { gold: number; weight: number }[];
    distAlphaAlpha: { gold: number; weight: number }[];
  };

  it("站级分布覆盖 1~3 级且每级权重合计 100", () => {
    expect(Object.keys(cfg.goldOrderDistribution).sort()).toEqual(["1", "2", "3"]);
    for (const lv of ["1", "2", "3"]) {
      const sum = cfg.goldOrderDistribution[lv].reduce((s, e) => s + e.weight, 0);
      expect(sum, `Lv${lv} 权重合计`).toBe(100);
    }
  });

  it("暖机分布权重合计 100", () => {
    for (const dist of [cfg.distAlpha, cfg.distBeta, cfg.distAlphaAlpha]) {
      expect(dist.reduce((s, e) => s + e.weight, 0)).toBe(100);
    }
  });

  it("暖机阈值 β > α > 0", () => {
    expect(cfg.warmupAlphaHours).toBeGreaterThan(0);
    expect(cfg.warmupBetaHours).toBeGreaterThan(cfg.warmupAlphaHours);
  });
});
```

- [ ] **Step 3: 创建 `tests/unit/data/recruit-groups.test.ts`**

```ts
import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

/** 肉鸽招募组职业映射 vs excel recruitGrps 一致性守护（data/rlv2/recruit-groups.json） */
describe("recruit-groups.json 一致性", () => {
  const groups = JSON.parse(
    readFileSync(`${__dirname}/../../../data/rlv2/recruit-groups.json`, "utf-8"),
  ) as Record<string, string[]>;
  const topic = JSON.parse(
    readFileSync(`${__dirname}/../../../data/excel/roguelike_topic_table.json`, "utf-8"),
  );
  const professions = [
    "pioneer", "warrior", "tank", "sniper",
    "caster", "support", "medic", "special",
  ];

  it("每组键均存在于 excel recruitGrps", () => {
    for (const key of Object.keys(groups)) {
      const found = Object.values(topic.details).some(
        (d: any) => d.recruitGrps?.[key],
      );
      expect(found, `组 ${key} 不存在于任何主题 recruitGrps`).toBe(true);
    }
  });

  it("组内职业均为标准 8 职业", () => {
    for (const profs of Object.values(groups)) {
      for (const p of profs) {
        expect(professions).toContain(p);
      }
    }
  });
});
```

- [ ] **Step 4: 创建 `tests/unit/data/mission-node-values.test.ts`**

```ts
import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

/** 肉鸽任务节点语义名→位值 vs excel nodeTypeData 一致性守护（data/rlv2/mission-node-values.json） */
describe("mission-node-values.json 一致性", () => {
  const values = JSON.parse(
    readFileSync(`${__dirname}/../../../data/rlv2/mission-node-values.json`, "utf-8"),
  ) as Record<string, number>;
  const topic = JSON.parse(
    readFileSync(`${__dirname}/../../../data/excel/roguelike_topic_table.json`, "utf-8"),
  );

  it("每个位值均为 2 的幂且存在于某主题 nodeTypeData 键", () => {
    const allKeys = new Set<number>();
    for (const det of Object.values(topic.details) as any[]) {
      for (const k of Object.keys(det.nodeTypeData ?? {})) allKeys.add(Number(k));
    }
    for (const [name, value] of Object.entries(values)) {
      expect(Number.isInteger(value) && value > 0 && (value & (value - 1)) === 0,
        `${name}=${value} 非 2 的幂`).toBe(true);
      expect(allKeys.has(value), `${name}=${value} 不在任何主题 nodeTypeData 键`).toBe(true);
    }
  });

  it("覆盖全部 20 个语义名", () => {
    expect(Object.keys(values)).toHaveLength(20);
  });
});
```

- [ ] **Step 5: 运行 4 个新测试**

Run: `pnpm exec vitest run tests/unit/data/`
Expected: 4 个测试文件全绿（`mission-node-values` 断言每个位值 ∈ 某主题 nodeTypeData 键——位值 16384/131072 需存在于某主题，若失败则先确认 excel 键全集再调整断言）。

- [ ] **Step 6: 全量回归**

Run: `pnpm exec vitest run`
Expected: 全部测试绿（含既有 100+ 测试；`building-trade-orders.test.ts` 引用 `GOLD_ORDER_DISTRIBUTION` 仍通过）。

---

### Task 8: 全量验证

- [ ] **Step 1: 类型检查**

Run: `pnpm exec tsc --noEmit`
Expected: 0 错误。

- [ ] **Step 2: 全量测试**

Run: `pnpm exec vitest run`
Expected: 全绿。

- [ ] **Step 3: 冒烟启动**

Run: `pnpm run start:quick`（前台起服 5 秒后 Ctrl+C，或观察启动日志）
Expected: 服务正常启动，无 `credit-shop-rows` / `trade-order-dist` / `recruit-groups` / `mission-node-values` 读取异常；随后停服。

- [ ] **Step 4: 清理残留引用**

Run: `pnpm exec grep -rn "CREDIT_SHOP_ROWS\|ROGUE6_CLASS_TICKETS\|GROUP_PROFESSIONS\|RLV2_MISSION_NODE_VALUES\|DIST_ALPHA\b" app/ --include=*.ts | grep -v "\.json"`
Expected: 仅剩 `RLV2_MISSION_NODE_VALUES` 的使用点（logic.ts 内部 2 处）与 `GROUP_PROFESSIONS` 使用点（rlv2.ts 内部），无残留字面量定义。
