# 提取硬编码整理到 JSON 设计

## 目标

将代码库中冗长的硬编码数据按「excel 可推导则改代码运行时推导、推导不出则落 JSON」的分层策略整理，消除魔法数据，使数据源可配置、可审计。

## 数据推导能力矩阵（已逐项实证）

| 硬编码 | excel 可否推导 | 处置 |
|---|---|---|
| `shop.ts` `CREDIT_SHOP_ROWS`（25 条候选池） | 部分：name/type 可从 `item_table` 推；id/count/originPrice/行分组/特价标记推不出（`SocialGoodList.json` 仅覆盖 8/25） | 落 JSON，name/type 改由 item_table 推导 |
| `trade-orders.ts` `GOLD_ORDER_DISTRIBUTION`/`DIST_*`/`WARMUP_*_HOURS` | 否（`building_data.tradingData` 仅 orderSpeed/orderLimit/orderRarity） | 落 JSON |
| `rlv2.ts` `GROUP_PROFESSIONS`（5 组职业映射） | 否（`recruitGrps` 仅 desc 中文文本） | 落 JSON |
| `mission/logic.ts` `RLV2_MISSION_NODE_VALUES`（21 语义名→位值） | 否（`nodeTypeData` 分主题且同名节点位值不一致，如「诡意行商」rogue_1~5=8、rogue_6=4096） | 落 JSON |
| `rlv2.ts` `PROFESSIONS`（8 职业） | 是（`recruitTickets` 键正则推导，rogue_1/6 实证全含） | 改代码运行时推导 |
| `rlv2.ts` `GROUP_TICKETS`（random 专用券） | 是（5star/quad_melee/quad_ranged 均实证存在） | 改代码运行时推导 |
| `battle.ts` `ROGUE6_CLASS_TICKETS` | 是（rogue_6 `recruitTickets` 实证全含） | 改代码运行时推导 |

## 数据文件（4 个新 JSON）

### 1. `data/shop/credit-shop-rows.json`

信用交易所候选池，7 行「并列随机抽取项」：

```json
{
  "rows": [
    [
      { "id": "4001", "count": 1800, "originPrice": 100, "allow95": true },
      { "id": "2001", "count": 9, "originPrice": 100, "allow95": true },
      { "id": "30011", "count": 2, "originPrice": 80 },
      { "id": "30012", "count": 3, "originPrice": 200 }
    ]
  ]
}
```

- 条目字段：`id`/`count`/`originPrice`/`allow95?`/`allow99?`
- **不含** name/type：运行时从 `excel.ItemTable`（`items[id].name` / `items[id].itemType`）推导，推导失败时告警并跳过该条目
- 原 `CreditShopMaterial` 接口保留（name/type 填充后使用）

### 2. `data/building/trade-order-dist.json`

```json
{
  "warmupAlphaHours": 3,
  "warmupBetaHours": 5,
  "goldOrderDistribution": {
    "1": [{ "gold": 2, "weight": 100 }],
    "2": [{ "gold": 2, "weight": 60 }, { "gold": 3, "weight": 40 }],
    "3": [{ "gold": 2, "weight": 30 }, { "gold": 3, "weight": 50 }, { "gold": 4, "weight": 20 }]
  },
  "distAlpha": [{ "gold": 4, "weight": 55 }, { "gold": 3, "weight": 30 }, { "gold": 2, "weight": 15 }],
  "distBeta": [{ "gold": 4, "weight": 85 }, { "gold": 3, "weight": 10 }, { "gold": 2, "weight": 5 }],
  "distAlphaAlpha": [{ "gold": 4, "weight": 65 }, { "gold": 3, "weight": 22 }, { "gold": 2, "weight": 13 }]
}
```

### 3. `data/rlv2/recruit-groups.json`

```json
{
  "recruit_group_1": ["pioneer", "sniper", "special"],
  "recruit_group_2": ["tank", "caster", "sniper"],
  "recruit_group_3": ["warrior", "support", "medic"],
  "recruit_group_4": ["pioneer", "support", "special"],
  "recruit_group_5": ["tank", "caster", "medic"]
}
```

### 4. `data/rlv2/mission-node-values.json`

`RLV2_MISSION_NODE_VALUES` 21 个语义名→位值（语义名是代码/官方枚举命名体系，位值跨主题不一致，JSON 固化并带一致性测试守护）。

## 代码改动

### `app/game/controller/shop.ts`

- 删除 `CREDIT_SHOP_ROWS` 字面量（77~122 行）
- 构造器 `readJsonSync("./data/shop/credit-shop-rows.json")`（跟随 `SocialGoodList.json` 先例，同步读取避免竞态）
- 构建 `CreditShopMaterial` 时从 `excel.ItemTable` 补 name/type

### `app/game/modules/building/trade-orders.ts`

- 删除 `GOLD_ORDER_DISTRIBUTION`/`DIST_ALPHA`/`DIST_BETA`/`DIST_ALPHA_ALPHA`/`WARMUP_*_HOURS` 字面量
- 模块顶层从 JSON 同步加载；**保留 `GOLD_ORDER_DISTRIBUTION` 导出名与形状**（测试引用）
- 模块头注释更新：「纯函数，无 IO（配置启动时从 JSON 一次性加载）」

### `app/game/controller/rlv2.ts`

- `chooseInitialRecruitSet` 内 `PROFESSIONS` → 从 `excel.RoguelikeTopicTable.details[theme].recruitTickets` 键正则推导（`_recruit_ticket_(pioneer|warrior|tank|sniper|caster|support|medic|special)$`），匹配顺序即职业顺序
- `GROUP_TICKETS` → 从 `recruitTickets` 推导 `5star`/`quad_melee`/`quad_ranged`
- `GROUP_PROFESSIONS` → 构造器从 `data/rlv2/recruit-groups.json` 加载（跟随 `choices.json` 先例，`_data` 中新增字段）

### `app/game/controller/rlv2/battle.ts`

- 删除 `ROGUE6_CLASS_TICKETS` 字面量 → 运行时从 `excel` rogue_6 `recruitTickets` 推导；`pickRogue6ClassTicket()` 保持

### `app/game/modules/mission/logic.ts`

- 删除 `RLV2_MISSION_NODE_VALUES` 字面量 → 顶层从 `data/rlv2/mission-node-values.json` 同步加载（`__dirname` 相对路径）

## 测试

- 新增 `tests/unit/` 一致性守护：
  - `mission-node-values` 每个位值 ∈ 某主题 `nodeTypeData` 键
  - `credit-shop-rows` 每个 id ∈ `item_table`，行内条目字段完整
  - `trade-order-dist` 结构（站级 1~3、权重合计 100）
- 回归：现有测试保持绿色（`GOLD_ORDER_DISTRIBUTION` 等导出名不变；shop/rlv2 测试不引用被删常量）

## 验证

`pnpm exec tsc --noEmit` + `pnpm exec vitest run` 全绿；`pnpm run start:quick` 冒烟启动。
