# 黑流树海（rogue_6）实现体检报告：已实现 vs 官方文本对照

> 体检日期：2026-08-17（首版）；**2026-08-17 18:35 更新**：P0（实托邦/误入奇境/行动力）与三结局核心链路已实现（见 §十一 变更记录）；**18:40 更新**：二结局·维度重构全链路已实现；**2026-08-19 更新**：节点分发全量补齐 + 主题规则注册表重构 + B1~B9 bug 修复（见 §十二）
> 对照源：用户提供的官方探索模式文本（模式/难度/分队/行动奖励/招募组合/区域/结局）
> 检查范围：`app/game/controller/rlv2/` 全部控制器、`app/excel/roguelike_topic_table.ts`、`data/excel/roguelike_topic_table.json`、`data/rlv2/*.json`、`app/game/router/rlv2.ts`
>
> **阅读须知**：本文按时间线增量更新，早期章节中被后续实现推翻的结论已就地标注 `~~已过期~~`；如遇同一项在不同章节结论冲突，**以日期更晚的结论为准**（§十二 > §十一 > 首版）。
>
> 结论速览：**核心框架与数据表高度完整**（难度表、分队、地图构造模板、结局收藏品、startbuff 选项全部在库）；首版列出的五大缺口中，实托邦/行动力/二三结局流程/误入奇境/节点分发均已落地，**仅实践者列表模式（MONTH_TEAM）与文明开化分队专属待办**。

---

## 图例

| 标记 | 含义 |
|---|---|
| ✅ 已实现 | 服务端逻辑存在且与官方文本一致 |
| 🟡 部分实现 | 数据/框架在，但关键逻辑缺失或与官方不符 |
| ❌ 未实现 | 数据表有配置但服务端无逻辑，或完全缺失 |
| 👁 客户端侧 | 纯客户端表现，服务端无需处理 |

---

## 一、游戏模式

| 官方文本 | 状态 | 说明 |
|---|---|---|
| 常规行动（目标生命8 / 希望6 / 源石锭6 / 携带6 / 留存3 / 零件箱10） | ✅ 已实现 | `init` 表：initialHp=8、initialPopulation=6、initialSquadCapacity=6、initialBandRelic 全量；留存上限 3（`stashRecruitLimit`）；零件箱 10（`scrap.limit`）。⚠️ 见 §九-1：**源石锭数据表为 8，官方文本写 6**，二者不一致 |
| 实践者列表（理想践行者 / 实践随行录 / 委托报酬 / 不结算分数） | ❌ 未实现 | `init` 表有 `month_team_1/2`（MONTH_TEAM，含专属招募组 `recruit_group_m1/m2`），但 `createGame` 将 MONTH_TEAM/CHALLENGE 一律转为 NORMAL（`rlv2.ts:227`），专属 init 条目永不命中；理想践行者干员、随行录、委托任务均无逻辑 |
| 探索初始化时间（1 分钟冷却） | 🟡 部分实现 | 见 §八-1 |

---

## 二、难度系统

### 难度表（数据）

| 难度 | 得分效率 | 数据表 | 状态 |
|---|---|---|---|
| 保密等级 0（初始生命更高 / 失败下次获得【特勤任务影像】） | ±0% | scoreFactor=1 ✅ | 🟡 失败补偿未接入（见下） |
| 保密等级 1（生命上限-2） | +5% | 1.05 ✅ | ✅ `level_life_point_add -2` |
| 保密等级 2（实托邦生成） | +10% | 1.10 ✅ | ✅ 实托邦生成已实现（2026-08-17，见 §六）。~~原结论"逻辑缺失"已过期~~ |
| 保密等级 3（险路尽头不再提前揭示） | +15% | 1.15 ✅ | 🟡 地图模板数据含 reveal 差异，但"难度3 起不揭示"无显式分支 |
| 保密等级 4（“居民”据点 / 失败不再获得特勤任务影像） | +20% | 1.20 ✅ | 🟡 “居民”据点节点类型 ✅（RESIDENT 134217728）；失败影像条件无 |
| 保密等级 5（敌生命+30%） | +25% | 1.25 ✅ | 👁 客户端战斗数值 |
| 保密等级 6（实托邦中期 / 方针） | +30% | 1.30 ✅ | ❌ 见 §六 |
| 保密等级 7（零件箱容量-2） | +35% | 1.35 ✅ | ✅ `scrap_limit_add -2`（scrap.limit 10→8，`scrap.ts:39,50`） |
| 保密等级 8（精英/领袖攻击+15%） | +40% | 1.40 ✅ | 👁 客户端 |
| 保密等级 9（进区损失 10% 源石锭） | +45% | 1.45 ✅ | ✅ `zone_gold_loss_percent` → `checkZoneEnd` 扣除 |
| 保密等级 10（部署-1 / 生命-2） | +50% | 1.50 ✅ | ✅ `deploy_limit_add -1` + `level_life_point_add -2` |
| 保密等级 11（领袖受伤-20%） | +50% | 1.50 ✅ | 👁 客户端 |
| 保密等级 12（实托邦晚期 / 范围扩大） | +50% | 1.50 ✅ | ❌ 见 §六 |
| 保密等级 13（非初始招募五星希望+1 / 症结之核 / 未熄之地） | +50% | 1.50 ✅ | ✅ 希望+1 解析（`parseDifficultyText` 正则命中）；敌人数值 👁 |
| 保密等级 14（猎犬proto / 源阶方） | +50% | 1.50 ✅ | 👁 客户端（服务端无敌人属性处理） |
| 保密等级 15（非初始招募六星希望+1 / 猎犬proto / 卡德霍） | +50% | 1.50 ✅ | ✅ 希望+1 解析；敌人数值 👁 |

### 难度机制

| 机制 | 状态 | 说明 |
|---|---|---|
| 进阶式累积（选 N 时 1..N 全生效） | ✅ | `difficultyBuffs` 按 grade<=N 过滤叠加（`buff.ts:72-92`） |
| 通关解锁下一级（进阶式扩展） | ✅ | `initModeGradeStates`（通关 N-1 解锁 N）+ `gameSettle` 写入 `record.modeGrade` |
| 难度 0：失败后下次探索获得【特勤任务影像】 | ❌ | `rogue_6_legacy_10`（开局助力）数据在库，但 `createGame` 的 legacy 处理只识别"5源石锭/1点希望"（`rlv2.ts:263-272`），**特勤任务影像未发放**；且未实现"失败才发放"判定 |
| 难度 4：失败后不再获得影像 | ❌ | 同上，无条件分支 |

---

## 三、调查者增益

| 机制 | 状态 | 说明 |
|---|---|---|
| 生灵的溯游（难度≥3 分裂 / ≥6 卵生 / ≥9 胎生） | ✅ | `ensureOuterTheme` THRESHOLDS `{分裂:3, 卵生:6, 胎生:9}`，点亮科技树节点后自动解锁分队升级（`rlv2.ts:373-384`） |
| 多元化展现（多元奇物 3~5/6~8/9+ 强化） | 👁 | 纯收藏品效果，客户端处理 |

---

## 四、分队系统

| 项 | 状态 | 说明 |
|---|---|---|
| 分队全集（含 6 个新增 + 升级变体） | ✅ | `bandRef` 22 条（band_2/22/5/7/16/18/20 为 bandLevel=1 升级变体），数据与官方命名一致（本源研修 band_14、文明开化 band_15/16、开拓者 band_17/18、多边贸易 band_19/20、地质调查 band_21、指挥 band_1/2、特勤 band_3/22、后勤 band_4/5、矛头 band_6/7、突击 band_8、堡垒 band_9、远程 band_10、破坏 band_11、高台 band_12、地面 band_13） |
| 分队效果 buff（生命/部署/初始干员/初始物品） | ✅ | `chooseInitialRelic` → `relic.gain` → `rlv2:buff:apply`（`relic.ts:36-47`）；`applyBuffs` 支持 level_life_point_add / level_char_limit_add / immediate_recruit / immediate_reward |
| 升级分队解锁隐藏旧分队 | ✅ | 科技树解锁（`unlockBuff`）与通关（`gameSettle`）两条路径均调用 `applyBandUpgradeVisibility` |
| 结局勋章边框（10+ 三结局） | 👁 | 结算展示，客户端 |
| 战术分队解锁条件（5 名对应职业通关） | 👁 | 收藏品解锁状态，客户端展示；服务端不校验 |
| 多边贸易分队（同商节点卖 3 零件+8 源石锭 / 进行商获枯苔藓球） | 🟡 | ✅ 零件箱容量 +2/+4（MAX_WEIGHT → scrap.limit）；🟡 "卖出 3 零件+8 金"（shop_recycle_reward buff 已就绪）待行商卖出接口 |
| 文明开化分队（消除理想源 +2 行动力 / 收藏品 / 不受方针影响） | ❌ | 依赖实托邦逻辑，实托邦未实现 → 该分队核心效果悬空 |
| 本源研修分队（本源系招募希望-2） | 🟡 | BAND 数据在；服务端 recruit 仅处理 `recruit_cost`/`recruit_hop_cost` buff，未见本源系职业减免接入 |
| 开拓者分队（初始 1 加工品 / 进区获加工品或概念体） | ✅ | `zone_into_reward` pool_scrap_3/6（开局/进区 1 件 GOODS 加工品，池已建、POOL 分支修复）；无限定区域时全区生效 |

---

## 五、探索准备阶段流程

### 1.5 收获培育结果（襁褓生灵）

| 项 | 状态 | 说明 |
|---|---|---|
| 襁褓获得 → 持久化到下一局（record.legacy） | ✅ | `gameSettle` 过滤 LEGACY 型写入 `rec.legacy`（`rlv2.ts:2447-2456`） |
| 开局加成：襁褓中的猫 +5 源石锭 / 狗 +1 希望 | ✅ | `createGame` legacy 循环（`rlv2.ts:263-272`） |
| 襁褓生灵效果：增加行动奖励**选项及选择次数** | ❌ | `GAME_INIT_SUPPORT` 只从 startbuff_1..6 随机 3 个；**7..12 号襁褓选项（每区+1 行动力 / 初始+1 希望 / 前2区敌生命-50% 等）数据在库但未接入**；"选择次数增加"无逻辑 |
| 其余 19 种襁褓（开局助力/特勤任务影像等） | ❌ | `rogue_6_legacy_01..14` 在库，createGame 仅识别两类 |

### 2. 行动奖励

| 官方选项 | startbuff id | 状态 |
|---|---|---|
| 未编号物（1 件普通收藏品） | choice_ro6_startbuff_1 | ✅ |
| 调查预付款（8 源石锭） | choice_ro6_startbuff_2 | ✅ |
| 空间租赁（-6 源石锭，零件箱+2） | choice_ro6_startbuff_3 | ✅（依赖 SCRAP limit） |
| 退行补偿（-2 生命上限，1 件随机收藏品） | choice_ro6_startbuff_4 | ✅ |
| 林间代步（1 件加工品） | choice_ro6_startbuff_5 | ✅ |
| 巢寄生（零件箱-1，1 件稀有收藏品） | choice_ro6_startbuff_6 | ✅ |
| 6 选 3 随机 | — | ✅ `GAME_INIT_SUPPORT` 随机 3 个 |
| 襁褓追加（7-12） | choice_ro6_startbuff_7..12 | ❌ 未接入 |

### 3. 招募组合

| 官方组合 | id | 状态 |
|---|---|---|
| 先手必胜（先锋/狙击/特种） | recruit_group_1 | ✅ |
| 稳扎稳打（重装/术师/狙击） | recruit_group_2 | ✅ |
| 取长补短（近卫/辅助/医疗） | recruit_group_3 | ✅ |
| 灵活部署（先锋/辅助/特种） | recruit_group_4 | ✅ |
| 坚不可摧（重装/术师/医疗） | recruit_group_5 | ✅ |
| 随心所欲（随机 3 张，第 1 张必为 5 星临时招募券） | recruit_group_random | ✅ 专用券 `_5star`/`_quad_melee`/`_quad_ranged` 存在；缺失时回退随机 |

### 4. 初始招募

| 项 | 状态 | 说明 |
|---|---|---|
| 初始招募券 + 招募（希望按 4星0/5星2/6星4 扣） | ✅ | `populationFor` rogue_6 专属曲线（`recruit.ts:51-56`）；`done` 扣 POPULATION |
| 助战干员（好友/系统助战） | 🟡 | `getTicketAssistList`/`recruitAssistChar` 静默关闭（单账号私服无好友，可接受） |
| 留存招募券（上限 3） | ✅ | `stashRecruitTicket`（`stashRecruitLimit`=3，`_candle` 变体映射） |
| 开局礼物（金+10 / 人口+1） | ✅ | `GAME_INIT_GIFT`（rogue_6 专属） |

---

## 六、区域与地图

### 常规区域（5 层）

| 官方层 | 官方初始行动力 | 状态 |
|---|---|---|
| Ⅰ 玻利瓦尔肤层 | 5（翅膀节点后 6） | ✅ |
| Ⅱ 甜美的伤口 | 6 | ✅ |
| Ⅲ 血色空脉 | 7 | ✅ |
| Ⅳ 受害者腐殖 | 8 | ✅ |
| Ⅴ 卡德霍之颅 | 8 | ✅ |
| **行动力机制整体** | — | ✅ 已实现（2026-08-17，见下"行动力机制"行）。~~原结论"stepRemain 固定重置为 20 / SPECIAL_ZONE_AP handler 为空 / 翅膀 +1 无逻辑"已过期~~ |

### 地图生成

| 项 | 状态 | 说明 |
|---|---|---|
| 构造模板（连通结构/起点/终点/固定节点） | ✅ | `BLACKSTREAM_CONSTRUCTIONS`（含 utopia 构造 6+ 套，`sourceId` 对应雾色：utopia-red / 全知者盲区 / 未亡者遗怨 / 源石之城 等） |
| 数量规则 + 距离规则（按层） | ✅ | `BLACKSTREAM_COUNT_RULES` / `DISTANCE_RULES`，BFS 距起点边距 + 回退曼哈顿 |
| 节点类型全集 | ✅ | 作战/紧急/“居民”据点/安全的角落/不期而遇/得偿所愿/失与得/先行一步/诡意行商/秘境行商/应急助力/误入奇境/狭路相逢/曲折密道/羽瞰点/险路小径/险路尽头/险路恶敌/命运所指（二结局）/流窜“居民” 全部映射（grid_zone.ts ROGUE6_NODE + CONSTRUCTION_TYPE_TO_NODE） |
| 起点相邻格一二层强制作战 | ✅ | `startAdjacentCombat = layerIndex <= 1` |
| 同步官服 map.zones（键 1000 起） | ✅ | `syncMapZones`，zone_end 标记依赖 `checkZoneEnd` |
| **常规区域实托邦（variation）** | ✅ 已实现（2026-08-17） | `applyUtopiaVariation`：难度≥2 起按概率附加乌托邦效果到 `map.zones[zone].variation`（25% / 6~11 难度 40% 更频繁 / 12+ 难度 60% 晚期）；效果 id 取自 variationData（9 种乌托邦全在库）；VI 层不生成 |
| **误入奇境隐藏层（未萌生的摇篮）** | ✅ 已实现（2026-08-17） | MIRAGE 节点 → portal 场景（scene_ro6_portalX_enter，按雾色场景族）→ 消耗 1 件加工品进入 → 按雾色选 utopia 模板生成隐藏层（layerIndex=6，本层专用行动力 template.action）→ 行动力耗尽返回进入时节点；portal 状态续局可恢复 |
| **行动力机制** | ✅ 已实现（2026-08-17） | 层初始行动力 5/6/7/8/8（`initialActionForZone`）；【生命游戏】翅膀节点（rogue_6_outbuff_37）Ⅰ 层 +1；襁褓天马（rogue_6_start_1）每区 +1；`SPECIAL_ZONE_AP` 物品增减当前区行动力（安全的角落/休息选项）；VI 层/portal 取模板 action |

### 节点交互

| 节点 | 状态 | 说明 |
|---|---|---|
| 全部 21 类节点分发 | ✅ 已实现（2026-08-19） | rogue_6 走 `gridZoneMoveTo` → `createRogue6NodeScene`（`ROGUE6_NODE_SCENE_PREFIX`，见 §十二）；标准主题仍走 `moveTo` + `NODE_SCENE_PREFIX` |
| 安全的角落 / 得偿所愿 / 失与得 / 狭路相逢 / 险路尽头 / 险路小径 | ✅ | 前缀 `rest` / `wish`+`relic` / `sacrifice` / `sala` / `final` / `evacuate`（官方 choiceScenes 实测确证） |
| 不期而遇 | ✅ | `createIncidentScene`（线人 bomb1）优先，未命中则 `normal*` / `bat*` 通用场景 |
| 诡意行商 / 秘境行商 / 应急助力 | ✅ | `ROGUE6_SHOP_NODES` → `BATTLE_SHOP`（含碎片回收、刷新、折扣）；应急助力另有 `hire*` 场景 |
| 作战 / 紧急作战 / 险路恶敌 / “居民”据点 | ✅ | `ROGUE6_BATTLE_NODES` → 战斗；关卡按 `ZoneStagePools` 三池分流（普通/精英/首领） |
| 先行一步（三结局"探索树的源头"入口） | ✅ 已实现（2026-08-17 流程 + 2026-08-19 节点可达） | `scout*` 场景（choice_ro6_scout_1/3）→ 送干员 → 下一层返回 +2 希望 + 怦然信标。~~原结论"只做远征记录"已过期~~ |
| 命运所指（二结局 3 选 1 / 三结局调谐仪式） | ✅ 已实现（2026-08-17） | `createFateScene`（PROPHECY 与 PROPHECY_HIDDEN 两个数值均分发）→ end1/end2 判定。~~原结论"无 PROPHECY 分支"已过期~~ |
| 误入奇境 | ✅ 已实现（2026-08-17） | `createPortalScene` → 消耗 1 件**加工品（MOVE 型）**→ `generatePortal` 隐藏层 |
| 曲折密道 / 羽瞰点 / 林间空地 | ✅ | 官方 subName 为传送 / 视野 / 空节点——地图机制而非事件场景，落地即 `WAIT_MOVE`（非缺陷） |

---

## 七、结局

| 结局 | 状态 | 说明 |
|---|---|---|
| **一、强制重启**（通关 V 层 boss【永无安宁/痛苦将息】） | ✅ | 5 层 boss（险路恶敌）→ `maxZone`=5 → `toEnding=ro6_ending_1`；"不持有怦然信标通过 V 层"为默认路线 |
| **二、维度重构**（线人与线索→沙盘αβ→V 层 3 个命运所指→混沌源阶理论） | ✅ 已实现（2026-08-17） | 线人事件（bomb1"线人与线索"，Ⅱ-Ⅳ 层不期而遇概率触发）→ 选"获得沙盘α"（choice_ro6_bomb1_1）；沙盘β Ⅰ-Ⅲ 层行商 1 源石锭上架（未持有才出现，随机藏品池排除二结局专属）；V 层命运所指（PROPHECY）→ 持有双沙盘必为窥视箱中（end2），否则 1/3 窥视箱中 / 2/3 好奇心与死（end1，50 源石锭标记或得 1 收藏品）；窥视箱中"找到声音位置"→"与当前区域首领的决战"→ 混沌源阶理论（ro6_b_5，节点变险路恶敌 zone_end）；不持怦然信标通过第Ⅴ层 → ending_2 |
| **三、纠缠调和**（先行一步→怦然信标→V 层后进入 VI 层→调谐仪式削弱症结之核） | 🟡 核心链路已实现（2026-08-17） | ✅ 先行一步"派一名同伴进入/探索"（choice_ro6_scout_1/3）→ 标记三结局远征 → 干员下一层返回 +2 希望 + 【怦然信标】（gameConst.expedEndingRelic 数据驱动）；✅ maxZone 持有怦然信标放行第Ⅵ层（源流交汇处模板 floor-6-01 已含起点右侧命运所指/调谐仪式入口）；✅ 通过 VI 层 → ending_3。🟡 调谐仪式提交（final_4/5/6 削弱）效果在客户端战斗内，服务端节点可正常通行 |
| 结局收藏品 | ✅ | 数据全在库（final_1..6、bubble_01..08、legacy_11 等） |

---

## 八、其他机制

| 机制 | 状态 | 说明 |
|---|---|---|
| 探索初始化时间（1 分钟） | 🟡 | 官服由客户端控制冷却；服务端无强制，可接受 |
| 支援选项（上一把 ≥3 层 → 开局 buff 3 选 1） | ✅ | `outer.support = lastZone>=3`，`GAME_INIT_SUPPORT` 场景 |
| 前瞻性投资（银行存取） | ✅ | `bankPut`（扣 1 金）/`bankWithdraw`；上限 999 |
| 月度任务刷新（A/B/C 抽取） | ✅ | `refreshMission` |
| 战令奖励 / 探索分数（难度倍率） | ✅ | `battlePassGetReward` / `exploreScore`（层档位+步数+战斗+招募+藏品，×scoreFactor） |
| 商店（折扣 25% / 刷新 2 次 / 回收） | ✅ | `generateShopGoods` / `refreshShop` |
| 远征（先行一步选干员） | ✅ | 记录/返回 + 三结局专属效果（送干员→返回 2 希望+怦然信标） |
| 献祭（失与得） | ✅ | `sacrificeChoice`（canSacrifice 8/12 价值过滤） |
| 重掷节点 / 升级节点 | ✅ | `rerollNode`（rollNodeData）/`upgradeNode` |
| 助战 / 好友 | 🟡 | 单账号私服静默处理 |
| 干员类型 CHARACTER（佣兵固定干员） | ✅ | `inventory.ts:213-218` |

---

## 九、数据侧发现的疑点

1. **初始源石锭不一致**：官方文本写「源石锭 6」，数据表 `initialGold=8`（黑流树海与其他集成战略一致为 8，疑为所贴文本版本差异；**以数据表/官服抓包为准**，但需你确认）。
2. **startbuff 12 个选项在库**（1-6 基础 + 7-12 襁褓）；襁褓追加已于 2026-08-17 接入（§十 P2-6），~~"仅用 1-6 / 逻辑缺失"已过期~~。
3. **NODE_BUOY 型 8 个物品**（线人与线索/神明之殇/文明之烬/光明之末等）全部在库；二结局依赖的线人（bomb1）读取逻辑已于 2026-08-17 接入，~~"无任何读取逻辑"已过期~~，其余 NODE_BUOY 仍无专属逻辑。
4. **VI 层构造模板**（layerIndex=5）已可达：`maxZone` 持怦然信标放行第 Ⅵ 层（2026-08-17），~~"模板不可达"已过期~~。
5. `chooseInitialRecruitSet` 的 `GROUP_PROFESSIONS` 与官方文本职业顺序一致（先手必胜=先锋/狙击/特种 ✓）。

---

## 十、缺口优先级建议（✅ = 2026-08-17 已实现）

### P0（影响主线可玩性）
1. ✅ **实托邦生成**：按雾色模板接入 `grid_zone.generate`（数据已就绪），并支持难度 2/6/12 三阶段（生成频率 + 早/中/晚期效果提升 + 方针）——常规区 variation + 误入奇境隐藏层全链路已落地。
2. ✅ **行动力机制**：层初始行动力 5/6/7/8/8（翅膀 +1 / 襁褓天马 +1）；`SPECIAL_ZONE_AP` 物品生效；隐藏层耗尽返回入口。

### P1（影响结局完整度）
3. ✅ **三结局流程**：先行一步→怦然信标→maxZone 放行 6 层→ending_3；**二结局**（线人→沙盘αβ→V 层命运所指 3 选 1→混沌源阶理论）✅ 全链路已实现——线人 bomb1、沙盘β商店、命运所指 end1/end2 判定、混沌源阶理论（ro6_b_5）、ending_2。
4. ✅ **误入奇境隐藏层**：消耗加工品进入 + 雾色→乌托邦 + 专用行动力。
5. ❌ **实践者列表模式**：MONTH_TEAM init 命中（不再强制转 NORMAL）+ 理想践行者随行录/委托任务——涉及模式判定改造 + 践行者干员 + 委托任务系统，私服场景收益有限，保留为后续。

### P2（细节完善）
6. ✅ **襁褓加成接入行动奖励**：襁褓羽蛇（legacy_04..09，通过≥2 区）→ 行动奖励追加 1 个襁褓选项（startbuff_7..12 → 襁褓宠物 start_1..6，relic buffs 数据驱动）；襁褓三头犬（legacy_03）→ 行动奖励选择次数 +1（追加 SUPPORT 事件）。
7. ✅ **难度 0/4 特勤任务影像**：难度 ≤3 失败 → record.legacy 记录 → 下次开局发放【特勤任务影像】（rogue_6_relic_fight_29）；难度 4+ 失败不再记录。
8. 🟡 **分队专属逻辑**（2026-08-17 部分落地）：✅ 本源研修（`recruit_cost_sub_profession`：本源系子职业 primcaster/primprotector/primguard/ritualist，4星+ 希望-2，CharacterTable.subProfessionId 数据驱动）；✅ 多边贸易零件箱容量（`rogue_6_max_weight` MAX_WEIGHT → rogue_6 特判加 SCRAP limit）；✅ 开拓者（`zone_into_reward` pool_scrap_3/6 → 进区/开局获加工品，池已建、POOL 分支修复）；🟡 多边贸易"卖 3 零件+8 金"（shop_recycle_reward buff 已就绪，待行商卖出接口）；❌ 文明开化（immediate_reward_on_weather_clear，依赖理想源/天气清除机制未实现）。
9. 🟡 **初始源石锭** 6 vs 8 核实（数据表 8，文本 6，以数据为准）。

---

## 十一、变更记录（2026-08-17）

实托邦 + 行动力 + 二/三结局流程落地，新增/更新测试 31 条（controller 247 全绿）：

1. `app/game/controller/rlv2/modules/grid_zone.ts`：
   - 导出 `ROGUE6_NODE`；新增 `GridPortalState` + `PORTAL_FAMILY`（雾色场景族 1~9 → 乌托邦效果 + utopia 模板映射）
   - `generatePortal`（误入奇境隐藏层：按雾色选模板 + variation + 专用行动力 + 返回点记录）、`leavePortal`（行动力耗尽返回）、`currentZoneKey`、`pickPortalTemplate`
   - `applyUtopiaVariation`（常规区实托邦：难度 2/6/12 三档概率附加 variation）
   - `initialActionForZone`（层行动力 5/6/7/8/8 + 翅膀节点 + 襁褓天马）、`step` 行动力耗尽自动返回、`generate` 支持模板 action（VI 层 5）
   - `pickTypeByRules` 支持无层类型表的隐藏层（跳过过滤）、`syncMapZones` 支持自定义 mapKey、toJSON 条件输出 portal
2. `app/game/controller/rlv2.ts`：
   - `gridZoneMoveTo` MIRAGE → `createPortalScene`；PROPHECY → `createFateScene`；INCIDENT → `createIncidentScene`（线人）
   - `selectChoice`：portal 分支（_1.._3 消耗加工品进入 / _4 直接 / _5·_6 结束）+ scout 三结局标记 + end1/end2/bomb1 二结局分支
   - `checkZoneEnd`：先行一步干员返回 +2 希望 + 怦然信标（expedEndingRelic 数据驱动）；通过 VI 层 → ending_3；持沙盘不持怦然信标通过 V 层 → ending_2
   - `maxZone`：怦然信标放行 6 层；`hasRelic` 辅助；`startChaosSourceBattle`（混沌源阶理论 ro6_b_5）/`gainPreciousScrap`/`createFateScene`/`createIncidentScene`
   - `generateShopGoods`：随机藏品池排除二结局专属沙盘；`buildShopContent`：Ⅰ-Ⅲ 层行商上架沙盘β（1 源石锭）
3. `app/game/controller/rlv2/inventory.ts`：`SPECIAL_ZONE_AP` handler 生效（增减当前区行动力）
4. `app/game/model/events.ts`：注册 `rlv2:portal:return` 事件
5. 测试：`rlv2-gridzone-portal.test.ts`（新 13 条）、`rlv2-ending-3.test.ts`（新 5 条）、`rlv2-ending-2.test.ts`（新 7 条）、`rlv2-legacy-support.test.ts`（新 8 条：襁褓选项/次数/特勤影像）；`rlv2-modules.test.ts` 更新行动力断言

### P2 变更（2026-08-17 18:50）
- `events.ts`：GAME_INIT_SUPPORT 追加襁褓选项（羽蛇 legacy_04..09 → startbuff_7..12 抽 1）；create() 三头犬（legacy_03）→ 行动奖励选择次数 +1（追加 SUPPORT 事件，仅 supportEnabled 时）
- `rlv2.ts`：gameSettle 难度 ≤3 失败 → record.legacy 记录特勤任务影像（难度 4+ 不记录）；createGame legacy 循环识别 fight_29 → 开局 relic gain
- 踩坑：行动奖励阶段（GAME_INIT_SUPPORT）**仅当 supportEnabled（上一把到 3 层）才出现**——追加 SUPPORT 必须挂在 supportEnabled 分支后，否则无条件多发破坏官服 pending 链（strict-diff/official-replay 抓到）

### P2 分队专属（2026-08-17 18:55）
- `recruit.ts`：`recruit_cost_sub_profession`（本源研修）——CharacterTable 字段为 **`subProfessionId`**（非 subProfession），本源系=primcaster/primprotector/primguard/ritualist（19 名干员实锤），4星+ 希望-2
- `inventory.ts`：MAX_WEIGHT rogue_6 特判 → scrap.limit（多边贸易零件箱容量）；**POOL 分支修复**——原来从池抽出后丢弃（注释掉的发放），pool_scrap_3/6 等池物品无法入库 → 递归 getItem
- `pool.ts`：建 pool_scrap_3/6（GOODS 型废品池，开拓者分队）
- `map.ts`：zone_into_reward/zone_into_cost 的 blackboard[2]（区域限定）可缺失（开拓者分队无限定全区生效，原实现 undefined.value 会崩）
- 遗留：多边贸易"卖 3 零件+8 金"（shop_recycle_reward 就绪，待行商卖出接口）；文明开化（immediate_reward_on_weather_clear，待理想源/天气清除机制）

### 关键数据结论（实锤）
- `variationData` 9 条 = 乌托邦效果表；`gameConst.expedEndingRelic = rogue_6_relic_final_3`（怦然信标）+ `portalZones`（19 隐藏层）；VI 层模板 floor-6-01（起点右侧命运所指=调谐仪式入口）
- **二结局数据**：线人= `scene_ro6_bomb1_enter`（选项 bomb1_1 得沙盘α / _2 珍贵加工品 / _3 离开）；命运所指= `scene_ro6_end1_enter`（好奇心与死：end1_1 消耗 50 源石锭标记 / end1_2 得收藏品）+ `scene_ro6_end2_enter`（窥视箱中：end2_1 找到声音→险路恶敌 / end2_2 离开 → end2_2 场景：end2_3 决战 / end2_4 再找）；混沌源阶理论= `ro6_b_5`

### 踩坑记录
- TypedEventEmitter（Emittery）的 `emit` 是**异步**的：测试中必须 `await emit` 再断言（线人沙盘α 未 await 导致断言失败）；控制器内发奖链尽量 await
- `relic` 为只读 getter（`inventory._relic.relics` 才是存储）；toJSON 严格比对不允许多余键 → portal 状态仅 active 时输出
- VI 层/portal 行动力取模板 `action`（floor-6-01=5、treehole=2），常规层用逐层表——不要一刀切
- 二结局沙盘β会混进随机商店藏品池（SUPER_RARE 档）→ 专属藏品须从 `generateShopGoods` 的 relicPool 排除

### P2（细节完善）
6. **襁褓加成接入行动奖励**：startbuff_7..12 按持有的襁褓追加选项（及选择次数）。
7. **难度 0/4 特勤任务影像**：失败时发放 legacy_10 → 下次开局送【特勤任务影像】。
8. **分队专属逻辑**：本源系招募希望-2（本源研修）、卖出 3 零件奖励（多边贸易）、进区获加工品（开拓者）、消除理想源奖励（文明开化，依赖实托邦）。
9. **初始源石锭** 6 vs 8 核实。

---

## 十二、变更记录（2026-08-19）：节点分发补全 + 主题规则注册表 + bug 修复

> 完整设计说明见 `design-spec.md §16.9`（架构/数据流/安全策略/bug 台账），接口协议见 `api.md`「肉鸽模式 · 黑流树海专属接口」。

### 12.1 节点语义确证（推翻此前的中文名猜测）

官方 `RoguelikeEventType`（`types_excel_gen.ts`）为**位标志枚举**，按声明顺序 2^n 展开后与 `details.rogue_6.nodeTypeData` 的 21 个键**逐一吻合**——每个节点的官方语义由此实锤，不再靠中文名推断。两处此前的误判已纠正：

- `16777216` 官方名为 **EVACUATE**（险路小径），场景 `scene_ro6_evacuate_enter`（三重身，选项 ZONE_END"保留行动力，进入下一区域"）——此前未映射场景；
- `134217728` 官方名为 **BATTLE_SAVAGE**（“居民”据点）→ 应走**战斗**分支（`moduleConsts.savageBubble` 佐证），此前误映射到 `res` 前缀场景；
- `65536` = STORY_HIDDEN（命运所指隐藏变体），与 32768 同名同描述，需一并分发。

`scrapTypeData` 同样以数据为准：**`MOVE` = 加工品**（可用于地图移动 / 误入奇境消耗）、`GOODS` = 自然物、`PASSIVE` = 概念体。~~此前"加工品 = 非 MOVE 型"的注释结论错误~~，见 B9。

### 12.2 主题规则注册表（架构重构）

新增 `app/game/controller/rlv2/theme-rules.ts` 作为主题数据的**单一事实来源**：`ROGUE6_NODE`（21 项）、`ROGUE6_SHOP_NODES` / `ROGUE6_BATTLE_NODES`、`ROGUE6_ZONE_ACTION`、`ROGUE6_NODE_SCENE_PREFIX`、`ROLL_NODE_TYPE_VALUES`、结局关卡/收藏品常量、`isBlackstream(theme)`。原先散落 7 个文件的 20+ 处 `theme === "rogue_6"` 与节点数值字面量全部改为查表。该文件**不 import 任何管理器**（避免循环依赖），`grid_zone.ts` 对外 re-export `ROGUE6_NODE` 保证既有调用方零改动。

### 12.3 bug 修复台账

| # | 现象 | 根因 | 修复 |
|---|---|---|---|
| B1 | 安全的角落/得偿所愿/失与得/**先行一步**等节点进入后无事件（三结局入口不可达） | `triggerNodeEvent()` 定义但**零调用**——rogue_6 走 `gridZoneMoveTo`，只处理战斗/商店/PORTAL/PROPHECY/INCIDENT | 新增 `createRogue6NodeScene(kind)` 按前缀筛 `scene_ro6_*_enter` 并派生选项；删除死方法 |
| B2 | 隐藏层重掷节点无效 | `rerollNode` 用 `zones[zone]` 而非 `zones[zoneKey(zone)]`（rogue_6 为 1000+ 键）；typeMap 缺 11 类 | 改用 `zoneKey`；typeMap 换成 `ROLL_NODE_TYPE_VALUES` |
| B3 | 客户端地图节点状态不刷新 | `gridZone/*` 路由漏传 `takePushMessages()` → `rlv2NodeArrive` 永不下发 | 路由接线 + 控制器累积 `rlv2NodeArrive{nodeType}` / `rlv2NodeChange{nodeList}` |
| B4 | 精英/首领节点打出普通关卡 | `generate()` 算出 `eliteStages` 后未使用 | `ZoneStagePools{normal,elite,boss}` 三池分流 |
| B5 | 多次误入奇境偶发覆盖已生成隐藏层 | 隐藏层键 `3000 + random*900` 可撞键 | `nextPortalZoneKey()` 递增分配；起点 state 与主层统一为 2 |
| B6 | 误入奇境消耗加工品时选错件 | `scrap.gain()` 的 `value` 恒为 1，排序失效 | `sellPriceOf()` 读官方 `goods/move/passiveScrapData.sellPrice` |
| B7 | 全链路 `as any` + 6 处 `sCRAP` 拼写兜底死分支 | `RoguelikeModule` 缺 gridZone/weather/scrap；`CustomizeData` 缺 rogue_5/6 | 从 `types_excel_gen.ts` 复用权威类型并补字段 |
| B8 | 死代码与硬编码 | `NODE_TO_KIND` 零引用、`occupied` Set 未用、`PORTAL_FAMILY` 硬编码 | 删除；`pickPortalTemplate` 改按数据字段 `utopiaPortal(s)` 筛选（该字段实为**雾色场景族编号**，非"节点所在列"） |
| B9 | 误入奇境后零件箱少的是自然物而非加工品 | `consumePortalScrap` 筛 `t !== "MOVE"`，与官方 `scrapTypeData` 语义**颠倒** | 改为 `=== "MOVE"`；消耗的若是当前载具则切回步行 |

附带修复：`scrap/loseScrap` 缺 `instId` 由静默 no-op 改为返回 `result: 1`；`gridZone/moveTo` 校验 route 非空数组。

### 12.4 验证结果

- `pnpm exec tsc --noEmit` 通过；
- 新增 `tests/unit/controller/rlv2-node-dispatch.test.ts`（21 条）覆盖 B1/B2/B3/B4/B6 与注册表一致性（含"21 项节点数值与官方 nodeTypeData 键集合完全相等"断言）；
- 全量 `pnpm exec vitest run`：1957 passed；2 个失败（`pay-gate`、`plugin-config-service`）经 `git stash` 复核为**改动前既有**，与本次无关。

### 12.5 仍待办

- 实践者列表模式（MONTH_TEAM 强制转 NORMAL，专属 init 条目永不命中）；
- 文明开化分队（`immediate_reward_on_weather_clear`，依赖理想源/天气清除机制）；
- 三结局调谐仪式提交（final_4/5/6 削弱效果在客户端战斗内，服务端仅保证节点通行）；
- 难度 3「险路尽头不再提前揭示」无显式分支。
