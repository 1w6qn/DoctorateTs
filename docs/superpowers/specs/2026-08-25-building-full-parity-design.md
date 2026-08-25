# 基建系统全量对齐官服——差距补齐设计

日期：2026-08-25
状态：设计定稿（用户已确认：差距分析+补齐 / 全量对齐官服 / wiki 反推不可考证机制 / 方案A 分批模块化）

## 1. 背景与目标

现有基建系统已覆盖大部分玩法（design-spec.md §11.1~11.12，manager 约 3800 行、60+ 端点、
buff/special 双引擎、电力/信用/订单时间模型）。本次以 **prts.wiki 机制文档 + excel 数据** 为准
做差距分析，将缺失/简化的机制补齐至与官服行为一致（"全量对齐"），不可考证机制按
prts.wiki 玩家实测结论反推并标注来源与置信度。

调研产出（wiki 抓取 10/10 成功）：各设施机制 + 服务端关键常量表，
常量摘要见本文 §10；完整技能表（后勤技能一览/store，5010 行）已调研摘录。

## 2. 差距清单（审计结论）

| # | 缺口 | 现状 | 官方行为（来源） |
|---|---|---|---|
| G1 | 配方解锁 | `requireRooms`/`requireStages` 从不校验 | 制造/加工配方按"曾达等级"+关卡2星解锁（制造站页/加工站页） |
| G2 | 专精材料 | 不消耗材料 | `character_table.skills[].levelUpCostCond[].levelUpCost`（excel 在库） |
| G3 | 专精时长阈值 | `processPoint` 无 maxPoint，completeUpgradeTime 无时长约束 | 专一 8h/专二 16h/专三 24h = `lvlUpTime`（excel）；协助位非涣散 +5% + 教官技能（训练室页） |
| G4 | 专精门控 | 无 | 专精上限=训练室等级；全满专精不可进训练位；训练不可中止（训练室页） |
| G5 | 贸易订单概率 | 均匀随机 1~4 赤金 | Lv1 100%×2；Lv2 60/40；Lv3 30/50/20（贸易站页） |
| G6 | 贸易暖机 | 无累积工时建模 | 裁缝α 3h/β 5h 后改概率（4金55/30/15；85/10/5；α+α 65/22/13），离岗清零（贸易站页） |
| G7 | 特殊订单 | 仅佩佩/可露希尔 | 补尤里卡/但书违约/龙舌兰投资（贸易站页，按优先级） |
| G8 | 开采协力策略 | changeStrategy 仅记录 | Lv3 源石碎片×2→20合成玉，2:00:00（贸易站页） |
| G9 | 注意力涣散 | buff.ts 无 ap 检查 | 心情 0 时技能/基础效率失效（基建主页） |
| G10 | 头数心情减免 | 无 | 制造/贸易 2人-0.05、3人-0.1 /时（制造站/贸易站页） |
| G11 | 办公室联络 | `_accrueHire` 仅累积 processPoint 供显示 | 12h/次、进驻+5%、人脉库存上限3、满则停工；供给公开招募标签刷新（办公室页） |
| G12 | refreshTags 打通 | 刷新无消耗来源 | 标签刷新消耗人脉资源（办公室页） |
| G13 | 会客室线索速度 | 相位×buff | 107/109/111% + 氛围档(≥2000/3000/4000 → +5/10/15%) + 稀有度(4★2/5★4/6★5%) + 精英(精1 8%/精2 16%) + 非涣散5%/人（会客室页） |
| G14 | 进度真实产线索 | 进度仅显示 | 20h 基准进度满 → 产线索；自有库上限10，满则停工（会客室页） |
| G15 | 宿舍恢复拆分 | /160 + /1000×0.55（总和吻合、拆分不一致） | (1.5+0.1×lv) + 0.0004×氛围（宿舍页） |
| G16 | 宿舍特殊技能 | 未建模 | 自律（恢复隔离）/患难之交（心情互换，需进驻顺序）/嗜睡慵懒/小酌怡情（均分）/单体恢复（锁定最低）/同种取最高（宿舍页+技能表） |
| G17 | buyLabor | 恒 1 源石/+10 | excel 常量 `apToLaborUnlockLevel=4`（控制中枢 Lv4 解锁 AP 兑换）、`apToLaborRatio=2` |
| G18 | 副手信赖定时 | 手动接口 | 每日 4:00/16:00 产生待收取：进驻≤100、中枢副手≤500、楼层副手≤125，按氛围折算，未收取覆盖（控制中枢页/信赖值） |
| G19 | 无人机 | 不建模 | **审计修订**：客户端协议无急速充能/持有点端点，官服存档无无人机字段（11.7 反编译确认）→ 官方行为为客户端本地推算；服务端对齐 = 加速请求的"3分钟/架"效果语义（§5.4） |

## 3. 总体架构

沿用 `buff.ts`/`special.ts` 分层：**纯函数引擎（可单测、无 IO）→ BuildingManager 薄接线**。
新机制拆独立模块于 `app/game/building/`，不再膨胀 manager。

| 模块 | 职责 | 接线点 |
|---|---|---|
| `mood.ts` | 涣散判定、暖机工时、头数减免 | 被各引擎调用；`assignChar` 维护 warmup |
| `unlocks.ts` | 配方/房间解锁判定 + 曾达等级追踪 | changeManufactureSolution / workshopSynthesis / changeSaleSolution |
| `mastery.ts` | 专精材料/时长/门控 | upgradeSpecialization / completeUpgradeSpecialization / _accrueTraining |
| `trade-orders.ts` | 订单概率/暖机/特殊订单 | _genTradingOrder |
| `hire-contacts.ts` | 联络进度→人脉库存 | _accrueHire / gacha refreshTags |
| `clue-speed.ts` | 线索速度全公式+真实产出 | _accrueMeeting / dailyRefresh |
| `dorm-special.ts` | 宿舍特殊技能+恢复公式 | _dormRecoveryPerSec / _recomputeCharScales |

**6 批执行顺序**（按依赖）：
① `mood.ts` 基座 → ② `unlocks.ts`+`mastery.ts` → ③ `trade-orders.ts` →
④ 加速效果语义（G19）→ ⑤ `hire-contacts.ts`+`clue-speed.ts` →
⑥ `dorm-special.ts`+buyLabor+副手信赖。
每批独立单测 + `tsc` 干净 + 存量基建测试（224 条）不回归。

## 4. 批次①：通用基座 mood.ts

- **涣散判定**：`isDispersed(charSrc) = (ap ?? 上限) <= 0`（AP raw，24 点 = 24×360000）。
  `getActiveCharBuffs` 增加 `skipDispersed` 开关，生产/贸易/线索/训练等加成链路启用；
  加工站副产物（wiki：涣散不产副产物）同步启用。**宿舍恢复不受涣散影响**（休息中）。
- **暖机工时**：存档扩展 `building.chars[instId].warmupSec`（服务端扩展字段，
  参照 playerdata-server-adapt `addFields` 先例；`_advanceBuilding` 按在岗累加，
  `assignChar`/`cleanRoom*` 撤出清零）。提供 `warmupHours(charSrc)` 供③⑥使用。
- **头数心情减免**：`_recomputeCharScales` 制造/贸易分支按在岗人数减
  0.05(2人)/0.1(3人) 点/时 = 5/10 raw AP/秒（1 点 = 360000/3600 = 100 raw/秒）。

## 5. 批次②：配方解锁 + 专精

### 5.1 曾达等级（G1）
- 服务端扩展 `building.maxLevelReached: { [roomId]: number }`（不落线格式，
  存档内自洽）；`buildRoom`(=1)/`upgradeRoom`/`completeUpgradeRoom` 取 max 更新；
  `degradeRoom` 不回退。
- `unlocks.ts#isFormulaUnlocked(formula, ctx)`：
  - `requireRooms[]`：`maxLevelReached[roomId] >= roomLevel` 且当前该类型房间数 ≥ `roomCount`；
  - `requireStages[]`：`dungeon.stages[stageId].completeState >= 3`（≥2星；
    语义对照 design-spec §12 completeState 2/3=胜利，实现时以真实存档再校准）。
- 接线：`changeManufactureSolution`/`workshopSynthesis`（配方选择）未解锁 → 拒绝（不扣资源、空 delta）；
  `changeSaleSolution` 校验 `tradingStrategyUnlockLevel`（开采协力 Lv3）。

### 5.2 专精（G2/G3/G4）
- `upgradeSpecialization`（非 timeZero 路径）：
  1. 门控：干员 `evolvePhase==2`、目标技能 `skillLevel==7`（满级）、
     `specializeLevel < 训练室等级` 且 `< 3`；训练室已有他人训练 → 拒绝；全技能满专精不可进训练位；
  2. 消耗 `levelUpCostCond[specializeLevel].levelUpCost`（足额校验后扣，复用 `_applyItemDelta`）；
  3. `trainee.state=1`、`speed = 1 + (协助位非涣散 ? 0.05 : 0) + train_* buff`、
     写 `maxPoint = lvlUpTime`（秒）、`processPoint=0`、`completeUpgradeTime = now + lvlUpTime/speed`。
- `_accrueTraining`：`processPoint += elapsed × speed（实时重算）`；达到 `maxPoint` → `state=2`（OUTOFDATE 待领取）。
- `completeUpgradeSpecialization`：仅 `state==2` 可领取（或 timeZero 配置路径）。
- 训练锁：训练位干员（`trainee.charInstId`）拒绝被 `assignChar` 派往其他房间；不可中止（无取消端点，官方语义）。

## 6. 批次③：贸易订单模型

- **概率表**（`trade-orders.ts`，常量来自贸易站页）：
  - Lv1：{2金:100%}；Lv2：{2:60%,3:40%}；Lv3：{2:30%,3:50%,4:20%}
  - 暖机改写（有裁缝/手工艺品类技能且 `warmupHours ≥ 阈值`）：
    α(3h)：{4:55,3:30,2:15}；β(5h)：{4:85,3:10,2:5}；α+α：{4:65,3:22,2:13}；α+β：按 β。
  - `gain.count = 赤金数 × getGoldRate()`；特殊订单按 11.10 既有优先级扩展：
    佩佩 > 可露希尔 > 尤里卡（报酬与赤金数同步）> 但书（α +1金+500/β +2金+1000）> 龙舌兰（α +250/β +500 币）。
- **暖机判定**：读批次①的 `warmupHours`；换站/撤出清零（①已保证）。
- **开采协力**（G8）：`strategy==="O_DIAMOND"` 且站级 ≥3 → 订单
  `delivery 源石碎片(3141)×2 → gain 合成玉(4002)×20`，基础获取时间 2h（`next.maxPoint` 语义内）。
- 订单上限按站级 6/8/10：`_refreshTradingOrders` 补单上限改读站级（现为恒定）。

## 7. 批次④：加速效果语义（G19）

- **结论**：无人机持有/充能为客户端本地状态（无服务端端点、无存档字段），服务端不建模持有量——
  与官服行为一致；急速充能不实现（客户端无协议）。
- **加速请求语义对齐**（1 架无人机 = 3 分钟进度）：
  - `accelerateSolution`：请求带 `cost` → `processPoint += cost × 180 × 有效生产力速度`
    （等价推进 3min/架），达到阈值即完成该方案；`cost` 缺省保持现有"立即完成 1 方案"
    （私服兼容旧客户端，文档记录）。
  - `accelerateOrder`：保持"立即完成订单"（官方无按架数加速单笔订单的独立语义暴露给服务端）。
- 文档更新：§11.7"加速免费"表述修订为"无人机持有为客户端状态，服务端按请求 cost 推进"。

## 8. 批次⑤：人力办公室 + 会客室

### 8.1 办公室（G11/G12）
- `_accrueHire`：有效速度 = `resSpeed/100 × (1 + 0.05(进驻基础) + hire_* buff)`；
  每累积 12h（43200s）基准进度 → 人脉库存 +1；**上限 `refreshTimes=3`，满则停止累积**（房间保留 `refreshStock` 字段，服务端扩展）。
- `gacha/refreshTags`：优先扣唯一 HIRE 房间 `refreshStock`；库存 0 → 拒绝（空 delta）。
  **私服兜底**：无 HIRE 房间或未进驻 → 免消耗放行（记录为私服友好项，防锁死公开招募）。
- 招募栏位数：检查现有 `gacha` slots 是否含办公室加成（2/3/4），缺则按 `hireData` 等级补。

### 8.2 会客室（G13/G14）
- `clue-speed.ts#meetingSpeedBonus(ctx)`：
  `相位(1.07/1.09/1.11) + 氛围档(5/10/15%) + Σ干员(稀有度 2/4/5% + 精英 8/16% + 非涣散 5%) + meet_* buff`。
  氛围 = 全宿舍 comfort 求和。
- `_accrueMeeting`：`processPoint += elapsed × 速度`；阈值 = 20h×100（基准）→ 达到即产 1 条线索
  （阵营加权复用 `_clueFactionWeighted`，含晓歌/U-Official 权重），`processPoint` 回退阈值；
  **自有库（ownStock）≥10 时停止累积**（满库停工）。

## 9. 批次⑥：宿舍 + 中枢杂项

### 9.1 宿舍（G15/G16）
- 恢复公式对齐：`(1.5 + 0.1×等级) + 0.0004×comfort + 技能`（替换 /160 与 /1000×0.55；
  总和不变、拆分对齐官方——低氛围场景恢复速度变化，属对齐目标）。
- `dorm-special.ts`：数据驱动的宿舍特殊技能表（charId→行为，来源：后勤技能一览/store）：
  - 自律：自身 +2/时 且屏蔽其他恢复源（恢复源隔离标志）；
  - 患难之交：满心情进驻时与宿舍**前一位**进驻干员互换心情（宿舍记录进驻顺序队列）；
  - 嗜睡（自身 -0.1，全体 +0.25）/慵懒（+0.2）——同种取最高；
  - 小酌怡情：+0.8/时均分给未满成员；
  - 单体恢复（慈悲 +0.75 等）：锁定宿舍内心情最低者直至满（记录锁定目标）。
- 全体恢复类按效果桶取 max（与 11.4 控制中枢规则一致）。

### 9.2 中枢杂项（G17/G18）
- `buyLabor`：控制中枢等级 ≥ `apToLaborUnlockLevel`(4) 时，官方路径
  `1 AP → apToLaborRatio(2) 点劳动力`（扣 `status.ap`，钳制 `labor.maxValue`）；
  现有源石路径保留为私服兼容（低等级可用），文档记录。
- 副手信赖：`dailyRefresh`（4:00）与 16:00 边界生成待收取信赖实体
  `building.assistTrust`（服务端扩展）：进驻信赖 = min(100, 总氛围/5000×100)、
  中枢副手 = min(500, 总氛围/5000×500)、楼层副手 = min(125, 该层宿舍氛围/5000×125)；
  未收取的新周期直接覆盖旧的；`getAssistReport`/领取接口合并发放（复用 `_addFavor`）。
  副手名单读 `setBuildingAssist` 已存的 assist 配置。

## 10. 数据与兼容性约定

- **存档格式**：除已声明的服务端扩展字段（`warmupSec`、`maxLevelReached`、HIRE `refreshStock`、
  `assistTrust`）外不新增线格式字段；扩展字段经 playerdata-server-adapt `addFields` 清单登记，
  旧存档惰性初始化（缺失→默认值）。
- **数值来源**：wiki 数值标注页源；excel 在库数值直接引用（`building_data.json` 常量：
  `apToLaborRatio=2`、`apToLaborUnlockLevel=4`、`hireData.phases[].refreshTimes=3`、
  `dormData.phases[].manpowerRecover=160~200`、`tradingStrategyUnlockLevel` 等）。
- **置信度**：贸易 α+α 叠加概率（65/22/13）为玩家实测（中置信）；副手信赖氛围折算曲线
  wiki 未给公式，采用线性折算（低置信，实现时以真实存档/抓包再校准）；宿舍特殊技能表
  按技能表描述逐一核对（高置信）。
- **响应契约**：不变——`res.send(player.delta)`，单请求单次读 `delta`；拒绝类操作空 delta。

## 11. 测试策略

- 每批新增 `tests/unit/manager/building-<topic>.test.ts`，镜像 `app/` 布局；
  引擎纯函数直测 + manager 集成经 `advance(seconds)`/注入 ts 的 `_advanceBuilding` 推进时间（11.9 模式，无需 mock 时钟）。
- 每批完成门槛：新测试通过 + `pnpm exec tsc --noEmit` 干净 + 存量基建测试（现 224 条）全绿。
- 关键场景清单（非穷尽）：涣散干员不计加成；暖机 3h 前后订单概率分布；配方未解锁拒绝；
  专精材料不足拒绝/足额消耗/8h 后待领取/训练锁；人脉满3停工/刷新扣库存；线索满库停工/
  20h 产出；自律恢复隔离；buyLabor 双路径；副手信赖覆盖逻辑。

## 12. 非目标（明确不做）

- 无人机持有量/充能进度服务端建模（G19 审计：官方即客户端本地）。
- 客户端建造加速（建造等待 `buildCost.time` 维持现状——请求协议无无人机字段）。
- 中间产物体系（感知信息/思维链环等宿舍技能转化链，技能表 §6 类——超出本次范围，后续单独立项）。
- 活动室（客户端/活动侧设施，协议未暴露服务端语义）。
