# DoctorateTs 目录重组设计：特性切片（Feature-First Slices）

- 日期：2026-08-28
- 状态：已与用户逐节确认，待最终审阅
- 范围：`app/` 全部 + 仓库根目录；`scripts/`、`tests/` 结构、`hook/`、`docs/` 不在范围内（tests 仅允许机械改写 import 行）
- 迁移策略：一次性大迁移（git mv + 批量 import 重写 + 集中验证）

## 1. 背景与痛点

用户认定的三个核心痛点（按优先级）：

1. **加新功能不知道往哪放**——三种组织模式并存，无统一落位规则
2. **模块边界模糊、耦合重**——跨模块引用无约束，`domain → service` 反向依赖 8+ 处
3. **文档与代码脱节**——AGENTS.md 宣称的 DDD 分层与实际不符

现状证据（2026-08-28 实测）：

| 事实 | 数据 |
|---|---|
| 三套模式并存 | `service/player/` Manager 模式（25 文件）；`domain/<mod>/` 特性包模式（handler+logic+trigger，5 模块）；`domain/router/` 集中路由模式（34 文件） |
| domain 不纯 | domain 263 个 TS 文件 vs service 37 个；路由、HTTP handler、业务 logic 大头都在 domain；`domain/activity/<family>/router.ts` 24 个活动路由全在 domain |
| 文档偏差 | AGENTS.md 称活动路由在 `service/activity/<family>/`，实际在 `domain/activity/<family>/` |
| 热点文件 | `service/player/medal.ts` 3324 行、`AdminService.ts` 2845 行、`excel.ts` 2062 行、`router/user.ts` 1062 行 |
| 根目录杂物 | `index.ts` 35KB（CLI 解析+启动编排+看门狗+REPL 混杂）、`player_data.json` 4.4MB（未跟踪）、`app/config.ts` 与 `app/config/` 同名并存 |

## 2. 目标与非目标

**目标**

- 唯一落位规则：新功能 = 找到业务模块包，包内自含 routes/manager/rules
- 模块边界可被架构守卫测试机器强制
- 文档（AGENTS.md）与结构一致，且有守卫兜底防再漂移
- `app/` 顶层职责归组：core（基础设施）/ game（业务）/ ops（运营设施）

**非目标（明确不做）**

- 不拆任何巨石文件的**内容**（medal.ts 3324 行原样搬入模块包，拆分是后续独立任务）
- 不改模块/目录命名（只搬家不改名；仅新增范式要求的约定文件 `routes.ts`/`public.ts`）
- 不改数据格式、协议行为、`data/`、`tmp/` 目录布局
- 不重组 `tests/`、`scripts/` 目录结构
- 不引入新依赖（守卫测试沿用现有 file-size-guard 的静态扫描模式）

## 3. 目标结构

```
app/
  core/                    # 基础设施内核：被依赖，永不依赖 game/ops
    config/  db/  logs/  utils/  auth/
  game/
    kernel/                # 玩家组合根 + 横切能力（详见 §5.1）
      events/              #   EventMap 契约 + 运行时总线
      http/                #   路由契约基建（validateBody/errors/common，原 domain/contracts/）
      inventory-pipeline.ts
      PlayerDataManager.ts  PlayerStatus.ts  player-composition.ts  ...
    excel/                 # 游戏数据基础设施（原 service/excel，含生成类型，不动）
    modules/               # 业务特性切片：一模块一目录（详见 §5.2）
      <mod>/
        routes.ts          #   薄路由：声明 + validateBody，不做业务
        manager.ts         #   状态与业务（可沿用现有文件名，如 medal.ts）
        rules.ts           #   纯函数规则 / 类型 / schema（可拆多文件，包内自由）
        public.ts          #   唯一对外出口
      activities/          #   24 个活动族 + 共享层
        <family>/          #     router.ts + logic.ts + ...（族内自含）
        shared/            #     unlockActivity、activity.ts 等活动族共享逻辑
    routes.ts              # 仅聚合注册（懒加载 import，不动机制）
    app.ts                 # Express 中间件装配（不动）
  ops/                     # 服务器运营设施：依赖 core，经 public.ts 依赖 game
    admin/  capture/  proxy/  updater/  plugin/  assets/
  server.ts                # 原 index.ts 启动编排（中间件/路由挂载/看门狗/后台更新/REPL）
index.ts                   # 根入口：仅 CLI 参数解析（~100 行），调 app/server.ts
```

## 4. 落位与边界规则

1. **落位规则（唯一）**：新功能 = 找到它的业务模块；没有就在 `modules/` 下建包。`domain/`、`service/` 目录名废止。
2. **对外出口**：`modules/A` 只允许 import `modules/B/public.ts` 导出的纯函数/类型；跨模块异步协作走事件总线（EventMap）。activities 族间共享走 `activities/shared/`。
3. **依赖方向**：`core` ← 被 `game`、`ops` 依赖，反向禁止；`game/kernel`、`game/excel` 禁止 import `modules`；`ops` 可依赖 `core` 与 `game` 模块的 `public.ts`。
4. **路由位置**：仅 `modules/<mod>/routes.ts`、`activities/<family>/router.ts`；`domain/router/` 集中地消失。
5. **文件上限**：沿用 1500 行守卫（file-size-guard）。
6. 以上规则由守卫测试强制（§7），并同步写入 AGENTS.md。

## 5. 迁移映射表

### 5.1 game/kernel/（组合根与横切能力）

| 现路径 | 新路径 |
|---|---|
| `service/PlayerDataManager.ts` | `kernel/PlayerDataManager.ts` |
| `service/PlayerStatus.ts` | `kernel/PlayerStatus.ts` |
| `service/player-composition.ts` | `kernel/player-composition.ts` |
| `service/events.ts` + `domain/events/` | `kernel/events/`（契约与总线合一） |
| `domain/contracts/`（common/errors/validate-body） | `kernel/http/` |
| `game/resp-schema.ts`、`game/request-context.ts`、`game/auth-strategy.ts` | `kernel/http/` |
| `service/player/inventory-pipeline.ts` | `kernel/inventory-pipeline.ts` |
| `service/player/inventory.ts` | `kernel/inventory.ts`（实测消费者：admin + rlv2 + 组合根，横切） |
| `domain/playerdata.ts` | `kernel/playerdata.ts` |
| `domain/shared/model.ts` | `kernel/model.ts` |
| `domain/util/random.ts`、`domain/util/multipart.ts`、`domain/util/stage-unlock.ts`、`domain/util/maxout.ts` | `kernel/util/`（stage-unlock 实测消费者为 battle 与 unlockActivity；maxout 唯一消费者是 ops/admin 网关，均按 §5.3 规则归 kernel） |
| `service/util/save-health.ts` | `kernel/save-health.ts` |
| `service/excel/` | `excel/`（生成类型随包；`scripts/generate-types.ts:41-42` 的 `PLAYERDATA_OUT`/`EXCEL_OUT` 输出常量同步改指新路径——这是 scripts/ 范围外仅有的两行路径常量修改） |

`game/app.ts`、`game/routes.ts` 留在 `game/` 根不动（Express 装配与路由聚合）。

### 5.2 game/modules/（业务模块）

| 目标模块包 | 来源 |
|---|---|
| `user/` | `domain/router/user.ts`、`service/player/freshPlayer.ts`、`service/player/status.ts` |
| `account/` | `domain/account/`、`domain/router/account.ts`、`service/player/AccountManager.ts` |
| `character/` | `domain/character/`、`domain/router/charBuild.ts`、`domain/router/charRotation.ts`、`service/player/char.ts`、`service/player/charRotation.ts`、`service/player/troop.ts`、`domain/util/char-skills.ts` |
| `battle/` | `service/player/battle.ts`、`service/player/BattleStore.ts`、`service/player/BattleInfoStore.ts`、`domain/shared/battle-model.ts` |
| `gacha/` | `domain/gacha/` 全包、`service/player/recruit.ts`、`domain/util/gacha-up-list.ts` |
| `building/` | `domain/building/` 全包 |
| `mission/` | `domain/mission/` 全包（templates/ 随包） |
| `shop/` | `domain/shop/` 全包 |
| `roguelike/` | `domain/rlv2/` 全包、`domain/router/roguelike.ts`、`domain/shared/rlv2-model.ts` |
| `sandbox/` | `domain/sandbox/`、`domain/router/sandbox.ts` |
| `crisis/` | `domain/crisis/`、`domain/router/crisis.ts`、`service/shared/crisis-seasons.ts` |
| `pay/` | `domain/pay/`、`domain/router/pay.ts`、`service/shared/pay-store.ts`、`domain/util/purchase-record.ts` |
| `mail/` | `domain/mail/`、`domain/router/mail.ts`、`domain/router/mailCollection.ts`、`service/player/mail.ts` |
| `social/` | `domain/social/`、`domain/router/social.ts`、`service/player/social.ts`、`service/player/SocialService.ts`、`domain/shared/social-model.ts` |
| `medal/` | `service/player/medal.ts` |
| `checkin/` | `service/player/checkin.ts`、`domain/activity/checkin/` |
| `retro/` | `domain/retro/`、`domain/router/retro.ts`、`service/player/retro.ts` |
| `storyreview/` | `domain/storyreview/`、`domain/router/storyreview.ts`、`service/player/storyreview.ts` |
| `home/` | `domain/home/`、`domain/router/home.ts`、`service/player/home.ts` |
| `depot/` | `domain/depot/`、`domain/router/depot.ts` |
| `aprilFool/` | `domain/aprilFool/`、`domain/router/aprilFool.ts`、`service/player/aprilFool.ts` |
| `arkodc/` | `domain/arkodc/`、`domain/router/arkodc.ts` |
| `autochess/` | `domain/autochess/`、`domain/router/autochess.ts` |
| `businessCard/` | `domain/businessCard/`、`domain/router/businessCard.ts` |
| `campaignV2/` | `domain/campaignV2/`、`domain/router/campaignV2.ts` |
| `charm/` | `domain/charm/`、`domain/router/charm.ts`、`domain/activity/charm/` |
| `deepsea/` | `domain/deepsea/`、`domain/router/deepsea.ts` |
| `explore/` | `domain/explore/`、`domain/router/explore.ts` |
| `interlock/` | `domain/interlock/`、`domain/router/interlock.ts`（`activity/interlockRefresh/` 留在 activities） |
| `misc-alignment/` | `domain/misc-alignment/`、`domain/router/misc-alignment.ts` |
| `multiplayer/` | `domain/multiplayer/`、`domain/router/multiplayer.ts` |
| `quest/` | `domain/quest/`、`domain/router/quest.ts` |
| `rune/` | `domain/rune/`、`domain/router/rune.ts` |
| `siracusaMap/` | `domain/siracusaMap/`、`domain/router/siracusaMap.ts` |
| `templateShop/` | `domain/templateShop/`、`domain/router/templateShop.ts` |
| `tower/` | `domain/tower/`、`domain/router/tower.ts` |
| `vecbreak/` | `domain/vecbreak/`、`domain/router/vecbreak.ts` |
| `dexnav/` | `service/player/dexnav.ts` |
| `dungeon/` | `service/player/dungeon.ts` |
| `equipmentMission/` | `service/player/equipmentMission.ts` |
| `system/` | `domain/router/audit.ts`、`domain/router/plugin-heartbeat.ts`（系统级杂项协议） |

`modules/activities/`：`domain/activity/` 下 24 个族目录原样平移；`domain/activity/activity.ts`（948 行共享逻辑）→ `activities/shared/`；`service/player/unlockActivity.ts` → `activities/shared/`（实测消费者为 act24side/bossRush/checkin 三个族 + admin）；`domain/data/vhalfidle.ts` → `activities/act1vhalfidle/`（唯一消费者，实测）。

注：`domain/contracts/` 是路由契约基建（validateBody/errors/common），已归 `kernel/http/`（§5.1），不构成业务模块。

### 5.3 散件归属裁决规则

迁移脚本生成逐文件映射后，凡本表未列出的文件按以下顺序裁决（实施计划第一步执行并人工复核异常项）：

1. 唯一消费者是某模块 → 随该模块
2. 消费者 ≥2 且属于横切能力 → `kernel/`
3. 消费者 ≥2 且属于活动族共享 → `activities/shared/`
4. 仅测试引用 → 随其被测模块

### 5.4 app/ 顶层与根目录

| 现路径 | 新路径 |
|---|---|
| `app/config/` + `app/config.ts` | `app/core/config/`（合一） |
| `app/db/` | `app/core/db/` |
| `app/logs/` | `app/core/logs/` |
| `app/utils/` | `app/core/utils/` |
| `app/auth/` | `app/core/auth/` |
| `app/admin/` | `app/ops/admin/` |
| `app/capture/` | `app/ops/capture/` |
| `app/proxy/` | `app/ops/proxy/` |
| `app/updater/` | `app/ops/updater/` |
| `app/plugin/` | `app/ops/plugin/` |
| `app/asset-registry/` + `app/asset.ts` + `app/asset-backfill.ts` | `app/ops/assets/`（三合一） |
| `index.ts`（35KB） | 根 `index.ts` 仅留 CLI 解析；其余 → `app/server.ts` |
| `player_data.json`（4.4MB，未跟踪） | 本地移入 `data/`（不涉及 git） |

别名：现有 `@game`、`@excel`、`@utils`、`@capture`、`@logs` 名称不变，目标路径随 §5.1/§5.4 映射同步 retarget（`@excel`→`app/game/excel`、`@utils`→`app/core/utils`、`@capture`→`app/ops/capture`、`@logs`→`app/core/logs`）；另新增 `@core/*`、`@ops/*`。tsconfig.json 与 vitest.config.mts 两处同步。

## 6. 已确认的归并判断（用户已认可）

- `service/player/recruit.ts`（公招）→ `modules/gacha/`：与寻访共用 `resolveGachaRank` 保底纯函数
- `service/player/troop.ts`（编队）→ `modules/character/`：与 char/charBuild 同属干员域
- `service/player/freshPlayer.ts`（新手开档）→ `modules/user/`：开档流程属于玩家档案域
- 目标范式：特性切片（方案 A）；迁移策略：一次性大迁移

## 7. 架构守卫测试

新增 `tests/unit/architecture/module-boundary.test.ts`（沿用 file-size-guard 的文件扫描模式，零新依赖）：

- R1：`app/core/**` 禁止 import `@game/*`、`@ops/*`
- R2：`app/game/kernel/**`、`app/game/excel/**` 禁止 import `app/game/modules/*`
- R3：`modules/A` import `modules/B` 时，B 侧路径必须是 `public.ts`（activities 族对 `activities/shared/` 免检）
- R4：含 `router` Express 挂载的文件仅限 `modules/*/routes.ts`、`activities/*/router.ts`、`game/routes.ts`
- R5：保留并继续执行 1500 行文件上限

守卫上线时暴露的存量越界 import：逐个修复；确属暂时无法解耦的，在测试内维护显式豁免清单（文件名 + 原因），禁止空泛豁免。

## 8. 迁移步骤与验证

前置：`app/asset.ts` 的未提交修改先由用户处置（提交或暂存），迁移在干净工作树上进行。

1. **别名准备**：tsconfig.json + vitest.config.mts 新增 `@core/*`、`@ops/*`（`@excel`/`@utils`/`@capture`/`@logs` 的 retarget 分别随 commit 1 / commit 2 落地）
2. **core + ops 迁移**（commit 1）：git mv §5.4 各项；脚本按映射表重写 import；`tsc --noEmit` + `vitest run` 绿
3. **game 迁移**（commit 2）：按 §5.1–5.3 git mv；生成逐文件映射表（含散件裁决）；批量重写全仓 import（含 `tests/**` 的 `@game/domain|service/*` 行——tests 目录结构与用例逻辑不动）；路由懒加载 `await import(...)` 路径同步；`tsc --noEmit` + `vitest run` 绿
4. **守卫上线**（commit 3a）：新增 module-boundary 测试，清理越界 import
5. **文档收口**（commit 3b）：重写 AGENTS.md Architecture/Conventions 节；design-spec.md 中目录相关章节同步修订
6. **端到端冒烟**：`pnpm run start:quick` 起服 → 登录 + syncData + 寻访 + 商店购买 + admin dashboard 打开 + 日志 Tab SSE 出流；`start:capture` 模式起服确认 capture 管道正常

运行时路径核查（步骤 2/3 中执行）：全仓 grep `__dirname`、`import.meta.url`、`process.cwd()`，确认无按代码目录定位的资源路径（数据路径均应位于 `data/`、`tmp/`）。

## 9. 风险清单

| 风险 | 缓解 |
|---|---|
| `routes.ts` 懒加载 import 路径漏改 | 映射表驱动重写 + tsc 兜底 + 守卫 R4 校验路由文件位置 |
| 动态拼路径的插件/资源加载（`app/plugin`、admin dashboard 静态资源） | 迁移前后 grep 路径常量并冒烟验证 dashboard |
| tests import 机械改写引入语义漂移 | 仅允许路径前缀替换，禁止改动用例逻辑；tsc + vitest 全量验证 |
| **tests 不在 tsc 检查范围**（tsconfig include 仅 `app/**` + `index.ts`），存在指向已不存在模块的 stale type-only import（实测：`tests/unit/model/battle.test.ts` 引用 `@game/domain/battle`，该文件已不存在，因 type-only import 被 esbuild 剥离而潜伏） | 重写脚本对"旧路径在仓库中无对应文件"的 import 逐条人工裁决重定向，不做盲目前缀替换 |
| 生成类型输出路径失效（excel 迁移后 `scripts/generate-types.ts` 找不到写入目标） | commit 2 内同步更新 `PLAYERDATA_OUT`/`EXCEL_OUT` 常量，并实际运行一次生成器验证输出落点 |
| 一次性迁移中途不可运行 | 按 §8 的 commit 1 / 2 / 3a / 3b 切分，每步验证后推进 |
| `git mv` 后历史追溯断裂担忧 | 全程 git mv（非删除重建），rename 检测可追溯 |

## 10. 成功标准

1. `pnpm exec tsc --noEmit` 零错误
2. `pnpm exec vitest run` 全绿
3. `start:quick` 冒烟通过（§8 步骤 6 清单）
4. `module-boundary.test.ts` 全绿，且对人为越界 import 能报错（负样本自测一条）
5. AGENTS.md 描述与实际目录一一对应；新功能落位规则在 AGENTS.md 中有且只有一种答案
