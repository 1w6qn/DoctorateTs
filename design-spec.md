# DoctorateTs 项目设计规范

## 目录
1. [项目概述](#1-项目概述)
2. [目录结构规范](#2-目录结构规范)
3. [TypeScript编码规范](#3-typescript编码规范)
4. [路由设计规范](#4-路由设计规范)
5. [数据模型设计规范](#5-数据模型设计规范)
6. [设计模式和架构原则](#6-设计模式和架构原则)
7. [工具和配置规范](#7-工具和配置规范)
8. [启动模式与离线支持](#8-启动模式与离线支持)
9. [管理后台设计规范](#9-管理后台设计规范)
10. [好友系统与 SQLite 数据层](#10-好友系统与sqlite数据层)
11. [基建系统逻辑说明](#11-基建系统逻辑说明)
12. [战斗结算后处理逻辑](#12-战斗结算后处理逻辑)
13. [勋章系统实现](#13-勋章系统实现)
14. [任务系统实现](#14-任务系统实现)
15. [官服数据迁移](#15-官服数据迁移)
16. [集成战略 rlv2 接口补全](#16-集成战略-rlv2-接口补全)
17. [子域名分发与远程配置](#17-子域名分发与远程配置)
18. [助战系统](#18-助战系统)

---

## 1. 项目概述

### 1.1 项目定位
DoctorateTs 是一个基于 Express 框架的 Node.js 服务器应用，用于模拟明日方舟（Arknights）游戏的后端服务。

### 1.2 技术栈
- **框架**: Express 5.0
- **语言**: TypeScript 5.5
- **状态管理**: Immer 10.1
- **数据存储**: JSON 文件
- **工具**: ts-node、nodemon、eslint、prettier

### 1.3 核心特性
- 使用 Immer 进行状态管理，支持增量更新和撤销操作
- 所有游戏配置数据存储在 JSON 文件中，运行时加载为只读数据表
- 支持自动更新游戏数据和生成类型定义文件
- 支持完全离线启动模式（`--offline`），零网络操作，启动前校验本地数据完整性

---

## 2. 目录结构规范

### 2.1 整体结构
```
DoctorateTs/
├── app/                    # 应用核心代码
│   ├── auth/               # 认证模块
│   ├── config/             # 配置模块
│   ├── excel/              # Excel 数据表管理
│   ├── game/               # 游戏核心逻辑
│   │   ├── controller/     # 控制器层
│   │   ├── manager/        # 管理器层
│   │   ├── model/          # 数据模型层
│   │   └── router/         # 路由层
│   └── utils/              # 工具函数
├── data/                   # 数据文件
│   ├── announce/           # 公告数据
│   ├── crisis/             # 危机合约数据
│   ├── crisisV2/           # 危机合约V2数据
│   ├── excel/              # Excel 数据表
│   ├── gacha/              # 抽卡数据
│   ├── rlv2/               # 肉鸽V2数据
│   ├── shop/               # 商店数据
│   ├── tower/              # 爬塔数据
│   └── user/               # 用户数据
├── hook/                   # Frida hook 脚本
├── scripts/                # 脚本工具
└── .trae/specs/            # 设计规范文档
```

### 2.2 目录职责说明

| 目录 | 职责 | 文件组织方式 |
|------|------|-------------|
| `app/auth/` | 用户认证逻辑，处理登录、Token验证等 | 单文件模块 |
| `app/config/` | 应用配置，包括端口、环境变量等 | 按环境分离配置文件 |
| `app/excel/` | Excel数据表管理，加载和提供游戏配置数据 | 每个数据表对应一个文件或类属性 |
| `app/game/controller/` | 业务控制器，处理复杂业务逻辑 | 按功能模块划分 |
| `app/game/manager/` | 管理器层，协调子系统的数据操作 | 每个子系统对应一个管理器 |
| `app/game/model/` | 数据模型定义，包括玩家数据结构 | 按数据类型划分 |
| `app/game/router/` | 路由定义，处理HTTP请求和响应 | 每个功能模块对应一个路由文件 |
| `app/utils/` | 通用工具函数，包括文件操作、加密等 | 按功能划分工具模块 |
| `data/excel/` | 游戏配置数据表，JSON格式 | 与Excel类属性一一对应 |
| `data/user/` | 用户数据存储，包括玩家数据和配置 | 按用户ID划分文件 |
| `scripts/` | 脚本工具，包括数据更新、类型生成等 | 每个脚本对应一个功能 |

---

## 3. TypeScript编码规范

### 3.1 命名约定

| 类型 | 规范 | 示例 |
|------|------|------|
| 接口 | PascalCase | `PlayerDataModel`, `CharacterData` |
| 类 | PascalCase | `PlayerDataManager`, `Excel` |
| 枚举 | PascalCase | `ItemType`, `Rarity` |
| 类型别名 | PascalCase | `ServerItemTable`, `FriendDataWithNameCard` |
| 属性/方法 | camelCase | `playerData`, `updatePlayerData` |
| 私有属性 | 下划线前缀 + camelCase | `_playerdata`, `_changes` |
| 常量 | UPPER_CASE_SNAKE_CASE | `MAX_AP`, `DEFAULT_PORT` |
| 文件 | kebab-case | `player-data-manager.ts`, `game-data-const.ts` |

### 3.2 类型定义规范

#### 3.2.1 接口定义
- 使用 `interface` 定义数据结构
- 接口命名使用 PascalCase
- 字段命名使用 camelCase
- 对于不确定的类型，使用 `any` 但需谨慎

```typescript
export interface PlayerStatus {
  nickName: string;
  level: number;
  exp: number;
  flags: { [key: string]: number };
}
```

#### 3.2.2 枚举定义
- 使用 `enum` 定义枚举类型
- 枚举名称使用 PascalCase
- 枚举值使用 UPPER_CASE_SNAKE_CASE

```typescript
export enum ItemType {
  MATERIAL = 1,
  CONSUMABLE = 2,
  EQUIPMENT = 3,
}
```

#### 3.2.3 类型别名
- 使用 `type` 定义复杂类型或联合类型
- 类型别名名称使用 PascalCase

```typescript
export type ServerItemTable = { [key: string]: ItemData };
export type FriendDataWithNameCard = PlayerSocial & { nameCardId: string };
```

### 3.3 函数结构规范

#### 3.3.1 函数声明
- 必须标注参数类型
- 必须标注返回值类型（除非返回 void）
- 异步函数使用 `async/await`
- 使用 JSDoc 注释描述函数用途

```typescript
/**
 * 获取玩家数据管理器
 * @param uid - 用户ID
 * @returns 玩家数据管理器实例
 */
async getPlayerData(uid: string): Promise<PlayerDataManager> {
  return this.data[uid];
}
```

#### 3.3.2 参数规范
- 参数命名使用 camelCase
- 参数必须标注类型
- 对于可选参数，使用 `?` 标注

```typescript
async setFriendAlias(uid: string, friendId: string, alias?: string): Promise<void> {
  // ...
}
```

#### 3.3.3 返回值规范
- 必须标注返回值类型
- 对于无返回值的函数，标注为 `void`

```typescript
async savePlayerData(uid: string): Promise<void> {
  // ...
}
```

### 3.4 类结构规范

#### 3.4.1 类声明
- 类名使用 PascalCase
- 使用 JSDoc 注释描述类的用途
- 属性在类顶部声明，按功能分组

```typescript
/**
 * 玩家数据管理器类
 * 
 * 作为单个玩家数据的核心管理类，负责协调玩家的所有子系统。
 */
export class PlayerDataManager {
  /** 背包管理器 */
  inventory: InventoryManager;
  /** 队伍管理器 */
  troop: TroopManager;
  
  constructor(playerdata: PlayerDataModel) {
    // ...
  }
}
```

#### 3.4.2 访问修饰符
- 使用 TypeScript 的访问修饰符（public/private/protected）
- 私有属性使用下划线前缀

```typescript
export class PlayerDataManager {
  private _playerdata: PlayerDataModel;
  private _changes: Patch[][];
  
  get uid() {
    return this._playerdata.status.uid;
  }
}
```

#### 3.4.3 Getter/Setter
- 使用 getter 获取私有属性
- 对于计算属性，使用 getter 而非方法

```typescript
get delta() {
  const delta = patchesToObject(
    this._changes.reduce((pre, acc) => acc.concat(pre), []),
    this._playerdata,
  );
  this._changes = [];
  return { playerDataDelta: delta };
}
```

### 3.5 导入导出规范

#### 3.5.1 导入路径
- 使用路径别名 `@excel/*`, `@utils/*`, `@game/*`
- 避免使用相对路径 `../`

```typescript
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { readJson } from "@utils/file";
```

#### 3.5.2 导出方式
- 使用 `export` 导出单个模块
- 使用 `export default` 导出主模块

```typescript
export class PlayerDataManager { /* ... */ }
export default router;
```

---

## 4. 路由设计规范

### 4.1 路由文件结构
- 每个功能模块对应一个路由文件
- 路由文件命名使用 kebab-case

```
app/game/router/
├── account.ts
├── activity.ts
├── gacha.ts
├── home.ts
├── mission.ts
└── shop.ts
```

### 4.2 路由注册方式
- 在 `app/game/app.ts` 中统一注册路由
- 使用动态导入（`await import()`）实现懒加载

```typescript
app.use("/account", (await import("./router/account")).default);
app.use("/activity", (await import("./router/activity")).default);
app.use("/gacha", (await import("./router/gacha")).default);
```

### 4.3 接口实现模式

#### 4.3.1 请求处理
- 使用 Express Router 定义路由
- 使用 `POST` 方法处理所有业务请求
- 通过 `httpContext` 获取玩家数据

```typescript
import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

router.post("/homeTheme/change", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.home.setHomeTheme(req.body);
  res.send(player.delta);
});

export default router;
```

#### 4.3.2 响应格式
- 成功响应包含增量更新数据 `playerDataDelta`
- 额外数据通过扩展对象返回

```typescript
// 基础响应
res.send(player.delta);

// 包含额外数据的响应
res.send({
  items: [],
  ...player.delta,
});
```

#### 4.3.3 错误处理
- 使用 try-catch 捕获异常
- 返回错误信息和错误码

```typescript
router.post("/gacha/draw", async (req, res) => {
  try {
    const player = httpContext.get<PlayerDataManager>("playerData")!;
    const result = await player.gacha.draw(req.body);
    res.send({
      ...result,
      ...player.delta,
    });
  } catch (error) {
    res.status(500).send({ error: (error as Error).message });
  }
});
```

### 4.4 中间件规范

#### 4.4.1 全局中间件
- 在 `app/game/app.ts` 中注册全局中间件
- 顺序：context → bodyParser → auth → routes

```typescript
app.use(httpContext.middleware);
app.use(bodyParser.json());
app.use(async (req, res, next) => {
  // 身份验证逻辑
  next();
});
```

#### 4.4.2 路由中间件
- 对于需要特定权限的路由，使用路由级中间件

```typescript
router.post("/admin/reset", verifyAdmin, async (req, res) => {
  // 管理员操作逻辑
});
```

---

## 5. 数据模型设计规范

### 5.1 PlayerDataModel 结构

#### 5.1.1 核心结构
`PlayerDataModel` 是玩家数据的根对象，包含所有子系统数据：

```typescript
export interface PlayerDataModel {
  dungeon: PlayerDungeon;        // 地牢数据
  activity: PlayerActivity;      // 活动数据
  status: PlayerStatus;          // 状态数据
  troop: PlayerTroop;            // 队伍数据
  inventory: { [key: string]: number };  // 背包数据
  // ...其他子系统
}
```

#### 5.1.2 子系统划分
每个子系统对应一个管理器类：

| 子系统 | 管理器类 | 职责 |
|--------|----------|------|
| inventory | InventoryManager | 管理物品数量 |
| troop | TroopManager | 管理角色和队伍 |
| dungeon | DungeonManager | 管理地牢进度 |
| home | HomeManager | 管理基建和家园 |
| status | StatusManager | 管理玩家状态 |
| checkIn | CheckInManager | 管理签到记录 |
| storyreview | StoryreviewManager | 管理剧情回顾 |
| mission | MissionManager | 管理任务进度 |
| shop | ShopController | 管理商店交易 |

### 5.2 状态管理模式

#### 5.2.1 Immer 使用方式
使用 Immer 的 `createDraft` 和 `finishDraft` 进行不可变状态更新：

```typescript
async update<T>(
  recipe: (draft: WritableDraft<PlayerDataModel>) => Promise<T>,
) {
  const draft = createDraft(this._playerdata);
  const result = await recipe(draft);
  this._playerdata = finishDraft(draft, (patches, inversePatches) => {
    this._changes.push(patches);
    this._inverseChanges.push(inversePatches);
  });
  return result;
}
```

#### 5.2.2 增量更新机制
- 修改数据时自动生成变更补丁（patches）
- 通过 `delta` getter 获取增量更新数据
- 支持撤销操作（通过 inversePatches）

```typescript
get delta() {
  const delta = patchesToObject(
    this._changes.reduce((pre, acc) => acc.concat(pre), []),
    this._playerdata,
  );
  this._changes = [];
  this._trigger.emit("save", []);
  return { playerDataDelta: delta };
}
```

### 5.3 数据持久化

#### 5.3.1 存储方式
- 使用 JSON 文件存储数据
- 玩家数据存储在 `data/user/databases/{uid}.json`
- 用户配置存储在 `data/user/users.json`

#### 5.3.2 保存机制
- 通过事件触发器（TypedEventEmitter）触发保存
- 在数据变更后自动保存

```typescript
this._trigger.on("save", async () => {
  await this.savePlayerData(uid);
});
```

---

## 6. 设计模式和架构原则

### 6.1 设计模式

#### 6.1.1 单例模式
- `AccountManager` 和 `Excel` 使用单例模式
- 通过全局变量导出实例

```typescript
export const accountManager = new AccountManager();
export default new Excel();
```

#### 6.1.2 观察者模式
- 使用 `TypedEventEmitter` 实现事件发布订阅
- 用于数据变更通知和保存触发

```typescript
this._trigger.on("save", async () => {
  await this.savePlayerData(uid);
});

this._trigger.emit("save", []);
```

#### 6.1.3 组合模式
- `PlayerDataManager` 组合多个子管理器
- 通过统一接口访问所有子系统

```typescript
export class PlayerDataManager {
  inventory: InventoryManager;
  troop: TroopManager;
  home: HomeManager;
  // ...
}
```

#### 6.1.4 策略模式
- 不同功能模块使用不同的管理器策略
- 通过接口统一调用方式

### 6.2 架构原则

#### 6.2.1 分层架构
- **路由层（Router）**: 处理HTTP请求和响应
- **控制层（Controller）**: 处理复杂业务逻辑
- **管理层（Manager）**: 协调子系统数据操作
- **模型层（Model）**: 定义数据结构

#### 6.2.2 依赖注入
- 通过构造函数注入依赖
- 管理器之间通过 PlayerDataManager 共享上下文

```typescript
constructor(player: PlayerDataManager, trigger: TypedEventEmitter) {
  this.player = player;
  this._trigger = trigger;
}
```

#### 6.2.3 单一职责
- 每个类只负责一个功能
- 管理器类负责特定子系统的数据操作

#### 6.2.4 不可变状态
- 使用 Immer 确保状态不可变
- 所有数据变更通过 `update` 方法进行

---

## 7. 工具和配置规范

### 7.1 TypeScript 配置
- 使用严格模式（`strict: true`）
- 使用路径别名（`@excel/*`, `@utils/*`, `@game/*`）
- 编译目标为 ES6

```json
{
  "compilerOptions": {
    "module": "commonjs",
    "target": "es6",
    "strict": true,
    "baseUrl": ".",
    "paths": {
      "@excel/*": ["app/excel/*"],
      "@utils/*": ["app/utils/*"],
      "@game/*": ["app/game/*"]
    }
  }
}
```

### 7.2 ESLint 配置
- 使用 TypeScript ESLint
- 使用 Prettier 进行代码格式化
- 遵循推荐规则

### 7.3 脚本命令
- `npm start`: 启动开发服务器（nodemon）
- `npm run build`: 编译 TypeScript
- `npm run update`: 更新游戏数据并生成类型
- `npm run test`: 运行测试
- `npm run update -- --offline`: 以完全离线模式校验本地数据完整性（不联网）
- 启动参数：`--offline` / `-o`（完全离线模式）、`--skip-update` / `-s`（跳过更新）

### 7.4 代码注释规范
- 使用 JSDoc 格式注释
- 每个类和函数都必须有注释
- 注释描述功能、参数和返回值

```typescript
/**
 * 获取玩家社交信息
 * 
 * 包含昵称、等级、助战角色、勋章板等信息。
 * @returns 玩家社交信息对象
 */
get socialInfo(): FriendDataWithNameCard {
  // ...
}
```

---

## 8. 启动模式与离线支持

### 8.1 启动模式总览

| 模式 | 触发方式 | 网络行为 | 适用场景 |
|------|----------|----------|----------|
| 在线更新（默认） | 直接启动 / `npm start` | git pull/clone 拉取 OpenArknightsFBS、ArknightsGameData，随后复制数据、生成类型、合并 gacha；失败自动回退本地缓存 | 首次部署、需要更新游戏数据 |
| 跳过更新 | `--skip-update` / `-s` | 跳过仓库拉取，仍执行本地复制、类型生成（npx）、gacha 合并 | 本地数据完整、希望快速启动 |
| 完全离线 | `--offline` / `-o`，或 `data/config.json` 中 `"offline": true` | **零网络操作**：不执行 git、不调用 npx、不复制、不合并 | 无网络 / 内网 / 演示环境 |

### 8.2 完全离线模式设计原则

1. **零网络访问**：不执行任何 git 命令（`clone`/`pull`），不通过 npx 启动子进程，从根源上杜绝网络请求和长时间超时等待。
2. **启动前校验**：在加载数据表之前，对本地必需数据文件清单（`REQUIRED_DATA_FILES`，共 66 个文件）做完整性检查。
3. **快速失败**：数据缺失时立即退出（exit code 1），列出缺失文件清单并给出解决指引，绝不带病启动。

### 8.3 校验范围

| 分类 | 路径 | 数量 |
|------|------|------|
| 应用配置 | `data/config.json`、`data/appConfig.json` | 2 |
| 用户数据 | `data/user/users.json` | 1 |
| Excel 数据表 | `data/excel/*.json` | 50 |
| 肉鸽/卡池 | `data/rlv2.json`、`data/gacha_detail_table.json` | 2 |
| 商店数据 | `data/shop/*.json` | 11 |

校验实现位于 `scripts/update-data.ts` 的 `verifyLocalData(baseDir)`：基于 `REQUIRED_DATA_FILES` 清单过滤出不存在的文件，返回缺失列表；入口 `index.ts` 在离线模式下先执行该校验，返回非 0 则终止启动。

### 8.4 启动流程

```
启动 index.ts → 解析命令行参数
  │
  ├─ offline=true（--offline / -o / config.offline）
  │     └─ verifyLocalData()
  │           ├─ 数据缺失 → 打印缺失清单 + 解决指引 → exit(1)
  │           └─ 数据完整 → excel.init() → 监听端口 → 启动完成
  │
  ├─ skipUpdate=true（--skip-update / -s）
  │     └─ 跳过更新 → excel.init() → 监听端口
  │
  └─ 默认（在线更新）
        └─ git 拉取 + 复制数据 + 生成类型 + 合并 gacha
              └─ 成功 → excel.init() → 监听端口
              └─ 失败 → 回退本地缓存 → excel.init() → 监听端口
```

---

## 9. 管理后台设计规范

### 9.1 功能定位
管理后台面向服主，提供 CLI（`npm run admin`）与 Web Dashboard（`/admin/dashboard`）两套入口，
覆盖用户管理（列表/详情/创建）、物品发放、邮件发送、服务器状态查看与基础配置修改。

### 9.2 架构
- 管理服务层 `app/admin/AdminService.ts`：纯逻辑层，CLI 与 HTTP 共用，复用 `AccountManager` / `mailManager` / `InventoryManager`。
- CLI `scripts/admin-cli.ts`：直接操作本地数据，无需启动服务器，完全离线可用。
- HTTP 管理 API `app/admin/admin-router.ts`：前缀 `/admin/api`，Bearer Token 认证（`admin-auth.ts`）。
- Dashboard `app/admin/dashboard/index.html`：单文件静态页（内联 CSS/JS，零构建依赖），页面免认证、API 需令牌。

### 9.3 配置
`data/config.json` 新增 `admin` 段：
- `enable`：是否开启 HTTP 管理接口（默认 `false`，安全默认）
- `token`：管理 API Bearer Token（服主自行修改）

### 9.4 安全
- 管理接口默认关闭；开启必须设置强 token。
- 所有管理操作（发放物品/发邮件/建号）校验用户存在性与参数合法性（数量为正整数、手机号唯一）。
- 建议仅在内网/本机暴露管理接口；Dashboard 页面免认证，但所有 API 请求必须携带令牌。

### 9.5 数据一致性
- 写操作统一走 `PlayerDataManager.update`（Immer 补丁）+ `accountManager.savePlayerData` / `saveUserConfig` 落盘。
- 创建用户采用模板复制（以 uid=1 数据库为模板）保证 `PlayerDataModel` 字段完整，写入文件后由 `reloadUser` 热加载进内存。
- `mailManager.sendMail` 为系统邮件唯一入口，`mailId` 全局自增（`nextMailId`，最小 1000000）。

### 9.6 CLI 命令一览
```
users list | users info <uid> | users create <phone> [password] | users grant <uid> <itemId> <count>
mail send <uid> <subject> [content] [--items id:count,...]
server status
config show | config set <key> <value>
```

---

## 附录

### A. 常用类型定义位置
| 类型来源 | 文件路径 | 说明 |
|----------|----------|------|
| FBS自动生成 | `app/excel/types_auto_gen.ts` | 355个enum，1621个interface |
| PlayerDataModel | `app/excel/types-playerdata.ts` | 796个接口，1065个枚举 |
| Excel数据表 | `app/excel/excel.ts` | 统一管理所有数据表 |

### B. 状态管理流程
```
1. 路由接收请求
2. 获取 PlayerDataManager 实例
3. 调用子管理器方法
4. 子管理器使用 update() 修改数据
5. Immer 生成变更补丁
6. 通过 delta 返回增量更新
7. 触发 save 事件保存数据
```

### C. 数据更新流程
```
1. 启动时执行 update-data.ts
2. 拉取 OpenArknightsFBS 和 ArknightsGameData
3. 复制数据文件到 data/excel/
4. 合并 gacha 文件
5. 生成 types_auto_gen.ts
6. 加载 Excel 数据表
7. 启动服务器
```

> 完全离线模式（`--offline`）跳过步骤 2-5，仅校验本地数据完整性（`verifyLocalData`）后直接进入步骤 6；数据缺失时退出并提示先联网执行 `npm run update`。

---

## 10. 好友系统与 SQLite 数据层

### 10.1 数据存储
好友关系数据（好友列表、好友申请、访问记录）存储在 `data/user/social.db`（SQLite），
使用 Node 24 内置 `node:sqlite`（DatabaseSync），零第三方依赖。
`data/user/users.json` 中的 `social` 字段仅作为首次迁移来源，迁移后不再作为数据源（重置为空结构）。
`social.db` 为运行时生成文件，已在 `.gitignore` 中忽略，不加入离线校验清单（REQUIRED_DATA_FILES）。

### 10.2 表结构
- `friends(uid, friend_uid, alias, create_ts)`：好友关系，主键 (uid, friend_uid)
- `friend_requests(from_uid, to_uid, create_ts)`：好友申请，主键 (from_uid, to_uid)
- `visited(uid, visited_uid, ts)`：访问记录，主键 (uid, visited_uid)

### 10.3 架构
- `app/db/database.ts`：连接单例（默认 `data/user/social.db`，测试用 `:memory:`；复用已关闭连接时自动重建）
- `app/db/schema.ts`：建表 SQL（幂等）
- `app/db/friend-repo.ts`：`FriendRepository` 仓储（3 表 CRUD）
- `app/db/migrate.ts`：`migrateFromUserConfigs` 首次启动从 users.json 导入并重置 JSON 社交字段
- `AccountManager._friendRepo`：init() 中惰性初始化（避免模块加载时创建数据库文件），社交方法（getSocial/addFriend/deleteFriend/sendFriendRequest/deleteFriendRequest/setFriendAlias/getFriendRequests）走仓储，签名不变

### 10.4 业务规则
- 双向好友：同意申请（processFriendRequest action=1）时双方互加；删除好友（deleteFriend）时双方互删
- 请求校验（sendFriendRequest）：不能向自己发送；对方已是好友拒绝；重复申请拒绝
- 申请接受后同步删除申请记录，并清除接收方 pushFlags.hasFriendRequest

### 10.5 已知约束
- 游戏中间件（app/game/app.ts）将所有 secret 强制映射为 uid=1（单机私服设计），多玩家交互逻辑由单测与独立进程集成脚本覆盖

---

## 11. 基建系统逻辑说明

### 11.1 覆盖范围
BuildingManager（app/game/manager/building.ts）已实现完整基建玩法：
- 房间管理：建造/升级/降级/清理槽位
- 干员分配：assignChar / 批量更换（batchChangeWorkChar）/ 批量休息（batchRestChar）
- 生产：制造结算（settleManufacture）/ 贸易结算（settleSale）/ 加工合成与分解（workshopSynthesis / workshopDecomposition）/ 加速（accelerateOrder / accelerateSolution）
- 信赖：gainIntimacy / gainAllIntimacy / gainAssistIntimacy（单次 +12 favorPoint）
- 线索：getDailyClue / sendClue / receiveClueToStock / putClueToTheBoard / deleteOwnClue 等 11 个方法
- 预设队列：add / delete / edit / use / useOne / changeName / saveDiy / editLock（存储于 building.presetQueues）
- 其他：buyLabor / confirmMessageBoardReward / 专精（upgradeSpecialization / completeUpgradeSpecialization）

### 11.2 实现约定
- 所有变更通过 PlayerDataManager.update（Immer）落盘
- 贸易结算：订单按 count × 500 兑换金币（与 deliveryOrder 一致），扣除贸易凭证 3003
- 信赖获得：单次 +12 favorPoint（同步 troop.chars 与 charGroup）
- 线索：每日一条（getDailyClue），ownStock/receiveStock/board 三区流转，ID 全局递增（_nextClueId）
- 预设队列：building.presetQueues（key 为 roomSlotId），旧存档惰性初始化（_presetQueues）
- 专精：upgradeSpecialization 置技能 state=1，completeUpgradeSpecialization 提升 specializeLevel 并复位
- 家具分解：产出木材（30012），简化固定产出 count × 2

### 11.3 简化项（YAGNI）
- 社交展示类接口（getRecentVisitors / getInfoShareVisitorsNum / sendEmoji / visitBuilding 等）返回空
- 制造/加工配方未严格按 BuildingData 表执行，使用简化产出规则
- 加速不消耗道具（私服友好）；buyLabor 1 源石/次 +10 劳动力

---

## 12. 战斗结算后处理逻辑

### 12.1 覆盖范围
BattleManager（app/game/manager/battle.ts）的战斗结束（finish）后处理：
- 结算清单：rewards / unusualRewards / additionalRewards / furnitureRewards / firstRewards / unlockStages 真实返回（此前为全空数组）
- 通关次数：胜利（completeState 2/3，非练习）时 `dungeon.stages[stageId].completeTimes + 1`
- 干员信赖：胜利时参战 squad 干员 `troop.chars[instId].favorPoint + 1`（battleInfo 新增 squad 字段，start 时保存）
- battleId：唯一化（时间戳 + 随机数），替代固定 "1"，避免多场战斗互相覆盖 battleInfo/replay
- 结算回传：`battle:finish` 事件新增可选回调，TroopManager.addonStageBattleFinish 收集结果，`/charBuild/addonStage/battleFinish` 路由合并 `{...result, ...delta}` 返回

### 12.2 修复的隐藏 bug
- **`in [` 操作符误用**（4 处）：`completeState in [2, 3]` 实际检查数组索引而非包含关系（`3 in [2,3]` 恒 false），导致关卡解锁、主线进度更新、dropType=8 首通奖励等逻辑从未生效 → 改为 `[..].includes(x)`
- **dropReward 无限递归**：零产出时用未收敛的 `displayDetailRewards` 重试（概率未中的条目永不移除）→ 真实掉落表下栈溢出崩溃 → 增加 depth 上限（10 轮）防死循环

### 12.4 掉落信息自动提取（excel 驱动）
- **归一化**：`app/excel/stage_table.ts` 的 `normalizeStageDropInfo` 在 excel 加载时（excel.init）将 `displayDetailRewards` 的 `occPercent`/`dropType` 字符串映射为数字档位（`ALWAYS→0, USUAL→1, OFTEN→2, SOMETIMES→3, ALMOST→4`；`ONCE→1, NORMAL→2, SPECIAL→3, ADDITIONAL→4, COMPLETE/CONDITION_DROP→8`），幂等（数字值保持不变）
- **修复前**：原始 excel 为字符串格式，而 dropReward 按数字比较 → **所有关卡掉落从未生效**（仅 finish 硬编码 GOLD/EXP 结算）
- **补产出**：对照 Python 参考 quest.py，`occPercent=0/dropType=2`（ALWAYS+NORMAL 必掉基础掉落）分支补 `pushReward()`——此前只 console.log 不产出，必掉材料（如 1-7 的 30012）从未掉落
- **保留的硬编码表**：SpecialGold / TacticalDrill / ToughSiege 等特殊关卡固定掉落（游戏设计值，excel 不含数量字段，无法自动提取）
- 已验证：main_01-07 归一化后 11 条掉落全部数字化，dropReward 正确产出必掉材料 30012 与概率掉落 30041/30061/3003 等

### 12.3 已知约束
- `/campaignV2/*` 等后半段路由（app/game/app.ts 61 行后）在真实服务器上未生效（404），为项目既有问题，与战斗结算无关；建议后续单独排查
- `/charBuild/addonStage/battleStart` 路由不返回 battleId，且固定练习模式（usePracticeTicket=1），HTTP 链路无法闭环非练习战斗——进程级 E2E 与单测覆盖结算逻辑
- 失败（completeState=1）不结算信赖/通关次数，rewards 为空

---

## 13. 勋章系统实现

### 13.1 架构
- **MedalManager**（app/game/manager/medal.ts）：勋章集合管理（init / setCustomData / rewardMedal / onMedalComplete / toJSON），构造时监听 `medal:complete` 事件
- **MedalProgress**：单个勋章进度追踪，**164 个 excel 模板全部实现**（PlayerLevel / PassStageSome / RecruitCount / GotChars / Rlv2* / Sbv3* / Act* 等），按模板注册事件监听推进进度

### 13.2 核心机制
- **挂载**：MedalManager 挂载到 PlayerDataManager（`player.medal`），构造时 `init()` 遍历玩家勋章创建进度实例
- **进度追踪**：构造条件放宽为「fts 未设 **或** 进度未满」→ 既有存档（1190 勋章中 228 个未满）也能继续追踪；模板事件（CompleteStage / char:get 等）触发时更新进度，达标后 `off` 监听并 emit `medal:complete`
- **领奖**：`/medal/rewardMedal` 路由调用 `player.medal.rewardMedal`，发放奖励组物品（items:get）并记录 rts
- **防重复**：rts != -1 视为已领取，重复请求返回空
- **持久化**：进度 val 与 `_playerdata.medal.medals` 共享引用（模板 update 直接写回）；rts 领取后显式同步写回持久态

### 13.3 容错（旧数据兼容）
- 勋章 `val` 缺失（旧存档）→ 构造兜底为 `[[]]`，不崩溃
- 勋章 ID 不在 excel MedalTable（活动下架残留）→ 跳过进度注册
- excel 未初始化时构造（PlayerDataManager 早于 excel 加载）→ 跳过进度注册

### 13.4 简化项（YAGNI）
- 164 个模板全部实现但仅核心模板有单测（PlayerLevel / JoinGameDays / CharNum / RecruitCount / GotChars / CharEvolveCount / PassTower）；活动类模板（Act*/Crisis*）依赖活动数据，按需验证
- 勋章展示（setCustomData / 名片展示）沿用既有实现，未扩展

---

## 14. 任务系统实现

### 14.1 架构
- **MissionManager**（app/game/manager/mission.ts）：任务集合管理（init / getMissionById / dailyRefresh / weeklyRefresh / confirmMission / confirmMissionGroup / autoConfirmMissions / exchangeMissionRewards），构造时监听 `refresh:daily` / `refresh:weekly` 事件
- **MissionTemplates**：按事件组织的任务模板映射（**46 个 excel 模板全覆盖**、无空实现），模板按 param[0] 细分（如 StageWithEnemyKill 的 0/1/2/3/5/6 分支）
- **MissionProgress**：单个任务进度追踪，按模板注册事件监听，达标后 off + state=3 + unlockNextMission

### 14.2 核心机制
- **挂载**：MissionManager 挂载到 PlayerDataManager（`player.mission`），构造时 `init()` 填充内存任务列表（DAILY 29 / WEEKLY 32 / GUIDE 72 / MAIN 82 / SUB 262 / OPENSERVER 4，共 481 个）
- **进度追踪**：MissionProgress.init 查 excel mission → 注册模板事件监听；事件触发时 update 推进，达标后写回 state=3 并解锁后续任务
- **刷新**：dailyRefresh 重置 dailyPoint + 按星期加载当日任务组；weeklyRefresh 重置 weeklyPoint + 加载全部 WEEKLY 任务
- **确认**：confirmMission 累计任务点数并自动兑换达标奖励组；autoConfirmMissions 批量确认
- **修复**：`/mission/confirmMission` 路由补 await（原返回 Promise 对象）

### 14.3 深层修复（任务系统从未生效的根因）
- **MissionManager.init 未挂载**：PlayerDataManager 构造未调用 → 481 个任务进度监听从未注册
- **init 未填充内存任务列表**：`this.missions` 为空 → getMissionById/confirmMission 依赖崩溃
- **Immer draft 内 push 崩溃**：init 在 `player.update` 回调内创建 MissionProgress（模板 push 到冻结 draft）→ 重构为「先补 ACTIVITY 分组，再在 draft 外创建进度实例」
- **Immer autoFreeze 冻结玩家数据**：finishDraft 默认冻结 `_playerdata`，管理器（MedalProgress/MissionProgress）直接修改数组（push）崩溃 → **全局禁用 autoFreeze**（PlayerDataManager 模块加载时 `setAutoFreeze(false)`），私服直接修改模式适用

### 14.4 简化项（YAGNI）
- 46 个模板仅核心模板有单测（CompleteStageAnyType / StageWithEnemyKill / UpgradeChar / CompleteAnyStage）；活动类模板依赖活动数据按需验证
- 任务状态 0/1 转换（未解锁→未接取）沿用既有实现，未扩展

---

## 15. 官服数据迁移

### 15.1 用途
用官服账号（手机号+密码）自动登录官服、拉取玩家数据、转换为私服存档并注册账号，实现「一键迁移官服数据到私服」。

### 15.2 使用方式
```bash
npm run migrate:official -- --accounts <账号文件路径> --template 1
```
- `--accounts`：账号文件（每行「手机号 密码」或两行一组「手机号\n密码」，忽略备注），默认 `reference/checkin-master/accounts.txt`
- `--template`：私服模板存档 uid（兜底字段来源），默认 1

### 15.3 登录协议（scripts/official-api.ts）
1. `getResVersion`：`ak-conf.hypergryph.com/config/prod/official/Android/version`
2. `getToken` 三步：`as.hypergryph.com/user/auth/v1/token_by_phone_password` → `oauth2/v2/grant`（appCode=7318def77669979d）→ `u8/user/v1/getToken`（u8_sign HMAC-SHA1）
3. `loginGame`：`ak-gs-gf.hypergryph.com/account/login`（拿 secret）
4. `syncPlayerData`：`/account/syncData`（返回完整玩家数据 user 字段）
全部使用 Node 24 内置 fetch + node:crypto，**零第三方依赖**。

### 15.4 转换与注册
- **convertOfficialData**（scripts/official-convert.ts）：官服 user 与私服存档同源——官方字段直接沿用、uid 替换为私服新 uid、移除连接态（secret/seqnum）、**模板全字段兜底**（官方缺失字段从模板存档复制，保证私服可加载）
- **registerImportedUser**（scripts/official-register.ts）：新 uid 从现有账号递增；写入 `data/user/databases/{uid}.json` + `users.json` 注册（auth.phone=官服手机号、auth.hgId=官服 uid、password 随机）

### 15.5 已知限制
- 真实官服调用未在测试中验证（全部 mock fetch）：官服接口可能变更、存在风控/验证码——脚本输出清晰错误，单个账号失败不中断其他
- 不迁移战斗回放/battleLog（仅全量拉取玩家数据）
- 迁移后的账号需重启服务器（或 `accountManager.init()` 重载）才能生效

---

## 16. 集成战略 rlv2 接口补全

### 16.1 背景
对照参考项目 Dorothinights（Python）的 rogue_3 接口集审计，现有 `app/game/controller/rlv2.ts`（主控制器）已实现 28 个方法（createGame/buyGoods/moveTo/battleFinish/gameSettle 等），本次补全 5 个缺失接口。

### 16.2 本次补全接口
| 接口 | 行为 | 参考 |
|------|------|------|
| `refreshShop` | 重生成当前 SHOP 商品 + refreshCnt-1 | Dorothinights refreshShop.py |
| `leaveShop` | 清空 pending → WAIT_MOVE | finishNodeAndEndCheck.py |
| `confirmPredict` | 清空 pending → WAIT_MOVE（rogue_3 预兆确认） | confirmPredict.py |
| `useTotem` | 接线 `modules/totem.ts` 的 `use()`（上下板效果已实现） | useTotem.py |
| `closeRecruitTicket` | 招募票 state=3（关闭）+ 清空候选列表 | closeRecruitTicket.py |

路由：`app/game/router/rlv2.ts` 新增 5 个 POST（refreshShop/leaveShop/useTotem/confirmPredict/closeRecruitTicket）。

### 16.3 隐藏问题
- **`_status.pending` 是只读 getter**（经 `_pending._pending` 内部数组操作）——实现/测试都需注意
- **图腾管理器访问**：`_module.totem` getter（`_modules["TOTEM"]`）——返回 any 避免与 `Module.totem` 结构类型冲突
- **外援 buff 配置缺失**（buff.ts）：`RoguelikeConsts[theme].outbuff[id]` 在真实数据下可能 undefined → 可选链容错
- **createGame 真实数据链路**（既有问题）：`modebuff`/`outbuff` 等 excel 配置在真实存档下仍可能缺失——本次仅修复 outbuff，createGame 完整链路留后续

### 16.4 简化项（YAGNI）
- useTotem 的混沌值扣减未实现（fragment/chaos 模块结构复杂）——仅接线图腾 use
- leaveShop/confirmPredict 的 zoneEndChecker（关卡结束检查）未实现——复用现有 pending 清理模式

---

## 17. 子域名分发与远程配置

### 17.1 子域名分发（app/config/host-router.ts）
私服场景：客户端通过改 hosts/DNS 将 `*.hypergryph.com` 指向私服，请求保留官服子域名 Host 头。`createHostRouter()` 中间件按子域名映射：
- `as.hypergryph.com/*` → `/auth/*`（账号系统）
- `ak-conf.hypergryph.com/*` → 保持（配置：/config/prod、/api/remote_config）
- `ak-gs-gf.hypergryph.com/*` → 保持（游戏：/account、/user 等）
- `game-config.hypergryph.com/*` → 保持（新版远程配置）
- 非 `*.hypergryph.com`（localhost/IP 直连）不重写

### 17.2 新版远程配置接口（app/config/remote-config.ts）
新版客户端（game-config 域名）请求的两个接口：
- `/api/remote_config/1/prod/default/Windows/network_config` → 网络端点配置（官方扁平格式：an/as/gs/hu/u8/hv 等，域名替换为私服地址）
- `/api/remote_config/1/prod/default/Windows/remote_config` → 功能配置（官方格式：fapv2/HGDownload_1/2、enableGameBI、enableNativeLicense、bakeMuzzleEnableRate 等）

功能配置字段可在 `data/config.json` 的 `RemoteConfig` 覆盖，缺省使用官服默认值。

### 17.3 已知约束
- Node fetch 会覆盖自定义 Host 头——子域名验证需用 node http 或 curl（E2E 经验）
- 旧版 `/config/prod/official/network_config`（{sign, content} 格式）保持兼容（prod.ts 复用 buildNetworkConfigContent）

---

## 18. 助战系统

### 18.1 用途
明日方舟助战：玩家在助战位放置干员（社交）、好友在编队时可借用（战斗）。私服单机场景：多账号互相借用。

### 18.2 接口
| 接口 | 行为 | 状态 |
|------|------|------|
| `POST /social/setAssistCharList` | 保存助战干员列表（charInstId/skillIndex）到 `player.social.assistCharList` | 既有 |
| `POST /quest/getAssistList` | 编队助战列表：按职业筛选好友助战干员，随机最多 6 个、charId 去重，返回 OrigChar 结构 | **本次新增** |
| `POST /quest/battleStart` | 战斗开始保存 `assistFriend`（uid/assistChar/assistSlotIndex）到 BattleInfo | **本次补全** |

### 18.3 数据流
1. **设置**：`setAssistCharList({assistCharList})` → `player.social.assistCharList`（{charInstId, skillIndex} 引用）
2. **展示**：`socialInfo` getter 把助战 charInstId 映射为完整干员数据（charId/skills/level/favorPoint 等）——好友列表/助战列表复用
3. **借用**：`getAssistList({profession})` 读好友 `socialInfo.assistCharList` 按职业匹配（excel.CharacterTable[charId].profession）→ 构造 OrigChar（nickName/uid/level/avatar/assistSlotIndex/powerScore=200 简化）；**好友数据不足 6 个时从其他账号随机补位**（isFriend=false、canRequestFriend=true、aliasName=null）
4. **战斗**：`battleStart` 的 `assistFriend`（SquadFriendData）保存到 BattleInfo（供结算/日志）

### 18.4 已知约束
- 战斗内助战干员数据由客户端自带（encryptBattleData）——服务端仅记录 assistFriend，不额外处理干员进队
- 助战社交点结算（借出方 yesterdayReward.assistAmount 累加）**未实现**（YAGNI）——需跨玩家写入 + 每日重置机制，留后续
- powerScore 简化为固定 200（参考实现也是 TODO）
- 好友关系数据来自 SQLite（social.db）——getAssistList 依赖好友关系存在
