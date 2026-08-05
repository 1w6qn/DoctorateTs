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
