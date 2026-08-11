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
19. [用户创建与自动注册](#19-用户创建与自动注册)
20. [服务端性能评估与优化](#20-服务端性能评估与优化)
21. [服务器地址配置](#21-服务器地址配置)
22. [资源与版本自动同步](#22-资源与版本自动同步)

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
- 使用 JSON 文件 + SQLite 存储数据
- 玩家数据存储在 `data/user/databases/{uid}.json`
- 用户配置（账号/密钥/战斗回放/抽卡保底等 UserConfig）存储在 SQLite `users` 表（`data/user/social.db`）——`data/user/users.json` 仅作为首次迁移种子（2026-08 迁移）

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

### 7.4 PlayerDataModel 类型生成

`app/excel/types-playerdata.ts` 是**运行时 PlayerDataModel 的唯一权威定义**——`app/game/model/playerdata.ts` 直接 `export *` 该文件（手写模型已全量替换删除），`app/game/model/character.ts` 等对生成模型重叠类型做桥接 re-export。由官服反编译自动生成（客户端闭包 + 服务端协议适配 + 线格式适配），线格式经真实官服存档标量+结构双维度校验。

- 输入：`reference/com.hypergryph.arknights_2.7.61.cs`（官服反编译，`reference/` 已被 gitignore，不入库）
- 命令：`npm run generate:playerdata`
- 产物：纯闭包 802 类 / 113 枚举，含 2.7.61 新增 `arkOdc` 等 22 个类型；`ListDict<K,V>` 映射为字典 `{ [key: K]: V }`（与真实存档 JSON 一致）
- 链路：`scripts/playerdata-parser.ts`（括号配对解析、完整枚举值、类型映射）→ `scripts/playerdata-builder.ts`（类型闭包、TS 生成、未定义引用自检）→ `scripts/playerdata-server-adapt.ts`（服务端协议适配 + 线格式适配）→ `scripts/generate-playerdata-types.ts`（CLI）
- **服务端协议适配层**（`scripts/playerdata-server-adapt.ts`）：客户端 2.7.61 模型与服务端 JSON 序列化协议分叉（服务端保守旧 key + 超集，如 `PlayerCharacter` 的 skin/tmpl 双结构并存）。适配层三操作：`renameFields`（客户端字段名→服务端 key，如 campaign→campaignsV2、towerId→tower、godCardId→id）、`addFields`（服务端独有字段，如 PlayerStage.startTimes/practiceTimes、商店 curShopId/info、房间 buff 结构）、`overrideFields`（结构差异，整接口转类型别名如 PlayerActivity 字典、PlayerBuilding.rooms 具名 12 房间类型、MissionPlayerDataGroup 索引字典）
- **线格式适配（wire pass）**：官服 JSON 把枚举/时间戳/布尔系统性降为数字——枚举字段→`number`（保留枚举定义作参考）、`System.DateTime`→`number`（unix ts）、布尔→`number`（0/1）；少数字符串序列化枚举（`roomId` "CONTROL"、`mode` "NORMAL"、`type` "CHAR" 等）与真实布尔（`avail`、`unlock` 等）经抓包标量审计反推的白名单保留
- **校验闭环**：`npx tsx scripts/validate-playerdata-json.ts --input test.json --root user`（官服账号文件 test.json 的 user 根路径）——**0 缺失 / 0 大小写差异 / 0 结构不匹配 / 0 标量不匹配**（95,694 节点）；`--input player_data.json`（官服大存档）同样全 0（107,515 节点）；`--input tmp/official/account/syncData/2026-08-09T07-31-24-506Z.json --root user`（最新抓包）同样全 0（95,977 节点）。清单增量维护流程：校验报告 → 更新适配清单 → 重生成 → 再校验
- 校验器含标量叶子类型比对（number/string/boolean/枚举字面量/基础类型联合）与 untyped 盲区报告（`object` 型字段路径）；已知线格式分歧（如 `flags` 官服 '1' 字符串 vs 运行时 number）在 `SCALAR_EXCEPTIONS` 文档化
- 运行时替换：`app/game/model/playerdata.ts` 为生成模型 re-export；`character.ts` 保留生成模型不含的服务端社交/分享类型；rlv2 子系统（`model/rlv2.ts`）为功能实现内部模型，与生成模型在 controller 边界显式桥接

### 7.4.1 excel 表类型生成（从 cs）

`app/excel/types_excel_gen.ts` 从 cs 反编译生成 **47 个 excel 表的权威类型**（1480+ 类 / 349+ 枚举），`app/excel/excel.ts` 的 55 个表类型引用与 troop/mission/mailCollection/mockExcel 等直接引用方均已从 FBS 版 `types_auto_gen.ts` 切换过来（FBS 版已删除，不再依赖 OpenArknightsFBS）。以 `data/excel/*.json` 全量校验 **0 缺失 / 0 大小写 / 0 结构 / 0 标量**（3.29M 节点）。

- 命令：`npm run generate:excel`；链路：`scripts/types-builder.ts`（统一构建器：C# 数组 `X[]`、泛型 `Undefinable<T>`/`KeyFrames<T>`、类继承字段合并、`abstract class`、List 继承 → 数组别名，多根闭包）→ `scripts/excel-server-adapt.ts`（表根映射 + rename/add/override/optional/枚举补充/字段覆盖/索引签名）→ `scripts/generate-types.ts --excel`（CLI，统一生成器）
- **表根映射** `EXCEL_TABLE_ROOTS`：表键 → cs 根类（包装类如 StageTable/ZoneTable/ActivityTable，元素类如 CharacterData/SkillDataBundle，多根表如 enemy_handbook_table 按 key 映射）；由 JSON 顶层结构 × cs 类字段匹配自动反推
- **excel 线格式与 playerdata 不同**：枚举为字符串（`position:"RANGED"`）、bool 为 true/false、时间戳为 number——**无需 enum→number wire pass**；个别数值/字符串混合字段（spType/professionMask/direction）用 `number | string` 字段覆盖
- **校验闭环** `scripts/validate-excel-json.ts`：复用 playerdata 校验器 walk 逻辑，字典表/包装表/多根表三模式；`--tables t1,t2` 子集迭代，`--full` 输出聚合报告
- 已知结构分叉的适配实例：`StageData_DisplayDetailRewards`（JSON 为 DisplayRewards 基类字段 + occPercent）、`CharacterData_MainSkill`（JSON 用旧字段名 levelUpCostCond/unlockCond）、`TowerCurrent_GameCard`（C# 继承 PlayerCharacter，整接口覆盖补全）、`PlayerBuildingChar_BubbleContainer` 等

### 7.5 代码注释规范
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
| 在线更新（默认） | 直接启动 / `npm start` | git pull/clone 拉取 ArknightsGameData，随后复制数据、生成类型（CS 反编译源）、合并 gacha；失败自动回退本地缓存 | 首次部署、需要更新游戏数据 |
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
管理后台面向服主，提供 CLI（`npm run admin`，离线可用）与 Web Dashboard（`/admin/dashboard`）两套入口，
覆盖用户全生命周期（建/查/改/批量/备份/导出导入/删除/修复）、物品/干员/皮肤发放、卡池管理、
关卡/任务/勋章/商店只读、邮件（单发/群发/查看/删除）、官服账号迁移、接口调试、统计、审计与一键启动。

### 9.2 架构
- **共享服务层 `app/admin/AdminService.ts`**：纯逻辑层，CLI 与 HTTP 共用（`adminService` 单例）。
  所有写操作统一 `pd.update`（Immer）+ `accountManager.flushSave(uid)` 落盘 + `_audit` 审计日志（`data/admin/logs.jsonl`）。
- **CLI `scripts/admin-cli.ts`**：无参数进入 REPL（Tab 补全）；全局 `--quiet/-q` 抑制内部日志（`LOG_LEVEL=error`，logger 运行时求值）；
  输出支持 `--json` / `--csv`。
- **HTTP 管理 API `app/admin/admin-router.ts`**：前缀 `/admin/api`，Token 认证（`admin-auth.ts`，`X-Admin-Token` 头）。
- **Dashboard `app/admin/dashboard/index.html`**：单文件静态页（内联 CSS/JS，零构建依赖），10s 轮询，全部注入走 `escapeHtml`。
- **端点规范 `app/admin/api-spec.ts` + `openapi.ts`**：`ADMIN_ENDPOINTS` 一份清单同时驱动接口控制台与 `GET /admin/api/openapi.json`（OpenAPI 3.0 文档）。
- **游戏协议代理 `AdminService.gameProxy`**：以玩家 secret 调用游戏端点（`game/app.ts` 锁中间件跳过 `/admin` 路径——
  否则 single 模式外层 admin 请求持有 singleUid 锁、内层代理等待同一把锁会死锁）。

### 9.3 配置
`data/config.json` 新增 `admin` 段：
- `enable`：是否开启 HTTP 管理接口（默认 `false`，安全默认）
- `token`：管理 API Bearer Token（服主自行修改）

### 9.4 安全
- 管理接口默认关闭；开启必须设置强 token。
- **危险操作双确认**：`users delete` 需 `--yes` + 服务端 `confirmWord="DELETE"`；`restore` 文件名白名单
  `^{uid}-[\d-]+\.json$` 防路径穿越；`gameProxy` 拦截 `/admin`、`/auth` 控制面路径。
- **审计日志**：所有变更操作（发放/邮件/建号/卡池/迁移/备份/删除/修复…）写入 `data/admin/logs.jsonl`，
  CLI `logs show` / Dashboard「操作日志」区块可查。
- 建议仅在内网/本机暴露；Dashboard 页面免认证，但所有 API 请求必须携带令牌。

### 9.5 数据一致性
- 写操作统一 `pd.update` + `flushSave`（`savePlayerData` + `saveUserConfig`），删除账号依赖 `upsertAll` 全量同步语义清 SQLite。
- 创建用户采用模板复制（uid=1 存档）保证字段完整，`reloadUser` 热加载进内存；官服迁移成功后逐个热加载。
- 干员引用（ID/中文名）统一走 `admin-names.resolveCharRef`；星级用 `charRarity` 归一化
  （character_table 的 rarity 为 `"TIER_5"` 字符串，`rarity + 1` 会变字符串拼接）。
- `runMigration` 接收账号**内容文本**（CLI 读文件、Dashboard 粘贴共用）；scripts 模块被 app/ 引用后纳入 tsc 编译。

### 9.6 CLI 命令一览
```
users list [--json|--csv] [--filter 关键字] | users info <uid>
users create <phone> [password]
users grant <uid[,uid...]> <itemId|名称> <count> | users grantall <uid> [count]
users grantchar <uid> <charId|干员名> | users skin <uid> <skinId>
users chars <uid> | users char <uid> <instId> [--level/--evolve/--potential/--skill]（无参数=详情）
users maxout <uid> | users maxchars <uid> | users repairchars <uid>
users stages <uid> | users unlock <uid> <stageId> | users unlockall <uid>
users items <关键字> | users missions <uid> | users medals <uid> | users shop <uid>
users backup <uid> | users backups <uid> | users restore <uid> <备份>
users dump <uid> [--pretty] | users export <uid> [path] | users import <存档JSON> [uid]
users delete <uid> --yes
mail send <uid[,uid...]|all> <subject> [content] [--items id:count,...] | mail list <uid> | mail delete <uid> <mailId>
server status | server refresh <uid> | server save [uid] | server check
config show | config set <key> <value>
gacha pools | gacha pool <poolId> | gacha state <uid> <poolId> | gacha up <uid> <poolId> [charId...] | gacha pity <uid> [ruleType] [count]
official accounts <file> | official migrate <file> [--template uid]
logs show [--last N] [--json]
全局：--quiet/-q（抑制日志）；无参数进入 REPL（Tab 补全）
```

### 9.7 REST API 一览（52 端点，前缀 /admin/api）
- 服务器/配置：`status`、`config`、`check`、`logs`、`spec`、`openapi.json`、`common-items`、`items`（搜索）、`stats`
- 用户：`users`（?filter=）、`users/:uid`、`users`（POST 建号）、`users/:uid/grant`、`grantchar`、`grantskin`、
  `chars`、`chars/:instId`（详情）、`chars`（POST 编辑）、`maxout`、`maxchars`、`repair-chars`、`building-max`、
  `grant-all`、`stages`、`stages/unlock`、`stages/unlock-all`、`missions`、`medals`、`shop`、`raw`、`mails`、`mails/:mailId`（DELETE）、
  `pools/:poolId`（玩家状态）、`pools/:poolId/up`、`pity`、`backup`、`backups`、`restore`、`export`、`refresh`、`save`
- 邮件/卡池/迁移：`mail`、`mail/all`、`pools`、`pools/:poolId`、`official/migrate`、`import`
- 调试：`game-proxy`（带玩家 secret 调游戏端点）

### 9.8 Dashboard 功能区块
概览（资源中文名网格 + 签到区 + 一键满配/基建/刷新/保存/备份/恢复 + 发干员/发皮肤）| 干员（星级分布条/搜索/详情弹窗/行内编辑/全部满级/修复结构）|
邮件（列表/删除/群发）| 卡池（清单/详情 + 玩家 UP/保底管理）| 接口（管理 API 控制台 + 游戏协议调试器 + OpenAPI 链接）|
迁移（官服迁移 + 官服操作 + 通用调用 + 卡池同步）| 数据（raw JSON 复制/下载）| 统计（默认折叠摘要）| 操作日志 | 用户列表搜索/分页

### 9.9 Dashboard 交互与视觉规范（2026-08 UI 升级）
- **零依赖约束**：单文件 `index.html`（内联 CSS/JS）+ `manifest.webmanifest` + `icon.svg`，无构建链、无框架。
- **布局**：`.layout` flex——左侧垂直侧边栏（8 Tab：概览/干员/邮件/卡池/接口/官服/像素画/数据）+ 右侧内容区；
  全局功能 Tab（接口/官服/卡池）不依赖选中用户、隐藏用户列表内容全宽；用户 Tab 未选用户时提示。
- **官服工具库**：独立「官服」页——tool-card 卡片网格（游戏工具库风格，点击卡片头展开/收起）：共享账号凭据 +
  状态/签到/邮件/一键日常/通用调用/卡池同步/账号迁移 7 工具，结果区复制按钮；当前后端地址显示。
- **通知**：Toast 替代 `alert`（自动着色 + 3s 消失；带 detail 时点击复制详情）；危险操作 `confirmDialog` 风险分级
  （danger 红标红底 / warn 黄标）。
- **轮询**：10s 只刷状态 + 用户列表（编辑输入框时跳过），统计/日志 30s；Tab 状态保持（切 Tab 回来恢复输入）。
- **主题**：CSS 变量 + `[data-theme=light]` 浅色覆盖；手动切换 + localStorage，未选择时跟随系统 prefers-color-scheme。
- **状态色语义**：`--ok/--err/--star5/--star4` 统一干员星级、邮件状态等；即时输入校验（数量/JSON 实时红框）。
- **数据展示**：星级分布条、分页（每页 50）、骨架屏、相对时间（fmtRel + tooltip 完整时间）、术语 tooltip、首次引导卡片。
- **批量多选**：用户列表复选框 + 全选 + 批量栏（发物品/发邮件/一键满配/清空），modal 批量模式循环发送。
- **导航**：URL hash 同步 Tab（#pools 直达/前进后退）；全局快捷键（/ u r 1-7）。
- **多端**：`@media (max-width:900px)` 侧边栏转顶部横排可滚动、内容单列；PWA manifest（不做 service worker——
  与 no-cache 冲突）；`@media print` 只保留详情内容。
- **缓存**：`/admin/dashboard` 与 manifest/icon 均 `no-cache`——单文件无版本号，禁止浏览器缓存旧版。
- **快捷键**：`/` `u` 聚焦搜索、`r` 刷新、`1-7` 切 Tab（非输入框时生效）。
- **代码质量**：内联 JS 用 `node --check` 语法校验（sed/批量改后必查括号配对），每批服务器页面冒烟。

### 9.10 关键设计决策
- **CLI 与 HTTP 共用 AdminService**：新增能力先在服务层实现 + 单测，再分别接 CLI / router / Dashboard，避免三端逻辑漂移。
- **scripts 引用策略**：AdminService 直接 import scripts 模块（`migrate-official`、`generate-max-account`），
  使其纳入 tsc 编译（曾暴露 `official-register` 潜在类型错误）；共享构建器（`buildMaxedSkills` 等）迁至 `app/game/maxout.ts`。
- **parseArgs 吞值**：`--quiet users list` 会把 `users` 当 flag 值吞掉——全局 flag 解析前先从 argv 剔除。
- **状态修复闭环**：`server check` 诊断（status/troop/干员字段/阿米娅 tmpl）→ `users repairchars` 修复 → 复检，形成闭环。

---

## 附录

### A. 常用类型定义位置
| 类型来源 | 文件路径 | 说明 |
|----------|----------|------|
| CS自动生成 | `app/excel/types_excel_gen.ts` | excel 表权威类型（1470+ 类 / 347+ 枚举，原 FBS 版 types_auto_gen 已删除） |
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
2. 拉取 ArknightsGameData
3. 复制数据文件到 data/excel/
4. 合并 gacha 文件
5. 生成 types_excel_gen.ts（CS 反编译源，不再依赖 OpenArknightsFBS）
6. 加载 Excel 数据表
7. 启动服务器
```

> 完全离线模式（`--offline`）跳过步骤 2-5，仅校验本地数据完整性（`verifyLocalData`）后直接进入步骤 6；数据缺失时退出并提示先联网执行 `npm run update`。

---

## 10. 好友系统与 SQLite 数据层

### 10.1 数据存储
好友关系数据（好友列表、好友申请、访问记录）与**用户账号配置**（UserConfig）存储在 `data/user/social.db`（SQLite），
使用 Node 24 内置 `node:sqlite`（DatabaseSync），零第三方依赖。
`data/user/users.json` 中的 `social` 字段仅作为首次迁移来源，迁移后不再作为数据源（重置为空结构）。
**2026-08 起 users.json 整体退化为首次迁移种子**——`AccountManager.init` 在 SQLite `users` 表为空时导入，之后用户配置以 SQLite 为唯一事实源（`saveUserConfig` 只写库，不再写 users.json）。
`social.db` 为运行时生成文件，已在 `.gitignore` 中忽略，不加入离线校验清单（REQUIRED_DATA_FILES，users.json 种子文件保留在清单中）。

### 10.2 表结构
- `friends(uid, friend_uid, alias, create_ts)`：好友关系，主键 (uid, friend_uid)
- `friend_requests(from_uid, to_uid, create_ts)`：好友申请，主键 (from_uid, to_uid)
- `visited(uid, visited_uid, ts)`：访问记录，主键 (uid, visited_uid)
- `users(uid, data, updated_ts)`：用户账号配置，主键 uid；`data` 为 UserConfig JSON 列（uid/password/secret/auth/social/battle/gacha/rlv2 整体序列化）

### 10.3 架构
- `app/db/database.ts`：连接单例（默认 `data/user/social.db`，测试用 `:memory:`；复用已关闭连接时自动重建）
- `app/db/schema.ts`：建表 SQL（幂等）
- `app/db/friend-repo.ts`：`FriendRepository` 仓储（好友 3 表 CRUD）
- `app/db/user-repo.ts`：`UserRepository` 仓储（users 表 CRUD：getAll/get/upsert/upsertAll——upsertAll 为全量同步语义：DELETE + INSERT 事务）+ `migrateUsersFromJsonFile`（users.json → SQLite 幂等迁移）
- `app/db/migrate.ts`：`migrateFromUserConfigs` 首次启动从 users.json 导入好友数据并重置 JSON 社交字段
- `AccountManager._friendRepo`：init() 中惰性初始化（避免模块加载时创建数据库文件），社交方法（getSocial/addFriend/deleteFriend/sendFriendRequest/deleteFriendRequest/setFriendAlias/getFriendRequests）走仓储，签名不变
- `AccountManager._userRepo`：init() 中初始化——`configs = getAll()`（空则迁移 users.json 种子）；`saveUserConfig` 全量 `upsertAll(configs)`（未 init 时 no-op，测试安全）
- 官服迁移脚本（`scripts/official-register.ts`/`migrate-official.ts`）注册/读取用户同样走 SQLite（users.json 仅种子）

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
- 信赖：gainIntimacy / gainAllIntimacy / gainAssistIntimacy（单次量由 basicFavorPerDay 派生，默认 12）
- 线索：getDailyClue / sendClue / receiveClueToStock / putClueToTheBoard / deleteOwnClue 等 11 个方法
- 预设队列：add / delete / edit / use / useOne / changeName / saveDiy / editLock（存储于 building.presetQueues）
- 其他：buyLabor / confirmMessageBoardReward / 专精（upgradeSpecialization / completeUpgradeSpecialization）

### 11.2 实现约定
- 所有变更通过 PlayerDataManager.update（Immer）落盘
- **Excel 驱动（2026-08-07，替代硬编码简化）**：查询工具层 `app/excel/building_excel.ts`（getManufactFormula / getWorkshopFormula / getRoomPhase / getGoldRate / getBuildingConstant）
  - 制造结算：查 `manufactFormulas`（14 配方：F_EXP 2001-2003 / F_GOLD 3003 / F_ASC 3213-3283 / F_DIAMOND 3141）——产出 `itemId×count×outputSolutionCnt`、消耗 `costs`（MATERIAL 扣 inventory / GOLD 扣金币）
  - 贸易结算：对齐真实订单结构 `{instId, delivery:[{id,count}], gain:{id,type,count}}`——扣 delivery 物品、加 gain 物品（不再 count×500 假结算）；instId 查找
  - 加工合成：查 `workshopFormulas`（68 配方）——goldCost/costs 消耗、产出、`extraOutcomeRate` 概率触发 `extraOutcomeGroup` 加权副产物；formulaId 支持请求体传入（回退房间 formulaId）
  - 劳动力：`laborRecoverTime`（360 秒/点）自动恢复（sync 入口，封顶 maxValue）
  - 房间建造/升级：查 `rooms[roomId].phases[level].buildCost`——扣 items（MATERIAL/GOLD）与 labor
  - 信赖：单次量 = `basicFavorPerDay`（720）÷ 60（每小时量，默认 12/次），同步 troop.chars 与 charGroup
- 线索：每日一条（getDailyClue），ownStock/receiveStock/board 三区流转，**type 用 7 阵营**（RHINE/PENGUIN/BLACKSTEEL/URSUS/GLASGOW/KJERAG/RHODES）、**id 用真实格式 `{uid}#{随机}#{时间戳}`**（对齐真实存档，替代递增 clue_ID）
- 预设队列：building.presetQueues（key 为 roomSlotId），旧存档惰性初始化（_presetQueues）
- 专精：upgradeSpecialization 置技能 state=1，completeUpgradeSpecialization 提升 specializeLevel 并复位
- 家具分解：产出木材（30012），简化固定产出 count × 2

### 11.3 简化项（YAGNI）
- 社交展示类接口（getRecentVisitors / getInfoShareVisitorsNum / sendEmoji / visitBuilding 等）返回空
- 加速不消耗道具（私服友好）；buyLabor 1 源石/次 +10 劳动力（apToLaborRatio=2 为 AP→劳动力比例，未接入）
- 干员基建 buff（chars.buffChar + buffs 表 747 个）**未应用**（服务端不重算，存档已有 buff 字段；客户端自行计算显示）
- 加工体力消耗（workshopFormulas.apCost）、制造心情消耗（costPoint）未接入（单位未确认）

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
- **convertOfficialData**（scripts/official-convert.ts）：官服 user 与私服存档同源——官方字段直接沿用、uid 替换为私服新 uid、移除连接态（secret/seqnum）、**模板全字段兜底**（官方缺失**或为空对象**的字段从模板存档复制，保证私服可加载——官服 syncData 中 shop/tshop/inventory/crisis 等可能为空对象，而私服路由直接访问 `shop.LS.info` 等深层结构，空对象会导致 500）
- **registerImportedUser**（scripts/official-register.ts）：新 uid 从现有账号递增；写入 `data/user/databases/{uid}.json` + SQLite `users` 表注册（auth.phone=官服手机号、auth.hgId=官服 uid、password 随机）

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

### 16.5 数据补全（2026-08，数据源与消费链路）

| 数据文件 | 覆盖 | 数据源 | 消费点 |
|---|---|---|---|
| `data/rlv2/event_choices.json`（505KB） | rogue_1..5 不期而遇全量效果 | 参考项目 odpy（官方 choices 的效果增强版，rogue_3/4/5 与官方 excel 数量完全一致） | `selectChoice`（lose/get/m_lose/m_get/i_get/i_lose/curse/get_id）、`moveTo` INCIDENT 生成 SCENE |
| `data/rlv2.json`（RoguelikeConsts） | 6 主题 outbuff/modebuff/recruitGrps | outbuff 从官方 `customizeData[theme].developments`（含 commonDevelopment）的 `buffDisplayInfo` 转换（displayType→RoguelikeBuff 映射，PERCENTAGE 除 100、ABSOLUTE_VAL 作 count）；modebuff 从 odpy `rlv2_data.py` rogue_buffs（rogue_2/3 难度 0-15）；recruitGrps 从官方 `details[theme].recruitGrps` 全量 | `buff.create()`（outbuff/modebuff 应用）、`chooseInitialRecruitSet` |
| `data/rlv2/nodesInfo.json` | 6 主题 × zone 关卡列表（Normal/Emergency/Boss） | 官方 `details[theme].stages` 按 `ro{n}_{n|e}_{zone}_` 前缀提取 | `map.generate()` 优先读（缺失回退动态过滤） |
| `data/rlv2/choices.json` | 6 主题开局 buff（行动奖励）场景 | 官方 `choiceScenes` + `choices`（startbuff 前缀） | `RoguelikeV2Config.choiceScenes`（数据完整性） |

**selectChoice 数据源切换**：官方 excel choices 无 lose/get 效果字段（效果藏在 description `<@ro.get>` 标签），selectChoice 改读 `eventChoices[theme].choices[choice]`（lose/get/m_lose/m_get/i_get/i_lose），官方 excel 仅提供 nextSceneId/type 元数据。下一场景选项列表来自 event_choices 的 `choices` 数组（不再用 `choice_{sceneId}_` 前缀匹配——真实数据匹配不到）。

**不期而遇事件生成**：`moveTo` 到 INCIDENT（type=32）节点时从 `eventChoices[theme].enter` 随机抽场景生成 SCENE 事件。

**区域推进（zone 推进）**：`finishEvent`/`finishBattleReward`/`leaveShop`/`confirmPredict`/`selectChoice(choice_leave)` 节点结束后调 `checkZoneEnd()`——当前节点 `zone_end: true` 时推进 `cursor.zone+1` 并生成新层地图（`rlv2:zone:new`）；达到主流程最大层（`maxZone`，取有 Normal/Emergency 关卡的 zone 最大值）触发 `gameSettle()` 结算。初始阶段（zone=0）结束生成第一层地图。

**容错**：`buff.create()` 对 `outer[theme]` 缺失（从未玩过该主题）与 `modebuff[modeGrade]` 缺失均容错；`chooseInitialRecruitSet` 招募组缺失回退官方 excel recruitGrps。

**死文件清理**：`data/rlv2/choiceBuffs.json`、`data/rlv2/recruitGroups.json` 零引用已删除（数据由官方 excel/event_choices/data/rlv2.json 覆盖）。

### 16.6 藏品池功能（2026-08，战斗收藏品掉落）

**池分类**（`app/game/controller/rlv2/pool.ts` `create()`，官方 `details[theme].items` 动态分池）：
- `pool_relic_all`：全部收藏品（type === "RELIC"）
- `pool_relic_normal` / `pool_relic_rare` / `pool_relic_super_rare`：按 `rarity` 分类（NORMAL/RARE/SUPER_RARE，BORN 不在稀有度池）
- `pool_sacrifice_n/r`：可献祭物品（value 8/12）
- `pool_fragment_3/4/5`：构想碎片（INSPIRATION/WISH/IDEA，仅含 fragment 模块的主题）

**随机抽取**：`getRelic(poolId, hasRelic)`——从池随机抽一个**未拥有**的收藏品（过滤 hasRelic），**不放回**（同池不重复，`splice` 移除）。池空或全部已拥有返回空串。

**战斗掉落**（`battle.ts` `finish()` 胜利分支，参考 Dorothinights `generateBaseBattleRewards`）：
- 掉落顺序：招募券 → 金币 → 碎片 → **随机收藏品**
- 收藏品项格式 `{index, items: [{sub, id, count: 1}], done: 0}`，id 来自 `pool_relic_all`（过滤已拥有）
- 概率：普通/紧急 40%，boss 战（stage 含 `_b_`）**必掉 2 个**
- 选择链路：`chooseBattleReward` → `rlv2:get:items` → `inventory.getItem`（RELIC type）→ `rlv2:relic:gain`（已有，无需改动）

**简化（YAGNI）**：官方无"battle 池/boss 池"分组（relics 只有 id+buffs），战斗统一用 `pool_relic_all`；精确概率在客户端，私服用简化概率。

### 16.7 增益树（科技树）解锁与加成（2026-08）

**数据**（官方 excel，6 主题全）：`customizeData[theme].developments`（rogue_1..3）或 `.commonDevelopment.developments`（rogue_4..6）——节点 `{buffId, frontNodeId[], nextNodeId[], tokenCost, nodeType, buffName}`。解锁状态存 `outer[theme].buff = {pointOwned, pointCost, unlocked: {buffId: 1}, score}`（已验证 pointCost == 已解锁节点 tokenCost 总和）。

**解锁**（`rlv2.ts` `unlockBuff(theme, buffId)` + `router/roguelike.ts` `POST /roguelike/upgradeOutBuff`）：
- 校验：节点存在 → 未解锁 → 前置（frontNodeId 数组）全部解锁 → pointOwned ≥ tokenCost
- 成功：pointOwned -= tokenCost、pointCost += tokenCost、unlocked[buffId] = 1
- 请求体 `{theme, id}`（兼容 buffId 字段名）；失败返回 `{result: 1, errorMsg: NODE_NOT_FOUND/ALREADY_UNLOCKED/FRONT_NOT_UNLOCKED/POINT_NOT_ENOUGH}`
- 注意：update（Immer）替换 _playerdata 后需刷新 `this.outer` 引用

**加成**：`buff.ts create()` 开局应用 `outer[theme].buff.unlocked` 的 outbuff（已有）——新解锁节点下一局生效。

**探索分数结算**（`gameSettle()`，官方公式，用户提供 2026-08：萨卡兹方式，各主题一致）：

| 项目 | 分值 |
|---|---|
| 通过层数（档位 0/30/80/150/270/400/550/650，>7 按 7） | 档位值 |
| 通过步数（trace.length） | ×1 |
| 普通战斗次数（trace 节点 type 1） | ×10 |
| 招募干员次数（recruit.tickets[].result 非空） | ×2 |
| 获得物品数（收藏品 relicList + 战术道具 activeToolList，不含思绪） | ×5 |
| 领袖战斗次数（trace 节点 type 4） | ×30 |
| 精英战斗次数（trace 节点 type 2） | ×20 |

求和 × 难度倍率（`details[theme].difficulties[].scoreFactor`，按 mode+modeGrade 匹配，MONTH_TEAM/CHALLENGE=0）= 探索分数；默认分数→魂灵书签转换效率 1:1（`score += 探索分数`、`pointOwned += 探索分数`）。历史重构提升转换效率暂未实现（YAGNI）。

**注意**：createGame 把 MONTH_TEAM/CHALLENGE mode 转成 NORMAL（现有行为），实际结算按 NORMAL 倍率；若需 MONTH_TEAM=0 需改 createGame 保留 mode。

---

## 17. 子域名分发与远程配置

### 17.1 子域名分发（app/config/host-router.ts）
私服场景：客户端通过改 hosts/DNS 将 `*.hypergryph.com` 指向私服，请求保留官服子域名 Host 头。`createHostRouter()` 中间件按子域名映射：
- `as.hypergryph.com/*` → `/auth/*`（账号系统）
- `ak-conf.hypergryph.com/*` → 保持（配置：/config/prod、/api/remote_config）
- `ak-gs-gf.hypergryph.com/*` → 保持（游戏：/account、/user 等）
- `game-config.hypergryph.com/*` → 保持（新版远程配置）
- 非 `*.hypergryph.com`（localhost/IP 直连）不重写

**mitmweb 重定向场景**（`mitmweb -M "|^https?://.*\.hypergryph\.com(.*)|http://127.0.0.1:8443\1"`）：
mitmproxy map remote 设置 URL 时会同步改写 Host 头为 `127.0.0.1:8443`，子域名信息丢失。此时启用**路径级兜底分发**（`applyPathFallback`）：
- `/game/*` → 剥 `/game` 基址前缀（ak-gs 域路径化形式）
- `/app/*`、`/u8/*`、`/user/auth*`、`/user/info*`、`/user/online*`、`/user/oauth2*` → 加 `/auth` 前缀（as 域接口）
- 游戏域 `/user/changeSecretary`、`/user/buyAp` 等二级段不在列表，不会被误判

**客户端事件批量上报**：`POST /batch_event`（游戏域根级接口，home.ts）——客户端定期上报行为事件，私服返回空对象 `{}`（客户端只认状态码）。

### 17.2 新版远程配置接口（app/config/remote-config.ts）
新版客户端（game-config 域名）请求的两个接口：
- `/api/remote_config/1/prod/default/Windows/network_config` → 网络端点配置（官方扁平格式：an/as/gs/hu/u8/hv 等，域名替换为私服地址）
- `/api/remote_config/1/prod/default/Windows/remote_config` → 功能配置（官方格式：fapv2/HGDownload_1/2、enableGameBI、enableNativeLicense、bakeMuzzleEnableRate 等）

功能配置字段可在 `data/config.json` 的 `RemoteConfig` 覆盖，缺省使用官服默认值。

### 17.3 已知约束
- Node fetch 会覆盖自定义 Host 头——子域名验证需用 node http 或 curl（E2E 经验）
- 旧版 `/config/prod/official/network_config`（{sign, content} 格式）保持兼容（prod.ts 复用 buildNetworkConfigContent）

### 17.4 抓包专用官服转发模式（app/proxy/official-forward.ts，--capture）
主服务器新增可切换的抓包专用官服转发模式：`npm run start:capture`（等价 `tsx index.ts -s --capture`）或 `data/config.json` 的 `capture.enabled: true` 开启。开启后 **as/gs 流量不再由私服响应，而是转发到官服**并记录响应到 `tmp/`（capture 模式强制 `debug.recordTraffic=true`，目录格式与 test.ts 抓包一致），用于与私服响应逐接口对比 / 协议逆向。

**挂载位置**：index.ts 在 host-router + `/config/prod`、`/api/remote_config`、`/api/gate`、`/api/game`（launcher）之后、`/` auth 之前挂 `createOfficialForwarder()`。config/launcher 保持本地——客户端才能拿到指向本代理的 network_config 被引导连进来。

**路由分发规则**（`resolveForwardTarget` 纯函数，与 test.ts / §17.1 路径级兜底一致）：
- **Host 优先**：`as.*` → `as.hypergryph.com`（路径原样，官服无 /auth 前缀）；`ak-gs-*` → `ak-gs-gf.hypergryph.com`（剥 `/game` 基址前缀，本地挂载点同样排除）；其余 `*.hypergryph.com`（ak-conf/game-config 等配置域）→ 不转发，保持本地
- **路径级兜底**（Host 非官服：localhost/IP 直连 / mitmweb 重写）：as 前缀 `/user/auth|info|online|oauth2`、`/u8`、`/app`、`/general`、`/as`（剥路径化前缀）→ as 域；`/game/*` → gs 域（剥前缀）；**其余 POST** → gs 域根路径兜底（/account、/shop、/activity、/user/checkIn 等），但**排除本地挂载点** `/admin` `/assetbundle` `/pcSdk` `/config` `/api` `/audit` `/arkodc` `/batch_event`（管理/配置/事件上报由私服响应——`/batch_event` 由 home.ts 返回 `{}`，转发官服只得 404 噪音，用户明确要求不转发；Host 级 ak-gs-* 分支同样排除）；GET 非 as 路径不转发（保持本地响应）
- 官服对双斜杠路径返回 404，endpoint 统一归一化去前导斜杠；`validateStatus: () => true` 原样透传官服 401/400 等状态；网络层错误（官服不可达）返回 502
- **content-length 剥离**（2026-08-09 修复）：客户端原始 body 可能带空白/换行（实测 oauth2/v2/grant 原始 94B、解析后重序列化 74B），透传 `content-length` 会让官服按声明长度等剩余字节而**永久挂起**（`POST /user/oauth2/v2/grant` 20s 无响应）。转发头剥离 `host`/`content-length`/`transfer-encoding`，由 axios 按实际 body 重算。test.ts 同步修复。
- **/u8 双写修复**（2026-08-09）：路径级兜底的 as 前缀 baseUrl 一律为 as 域根地址、path 保留完整原路径（含 `/u8`）——若 baseUrl 再拼 `/u8` 基址会与 path 里的 `/u8` 双写（实测 `as.hypergryph.com/u8/u8/user/v1/getToken` → Go 404，修复后 400 字段校验）。test.ts 的 `app.post("/u8/*endpoint", ...)` 通配符不含 `/u8` 前缀，无此问题。
- **multipart 原始字节透传**（2026-08-09 修复）：非 JSON 请求（实测 `POST /activity/arkhub/savePixelArt` 为 multipart/form-data 2106B）`express.json` 不解析 → `req.body` 为空 `{}`，透传会让官服 400 `"Invalid multipart payload format"`。index.ts capture 块在 `bodyParser.json` 后挂非 JSON 原始体捕获中间件（`req.rawBody`），转发器 POST 时优先用 `rawBody` 原样透传字节（content-length 已剥离由 axios 重算）。test.ts 同步修复。

**登录链路**：客户端经本地 network_config 连到本代理 → `/user/auth/*`、`/u8/*`、`/user/oauth2/*` 转发 as 域拿到**官服真实 token** → `/account/login` 等 gs 请求带真实 secret 转发 `ak-gs-gf` 由官服校验。转发命中后不 `next()`，私服 authMiddleware/游戏路由不参与，故不受单例 secret 强制影响。

### 17.5 arkhub 网关特殊适配（app/proxy/arkhub-gateway.ts）
阿卡狄亚（arkhub）是独立实时网关玩法：`POST /activity/arkhub/enterHall` 响应返回 `{ result, endpoint: "arkhub-gateway.hypergryph.com", port: 30000 }`，客户端随后用 BestHTTP WebSocket 连该网关（私有协议，明文 TCP；TLS 握手被直接断开、明文 WS 握手无响应）。capture 模式两项适配（2026-08-09）：
1. **enterHall 响应改写**：`createOfficialForwarder` 收到 `arkhubGateway` 选项且路径为 `/activity/arkhub/enterHall` 时，把 `endpoint` 改写为 `config.Host` 去 scheme、`port` 保持网关端口——否则客户端直连官服网关（hosts 重写时连 127.0.0.1:30000 无监听而失败，且网关流量不经过代理）。非网关形状响应（如 401）原样透传。
2. **TCP 转发器（端口自动避让）**：`startArkhubGatewayProxy` 首选 `config.capture.gatewayPort`（缺省 30000），被占时自动尝试下一个空闲端口（port, port+1, ... 最多 50 次）——多实例并存时每个实例各拿一个空闲端口（如 30000/30001/30002），enterHall 改写用**实际监听端口**，客户端互不干扰。返回 `{ server, port, exhausted, adjusted }`：全部避让端口被占（exhausted，极罕见）时仍改写指向配置端口（其上大概率有另一实例转发器）。每个连接建立到官服网关的透传管道（纯 TCP pipe，不做协议解析——客户端自带上层握手/鉴权），双向字节流落盘 `tmp/arkhub-gateway/{connectionId}/`（up.bin=客户端→官服、down.bin=官服→客户端、meta.json）。实现注意：每次尝试**新建 server**（复用同一 server 重 listen 有回调错乱问题，实测 adjusted 结果错乱）。

**与 test.ts 关系**：test.ts（`npm run ts`，8444）是独立纯转发抓包代理，规则同源但可独立运行；本模式把同一套规则并入主服务器（8443），免去另起进程。**账号说明**：capture 模式用官服账号登录（reference/checkin-master/accounts.txt），与私服账号体系互不相通。

### 17.6 管理后台像素画工具 + 上传官服（2026-08-09）
Dashboard 新增「像素画」Tab（app/admin/dashboard/index.html `loadPixelPane`）：24×24 画布编辑器（40 色调色板绘制/橡皮擦/清空/示例），下载 PNG / 像素数据，上传官服。

**像素数据格式**（逆向确认）：24×24×3 RGB 共 1728 字节，空白 (255,255,255) 为透明背景；md5 即 1728 字节的 md5（`RequestPixelArtUploadTokenReq` 的 Md5 字段）。工具模块 `app/admin/arkhub-pixel.ts`（PIXEL_PALETTE 默认 40 色——官服热更 display_meta_table.pixelMapData.paramMap.htmlColors 本地为空，可替换）。

**上传官服流程**（`official-ops.uploadPixelArt`，`/admin/api/pixel/upload-official`）：
1. `OfficialSession.login`（HTTP 会话）→ uid/secret
2. **网关**（app/admin/arkhub-gateway-client.ts）申请上传 token：帧 `[4B 大端总长含自身][4B mainID][8B subID][protobuf]`；UserLoginReq mainID=4 subID=0x0fa1（HTTP secret 可直接网关登录，code 100=OK、112=RelayLoginSuccess 表示账号已有活动会话）；RequestPixelArtUploadTokenReq mainID=8 subID=0x00029CE231D603B3，消息体 `[4B 递增序列前缀][field2=Md5]`，响应 subID=0x00029CE231D60CF6 `[前缀][Code][Credential{pixelArtId,uploadToken,expireTime}]`
3. **HTTP multipart 上传** `POST /activity/arkhub/savePixelArt`（与真实客户端字节级一致）：`json` part（name="json" filename="json_info"，body=`{"brief":{"activityId":"act1arkhub","token":"<token>"}}`）+ `pixelData` part（name="pixelData" filename="pixelDataFile" Content-Type=multipart/form-data，1728B）
4. **网关保存确认** SavePixelArtReq mainID=8 subID=0x00029CE231D674D5 `[PixelArtId][UploadSuccess=1][DoPublish=0]`

**实现要点（2026-08-09 已端到端验证）**：登录后须发**场景 hello**（mainID=8 subID=0x00018FB64DE29CDB proto=`08 00`）并等约 1.5s 让场景数据就绪，token 请求才可用（缺 hello 时服务器关连接）；close 时发登出帧（subID=0x0002C89B38B3C3C9 proto=`08 01`）释放会话绑定。**限制**：账号同时只允许一个活动网关会话（重复登录返回 112 中继，RelayLoginSuccess），旧会话过期（约 1-3 分钟）后恢复；失败时给出可操作错误。已实测上传成功：pixelArtId 返回、getPixelArt 可查。

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

---

## 19. 用户创建与自动注册

### 19.1 创建方式（三种等价入口）
| 入口 | 说明 |
|------|------|
| `POST /auth/user/auth/v1/token_by_phone_password` | **登录自动注册**：手机号+密码不存在时自动创建用户并返回 token（新 uid） |
| `npm run admin -- users create <phone> [password]` | 管理后台 CLI 创建 |
| Dashboard「+ 创建用户」 | Web 管理界面创建 |

### 19.2 实现（AccountManager.registerUser）
- **模板复制**：以 `data/user/databases/1.json` 为模板深拷贝，替换 uid/昵称（博士{uid}）/注册时间
- **uid 递增**：现有账号最大值 +1
- **注册**：写入 `databases/{uid}.json` + SQLite `users` 表（auth.phone=手机号、hgId=uid、password=密码；users.json 已迁移为种子不再写入）
- **secret 生成**：`generateSecret(phone)` = MD5(phone + 渠道密钥)（确定性）——token=secret 语义（参考 DoctoratePy）
- **查重**：手机号已存在抛错

### 19.3 数据流
1. 客户端输入新手机号+密码登录 → `tokenByPhonePassword` 未匹配 → `registerUser` 自动创建 → 返回账号 secret 作为 token（**不是 uid**——旧实现返回 uid，2026-08 对齐 DoctoratePy token=secret 模型）
2. 后续 `grant`/`getToken`/`syncData` 走标准流程（token=secret 或 uid 兼容）
3. 管理后台 CLI/Dashboard 的 createUser 复用同一注册逻辑（DRY）

### 19.4 已知约束
- 模板存档缺失（1.json 被删）时注册失败并给出清晰错误
- 新用户昵称固定「博士{uid}」、等级/资产继承模板（1 号账号）——私服简化
- 服务器运行中注册的新用户**免重启**：`getPlayerData(uid)` 懒加载（`_loadPlayer`）——data 缺失时自动从 `databases/{uid}.json` 读取并加载（与 init/ensureSingleUser 共用加载逻辑）

### 19.5 完整 Token 登录流程（2026-08-07）
客户端登录链路（对齐 DoctoratePy `server/account.py` accountLogin）：

```
① POST /user/auth/v1/token_by_phone_password {phone, password}
      → {data: {token}}                                   [as 域，账号 token = secret]
② POST /user/oauth2/v2/grant {appCode, token}
      → {data: {code, uid}}                               [as 域，授权码]
③ POST /account/login {token, clientVersion, networkVersion}
      → {result:0, uid, secret, serviceLicenseVersion:0, majorVersion:"446"}   [gs 域，换游戏凭证]
④ 客户端所有游戏请求带 secret 头 → authMiddleware 解析玩家
      single：强制 secret=singleUid（任意 token 收敛）
      real：getUidByToken(secret) → getPlayerData(uid)，无效 401
```

关键实现：
- **`/account/login` 按 token 动态解析**（`app/game/router/account.ts`）：读 `req.body.token` → `accountManager.getUidByToken(token)`（real 按 uid/secret 双查；single 任意 token 收敛 singleUid）→ 返回动态 `uid` + `secret`（账号 secret，无则回退 uid）——**无效 token 返回 `{result: 3}`**（参考 DoctoratePy「记忆已经模糊，请重新输入登录信息」）
- **版本校验 YAGNI**：`clientVersion`/`networkVersion` 读取但不拦截——私服客户端版本可能滞后于配置（用户不跑 update），严格校验（result 2/5）会卡登录且客户端不报原因；版本同步由 `syncGameVersion`（22 章）负责
- **`getTokenByUid(uid)`**：返回 `configs[uid].secret || uid`（完整 token 语义；旧账号无 secret 回退 uid）
- **`getPlayerData(uid)` 懒加载**：data 缺失时 `_loadPlayer` 从存档文件读取——real 模式注册新账号后登录/同步免重启
- **防御**：`/account/syncData`、`/account/syncStatus`、`/account/syncPushMessage` 在 `httpContext` 无 playerData（real 模式无 secret 头）时返回 **401** 而非 500
- **`loginout`**：返回 `{result: 0}`（对齐 DoctoratePy onlineV1LoginOut）

---

## 20. 服务端性能评估与优化

### 20.1 实测基准（2026-08-06，真实存档 + 本地压测）
| 指标 | 实测值 |
|------|--------|
| 启动耗时 | excel 927ms + accountManager 123ms ≈ 1.05s |
| 请求延迟（/account/syncStatus ×100） | p50 22ms / p95 37ms / p99 109ms |
| 内存 | RSS 455MB（heap 230MB——excel 154.6MB 源文件对象驻留） |
| 存档序列化 | 6.6ms/次（1.3MB JSON） |
| 磁盘写 | <1ms（1413MB/s） |

### 20.2 已实施优化
1. **原子写**（`savePlayerData`）：先写 `{uid}.json.tmp` 再 `rename`——避免写盘中断导致存档截断损坏（评估中发现 1.json 曾损坏）——`perf(auth): 存档原子写与防抖合并保存`
2. **防抖合并**（`scheduleSave`/`flushSave`）：save 事件改为 500ms 防抖——窗口内多次变更只落盘一次（多玩家/高频请求场景每请求省 ~6.6ms 序列化）；`flushSave(uid)` 可显式立即保存（服务器关闭时调用）——同上提交
3. **excel 并行加载**：`excel.init` 的 44 个串行 `await readJson` 改为 `Promise.all` 批量加载（loaders 数组）——IO 重叠，启动 927ms → 848ms（~9%）；收益受限于 JSON.parse 单线程 CPU——`perf(excel): 数据表并行加载`
4. **syncData 直改时间戳**：登录全量同步改为直改 `pushFlags.status`（免 Immer update 与存档防抖保存）；实测基线 avg 20.7ms / p95 52ms（响应 1290KB）——大头为 1.3MB 序列化（不可避免），Immer 惰性代理本就不深拷贝全量——`perf(sync): syncData 直改时间戳`

### 20.3 待优化项（YAGNI 暂缓）
- **excel 懒加载**：启动 927ms 主要耗时（154.6MB JSON 全量 parse）——可改为按需加载 + 缓存（收益：启动降至 ~200ms）
- **存档拆分**：玩家活跃/历史数据分文件——降低单次序列化体积
- **多实例内存**：excel 对象驻留 230MB heap——多开场景注意

### 20.4 评估结论
单玩家私服场景性能充足（p95 37ms，余量 5 倍以上）；已实施原子写保证数据安全；防抖为多玩家场景预留扩展。

---

## 21. 服务器地址配置

### 21.1 Host 默认值
`data/config.json` 的 `Host` 默认 `http://127.0.0.1`（本机/模拟器连接）——不再硬编码局域网 IP。

### 21.2 auto 自动检测
`Host` 设为 `http://auto` 时，启动自动检测本机**第一个非回环 IPv4**（`os.networkInterfaces`）——真机/局域网连接场景（换网络环境无需改配置）；无局域网 IP 时回退 127.0.0.1。

```json
{ "Host": "http://auto" }   // 自动检测局域网 IP
{ "Host": "http://127.0.0.1" }  // 本机/模拟器（默认）
```

客户端通过 `network_config` 接口（gs 字段）拿到实际连接地址。

---

## 22. 资源与版本自动同步

### 22.1 触发时机
- `npm run update`（CLI 手动）
- 服务器**在线模式**启动（index.ts 自动调 `updateModule.main(false)`）
- 离线模式跳过（不联网）

### 22.2 更新流程（scripts/update-data.ts main）
1. **仓库更新**：git pull/clone `ArknightsGameData`（OpenArknightsFBS 依赖已移除，类型改由 CS 反编译源生成）
2. **数据复制**：excel JSON（zh_CN/gamedata/excel + battle + levels）→ `data/excel/`
3. **类型生成**：`generate-types.ts`（统一 CS 反编译源生成器 → `types-playerdata.ts` + `types_excel_gen.ts`，原 FBS 版 generate-types.ts 已删除）
4. **gacha 合并**：`data/gacha/` → `gacha_detail_table.json`
5. **版本同步**（`syncGameVersion`）：调官服 `ak-conf.hypergryph.com/config/prod/official/Android/version`（复用 `scripts/official-api.ts` 的 `getResVersion`）→ 更新 `data/config.json` 的 `version`（clientVersion/resVersion）——客户端版本接口/热更新列表据此工作

### 22.3 实测
`syncGameVersion` 真实拉取：`2.5.60/25-05-20-12-36-22_4803e1 → 2.7.61/26-08-03-23-34-20_a745fc`（版本无变化时跳过写盘）。

### 22.4 注意
- **版本与资源需同步更新**：单独跑 syncGameVersion 会得到新版本号但本地 excel/assets 仍是旧数据（客户端请求新资源会 404）——正确做法是完整 `npm run update`（数据+版本一起）
- 版本更新后需重启服务器生效（config 启动时读取）

---

## 23. OBS 缺失 API 移植记录（2026-08-08）

### 23.1 背景
以 `reference/OpenBachelorS-master`（EN 版 FastAPI 私服）为参考，补齐 DoctorateTs 缺失/拼错的 API。对比工具：`scripts/_diff-routes.py`（挂载感知路由 diff，140 条 OBS 路由未覆盖 → 122 条，P1 全部覆盖）。

### 23.2 修正（P0，api.md 契约）
- `/gacha/cancleNormalGacha` → `/gacha/cancelNormalGacha`（拼写）
- `/mail/listMailbox` → `/mail/listMailBox`（大小写；Express 匹配大小写不敏感，行为等价）

### 23.3 新增端点（P1，参考 OBS bp 蓝图）
quest: battleContinue / finishStoryStage（委托 BattleManager.finishStoryStage）/ editStageSixStarTag
gacha: choosePoolUp（gachaRuleType 反查池类型，写 `gacha[type][poolId].upChar`）/ getFreeChar（空操作）
charBuild: changeSkinSpState（`skin.skinSp[skinId]`）
social: setStarFriendList（空实现）
mailCollection: getList（新 router，挂 `/mailCollection`，读 `DisplayMetaTable.mailArchiveData`）
medal: setCustomData（`medal.custom.customs["1"]`）
gallery: saveDiyMagazineV2（与 V1 共用 saveDiyMagazine 逻辑）
retro: typeAct20side/competitionStart + competitionFinish（固定 stub）
home: firework savePlateSlots/changeAnimal、car confirmBattleCar、templateTrap setTrapSquad、troop pinSpecialOperator
auth: `/u8/user/auth/v1/agreement_version` POST 别名（响应同 GET）

完整清单见 `api.md`「OBS 移植端点」附录。

### 23.4 冒烟验证结论
- 新端点：mailCollection/getList、quest/battleContinue、car/confirmBattleCar、retro/vecbreak 双前缀均 200
- **双前缀修正（2026-08-09）**：原记录「/retro/*、/campaignV2/* 双前缀为既有设计」经全量客户端路由核对确认为 bug——客户端调用单前缀（`/campaignV2/battleStart`、`/retro/unlockRetroBlock`），双前缀命中不到；已补根挂载使单前缀可用（双前缀仍兼容，见下节）。
- **已知问题（非本次引入）**：`POST /gacha/cancelNormalGacha` 对 uid=1 满级号返回 500（recruit.cancel 内部异常，路由命中正常），待单独排查
- **P2 部分完成（2026-08-08，参考 DoctoratePy/CS 2.7.61/抓包）**：bossRush（尖灭测试）模块已实现——`/activity/bossRush/battleStart|battleFinish|relicSelect|relicUpgrade`（battleStart/battleFinish 复用标准战斗结算 + 尖灭专属 wave/milestone/token/best 更新，掉落加值数据驱动），并修正 `/activity/rewardMilestone` 对 BOSS_RUSH 活动写入 `milestone.got`（对齐官服快照结构）。
- **P2 补全（2026-08-08 续）**：enemyDuel（怪猎对决 8 路由，排行榜 NPC 填充）、act24side（怪猎 6 路由，合成抽奖数据驱动）、act25side（生息演算 6 路由）、football、act29side、act36side、trainingGround、aprilFool act3fun/act4fun/act6fun/act7fun 补全，以及 act13side/act1vhalfidle/act27side/act35side/act38side/act42d0/act42side/act44side/act45side/act46side/actBlessOnly/actCheckinAccess/loginOnly/prayOnly/year5General/teamQuest/typeAct3d0/typeAct4d0/typeAct5d0/typeAct5d1/typeAct9d0/typeAct20side/arcade/autochessSeason 约 110 条 stub（参考 ODPY 202 stub）。
- **路由前缀修正（2026-08-08）**：客户端将 roguelike/interlock/vecBreakV2 挂在 `/activity` 前缀下（`/activity/roguelike/*` 等），但既有 router 自带 `/roguelike|/interlock|/vecBreakV2` 路径 —— 在 app.ts 补 `/activity` 挂载别名；act25side/act29side/act36side/trainingGround/actcheckinvs 为根路径路由，新增 activity 模块 `rootRouter`（同 user.ts 模式）挂载到 `/`，修复合签到 `actCheckinvs/sign`（客户端 `/actcheckinvs/sign` 根路径调不到）的隐藏缺口。
- **全量客户端路由覆盖（2026-08-09，541 条客户端游戏路由逐一 curl 冒烟，404 清零）**：
  - campaignV2/retro 的 router 自带模块前缀 + 既有 `/campaignV2|/retro` 挂载产生双前缀，客户端调用单前缀 —— 补根挂载（双前缀仍兼容）
  - `/crisis/getInfo` 客户端路径别名（既有 `/getCrisisInfo` 客户端调不到）；`/crisisV2/*` 用 URL 重写中间件别名到 `/crisis/v2/*`
  - `/sandboxPerm/sandboxV2|V3/*` + `/sandboxPerm/changeTopic|pinTopic` URL 重写别名到 sandbox router 的 `/v2|/v3|/changeTopic|/pinTopic`；补 6 条 racing stub
  - `/activity/multiplayerV3/*` 补 /activity 挂载别名；`/rune/battleStart|battleFinish` 新 router（复用标准战斗）；`/vecBreakV2/getSeasonRecord` 根挂载
  - rlv2 补 31 条缺失路由（buyGoods 接线控制器已实现方法 + bank/copper/gridZone/nodeMission 等 rogue_3/4/5 stub）；quest 补 getCowLevelReward/getMainlineRecordRewards/getMainlineCache/unlockStageFog/unlockHideStage；mission 补 confirmMissionList/confirmMultiGroupMissionList
  - 杂项：shop/buyREPGoodWithTicket、social/getFriendAndRequestSendList、tower/seasonMissonsAward（客户端拼写）、gacha 裸 `/gacha`、autoChess/act1|act2autochess、audit/official/*（新 router）
- **rlv2/selectChoice 接线修复（2026-08-08）**：控制器已实现（§16.5）但路由未暴露，已补 `POST /rlv2/selectChoice`（CS: RoguelikeSelectChoiceRequest，抓包 body `{choice}`）
- **pay 补全（2026-08-08，参考 DoctoratePy + 抓包）**：新增 `/pay/createOrder`（返回对齐抓包形状的 extension JSON）与 `/pay/confirmOrder`（现金包 CS_ 复用 shop.buyCashGood 发放钻石，含首充双倍）；订单存内存 Map，重启即失效（私服可接受）
- **arkodc 模块（2026-08-09，参考 OBS misc_bp + CS ArkOdc 类 + ODPY arkodc 类）**：`/arkodc/battleStart|battleFinish`（战斗 stub）、`/arkodc/savePosition`（写 `arkodc.topics[topicId].position`）、`/arkodc/triggerInteraction`（awardId 标记 `rewards[awardId]=1`）、`/arkodc/restart` —— 根路径挂载
- **稀有度索引修复（2026-08-09，实机冒烟发现的真实 bug）**：`CharacterTable.rarity` 为字符串枚举 `"TIER_N"`，但 char/recruit 多处按数值下标/比较使用（`maxLevel[rarity]`、`evolveGoldCost[rarity]`、`data.rarity === 5`、`charsList[rarity]` 字符串键 vs 数值键）→ upgradeChar/evolveChar 500、公共招募星级分组/高星 tag 失效、rlv2 招募免费稀有度升级失效。新增 `@utils/rarity`（`rarityToIndex` TIER_N→N-1）并全量修复 char.ts/recruit.ts/rlv2 recruit.ts；upgradeChar/evolveChar 补 maxLevel/evolveCost 防御钳制。验证：实机 upgradeChar（char 2 正常升级）、evolveChar（含 null evolveCost 的预备干员）均 200。
- **ODPY 缺失清单逐条核对（2026-08-09，`scripts/_audit-odpy-gaps.py`）**：ODPY 663 条路由中 DoctorateTs 未覆盖 260 条，逐条 curl 冒烟标注——**已覆盖 174**（HTTP 200/202/500 路由命中，含 sandboxPerm 72 条、crisisV2 7 条、campaignV2/retro 5+5、rlv2 28、aprilFool 11 等）+ **设计跳过 68**（单账号 auth 19、yostar 4、支付变体 9、admin 5、遥测/埋点 8、config/remote_config 变体 8、GET 覆盖 5、ODPY 独有 3 等）+ **需补充 16 全部分类为已覆盖**（remote_config 4 条为 GET 覆盖、shop `<string:shop_type>` 模板 3 条由具体路由覆盖、静态资源 gallery/jpg + announce/images + assetbundle 302 等路径参数路由为设计跳过/静态资源）
- **既存未决项处理（2026-08-09）**：
  - `gacha/cancelNormalGacha` 满级号 500 已修复——根因是客户端请求未初始化的招募槽位（满级号仅 4 槽但客户端发 slotId 4/5），recruit.cancel 补缺失槽位初始化守卫（不再 500）
  - `gallery/jpg`、`announce/images` 静态图片路由已补齐——私服无素材文件，返回 1x1 透明 PNG 占位图（客户端不再收 HTML 404）
  - **syncData 对齐决策（用户确认）**：保持现状（Immer 单点 patch + 刷新 pushFlags，客户端实测可用）；移除 delta.ts 未接线的 `buildSyncDataDelta`/`SYNC_DATA_DELTA_KEYS` 死代码与 account.ts 未使用 import
  - **目标完成边界（用户确认）**：参考项目全量对齐（ODPY 663 条全量覆盖，含此前标注的设计跳过项）
- **参考项目全量对齐（2026-08-09，用户确认边界后实施）**：ODPY 260 条缺失清单 → **已覆盖 256 / 设计跳过 2（/arknights 子域名转发、/api/game/<subpath> catch-all 已补）/ 需补充 0**；OBS 105 条缺失运行时复核 **0 个 404**；DoctoratePy 36 条缺失全部补齐（pay alipay/wechat/success、/login、shop/buyFurniGroup、quest/changeSquadName2 别名、旧版 auth 路径 11 条 URL 重写别名）。新增 `router/misc-alignment`（遥测/pay 变体/api 端点/yostar/common EN stub 约 30 条）、launcher catch-all、building/getMessageBoardContent、config prod b/network_config、remote_config bilibili/101 变体。

- **基建系统修复（2026-08-09，审计发现 7 项问题后修复 5 项核心）**：
  - 制造站生产随时间累积：`sync()` 新增 `_accrueManufacture`（房间 capacity × 流逝时间 → processPoint，每满 formula.costPoint 产 1 批，remainSolutionCnt 递减/outputSolutionCnt 递增）；`changeManufactureSolution` 改为从 0 开始累积（remainSolutionCnt=目标，outputSolutionCnt=0）而非立即满产——生产速度 buff 与时间挂钩
  - 贸易站订单补充：`sync()` 新增 `_refreshTradingOrders`（工作时间 stock < 2 单时按 3003×汇率生成金币订单，结构与官服样本一致）——原实现无生成逻辑，交付完即枯竭
  - 余额校验：制造结算/加工合成按可承担次数部分结算，避免负库存/负金币
  - `deliveryOrder` 按客户端指定 instId 结算（原忽略 orderId 总结算队首）
  - 非法 roomSlotId 守卫：settleManufacture 等不再 500
  - 训练室 `_accrueTraining`：trainee.processPoint 随时间累积（进度显示一致；完成仍由客户端 completeUpgradeSpecialization 驱动）
  - 单测 5 条 + 实机冒烟（settle slot_999 200、清空 stock 后 sync 补 2 单、8 秒产出 processPoint=486 与 54×9s 吻合）


- **抽卡系统修复（2026-08-09，用户报告 tenAdvancedGacha 500）**：
  - 缺详情卡池回退：`gachaPoolClient` 有但 `gacha_detail_table.details` 缺失的 5 个池（LIMITED_76_0_1/SINGLE_75_0_3/DOUBLE_75_0_4/CLASSIC_DOUBLE_75_0_1/CLASSIC_DOUBLE_76_0_1）抽卡不再 500——`_poolDetail` 回退到首个结构完整池（去 UP 走通用池）+ WARN 记录；`gachaPoolClient.find()!` 补守卫（池完全缺失回退 NORMAL）；`_getRarityRank` 空 perAvailList 防御
  - **char:get 订阅 bind 丢弃 bug（重大）**：`char.ts` 原 `this._trigger.on("char:get", () => { this.onCharGet.bind(this); })` 把 bind 结果丢弃，`onCharGet` 从未执行——**抽卡/招募的干员从未真正入账**（charGet 响应只有 logInfo、无 charInstId/charId/itemGet）。改为异步闭包调用后，抽卡完整返回 char 数据（潜能/兑换物正确发放）；onCharGet 签名兼容事件可选参数
  - 单测 2 条 + 实机验证：正常池与缺详情池十连均返回完整干员数据

  - ruleType 缺失处理（续）：gachaPoolClient 中 DOUBLE(37)/CLASSIC_DOUBLE(31)/BACKFLOW(1)/SPECIAL(7) 共 76 个池的 ruleType 不在 funcs 映射 → funcs[ruleType] is not a function 500；补齐四类走通用 _handleGacha + 调用处防御回退 NORMAL。实测四类池抽卡均 200 且新干员入账

- **getGoodPurchaseState 响应形状修复（2026-08-09，用户报告 41KB 响应异常）**：CS 协议（GetGoodPurchaseStateResponse { result: Dictionary<string, int> }）与抓包均要求扁平 `{goodId: 1|-1}`（1=可购买/-1=已购买），原实现直接返回各商店原始 info 数组（41KB 且形状不符，客户端无法解析限购状态）。已按客户端 goodIdMap 重写：常规商店读 `.info`、GP 嵌套结构展平；响应从 41KB 降到 306 字节。单测 2 条。

- **charRotation/setCurrent 500 修复（2026-08-09，用户报告）**：满配号生成器重排 charInstId，预设 preset.profileInst（138/1）指向不存在的干员 → `draft.troop.chars[profileInst].charId` 崩溃。已加守卫：未知预设直接返回；profileInst 查不到时回退到 profile 字符串（"char_xxx#皮肤" → charId）。实测 preset 1 → secretary=char_1012_skadi2、未知预设 200。单测 2 条。

- **招募结算响应缺 result 修复（2026-08-09，用户报告 finishNormalGacha 客户端提示异常）**：CS FinishNormalGachaResponse/CancelNormalGachaResponse 均要求 `result: Int32`，原实现缺失 → 客户端解析异常。已补 `result: 0` 并更新协议类型为必填；实机验证 finishNormalGacha/cancelNormalGacha 均返回 result: 0。单测 1 条更新。

- **shop/decomposePotentialItem 500 修复（2026-08-09，用户报告）**：`potentialMaterialConverter.items` 按数值键（0~5）索引，而 `CharacterTable.rarity` 为字符串枚举 "TIER_N"——`items["TIER_5"]` undefined → `item.id` 500。用 `rarityToIndex` 修复 troop.ts 两个分解方法（decomposePotentialItem/decomposeClassicPotentialItem）+ 不存在的干员/无配置防御。单测 3 条（含字符串 rarity 场景）。

- **storyreview/readStory 500 修复（2026-08-09，用户报告）**：原实现把完整 storyId 当 group key 查（`groups["act6d5_level_act6d5_st02"]` undefined）→ `.stories` 崩溃；正确 group 应为 storyId 前缀（如 act6d5）。新增 `_groupKeyOf`：组 key 直接匹配 → 最长前缀匹配（兼容多下划线组名）→ DoctoratePy 首段+min→mini 兜底；unlockStoryByCoin/readStory/rewardGroup 全补守卫与去重。实测 readStory rc 正确递增、未知 group 200。单测更新 3 条。

- **ODPY 参考更新复核（2026-08-09）**：用户更新 opendoctoratepy-ex-public（663→668 条路由），重跑全量运行时扫描——**668 条全部覆盖，0 个 404**（新增 5 条路由均已被现有实现命中）。审计工具 `_audit-odpy-gaps.py` 复跑：已覆盖 261 / 设计跳过 2 / 需补充 0。

- **arkodc 对齐 ODPY 更新（2026-08-09）**：用户更新 opendoctoratepy-ex-public（663→668，新增 5 条均为 arkodc API），参考实现含完整逻辑（依赖 arkvent_table）。已对齐：
  - excel.ts 接入 `ArkventTable`（data/excel/arkvent_table.json，原未加载）
  - triggerInteraction 完整实现：宝箱（awardId → rewards 标记 + odcDataMap.rewardGroups 物品 + q 后缀触发关联 actor varSeqs）、任务（avgId → actorData.actorShowCondition varSeqs 推进 + 黑名单/intro/trademan 特例）
  - battleFinish：解密战斗数据判定完成（q001_logic_after_bat_p1 非中断/放弃，其余 completeState 2/3）→ actorData varSeqs 推进
  - battleStart 记录 topic（模块级）供 battleFinish 消费；restart 重置 varSeqs + position 并下发 deleted 列表
  - 实机：battleStart/triggerInteraction/restart 均 200，restart 正确返回 deleted varSeqs 列表

- **arkhub（方舟枢纽）游戏路由实现（2026-08-09，用户报告 /activity/arkhub/syncInfo 404）**：客户端 7 条路由（enterHall/getFriendUidList/getPixelArt/savePixelArt/setSecretary/setSquad/syncInfo）原未实现。按抓包实现：enterHall 返回 gateway 端点+端口、setSecretary/setSquad 更新 activity.ARK_HUB[act1arkhub]、syncInfo 空增量、getPixelArt/savePixelArt 私服空（像素画走 admin 的 arkhub-gateway-client 与官服网关通信）。全部 200 且 setSecretary 正确持久化。

- **templateShop 商店打不开修复（2026-08-09，用户报告奇象巡展/arkodc 商店）**：getGoodList 原返回空 data（商店无法打开）。已复制 ODPY 数据源 `data/shop/templateShop.json`（33 家商店含 sandbox_1/2、shop_act53side 巡展店），getGoodList 返回完整商店配置（32KB，含 shopGroup 商品）；buyGood 实现购买（扣货币→发物品→限购记录），修复 tshop 初始化崩溃。实机：getGoodList 完整返回、buyGood 无货币返回空列表不 500。

- **抽卡 charGet 响应修复（2026-08-09，用户报告）**：
  - curCharInstId 从不递增 bug：onCharGet 新干员用 `draft.troop.curCharInstId` 作为 instId 但从不 +1 → 后续新干员 instId 冲突互相覆盖。已在新干员创建后递增
  - potent 字段缺失：CS GachaResult.potent（潜能提升信息），未满潜重复干员应返回 `{delta, now}`。已实现（potentialRank < maxPotentialLevel 时返回）
  - 单测 2 条

- **building/setPrivateDormOwner 破坏存档修复（2026-08-09，用户报告）**：CS 字段名为 `charInsId`（大 S），原实现读 `charInstId` → undefined 被 JSON 序列化为 null → `owners:[null]` 写入存档。已改读 `charInsId ?? charInstId` 并加 null/非法 slotId 防御；实测 charInsId 正确写入数字。单测 1 条。
- **进程自动退出防护（2026-08-09，用户报告程序可能自动结束）**：Node 24 未处理 Promise 拒绝默认终止进程——`rlv2.checkZoneEnd` 的 `void this.gameSettle()` 在无进行中游戏（game 为 null）时崩溃。已加 `.catch()` 记录；index.ts 增加全局 `unhandledRejection`/`uncaughtException` 处理器（记录错误栈 + 保持进程存活）。

- **存档健康检查与自动修复（2026-08-09）**：新增 `app/game/util/save-health.ts`——加载/保存时自动检测并修复常见损坏：必填顶层结构缺失（重建）、troop.chars 非法干员（移除）、`building.rooms.PRIVATE[].owners` 含 null 条目（setPrivateDormOwner 字段名 bug 残留，过滤）、status.uid 类型（转字符串）。幂等、保守（不做破坏性重建）；修复结果 WARN 记录。实机：2222 存档 slot_47.owners [null] 加载时自动修复并落盘。单测 6 条。

- **P4 跳过**：YoStar/EN 专属（yostar/get-auth、user/login、user/quick-login、user/detail、/common/* 等）——CN hypergryph 客户端不调用（全量对齐后已补 stub，路径可达）

## 24. 状态管理技术约定（2026-08-11 增补）

### 24.1 共享引用与 Immer 克隆（A2）

部分管理器持有 `_playerdata` 子对象的**直接引用**（非 Immer draft），并在 `update()` recipe 之外原地修改：

| 模块 | 持有引用 | 持久化机制 | 保护措施 |
|------|----------|------------|----------|
| `RoguelikeV2Controller` | `this.outer/current/pinned` | 原地写 + 全量落盘捕获 | `update()` wrapper 末尾统一刷新三个引用（Immer finishDraft 克隆被写子树后引用会指向旧对象） |
| `MedalProgress` | `this.val`（与 `_playerdata.medal.medals[id].val` 共享数组引用） | 共享引用原地写 | 构造器回填缺 val 旧数据 + `_syncToPersist()` 显式写回（自愈断链）+ `markDirty` 回调 |

**约定**：`finishDraft` 会对 recipe 中**被修改的子树**做克隆——任何「在 recipe 外持子对象引用并原地写」的代码，在该子树被 recipe 克隆后都会写到孤儿对象。因此：
- 引用刷新/显式写回必须在克隆点之后（rlv2 在 wrapper 末尾、medal 在进度更新事件里）；
- 绕过 `update()` 的直接变更**必须**调 `player.markDirty()`（条件落盘只保存有变更的请求）；
- 新增此类模式时优先走 `update()`，或严格按上表补齐刷新/写回。

### 24.2 账号数据存储演进方向（B2，YAGNI 暂缓）

现状：玩家账号为 JSON 全量落盘（`data/user/databases/{uid}.json`，满配号 ~5.4MB，已紧凑化 + 条件落盘降频）；账号配置/社交/回放/结算信息已 SQLite 化（social.db：users/friends/visited/replays/battle_infos 表）。

**方向（未实施）**：玩家账号主体 SQLite 化或增量补丁日志，替代全量 JSON dump。当前 JSON 全量 dump 在条件落盘 + 紧凑化后成本已大幅下降，单账号私服场景足够；多账号/频繁落盘场景再迁移。
