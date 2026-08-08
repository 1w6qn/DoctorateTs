# DoctorateTs

明日方舟（Arknights）私服模拟器，TypeScript + Express 5 实现。数据全部本地 JSON，无数据库依赖。

## 快速开始

```bash
npm install
npm run update     # 拉取并生成游戏数据（离线环境用 npm run update:skip 或 --offline）
npm start          # 启动服务器（默认端口 8443，见 data/config.json）
```

**一键启动（Windows）**：双击根目录 `start.cmd` —— 跳过联网更新快速启动，服务就绪后自动打开管理后台（`http://localhost:8443/admin/dashboard`）。等效命令：`npm run start:quick`（等价于 `tsx index.ts -s`）。

三种启动模式：

| 模式 | 触发方式 | 说明 |
|------|----------|------|
| 在线更新（默认） | `npm start` | 拉取远程数据，失败自动回退本地缓存 |
| 跳过更新 | `--skip-update` / `-s`，或 `npm run start:quick` | 跳过 git，使用本地数据，快速启动 |
| 完全离线 | `--offline` / `-o`，或 `data/config.json` 中 `"offline": true` | 零网络，启动前校验本地 66 个数据文件 |

## 管理功能

### 命令行（无需启动服务器，完全离线可用）

```bash
npm run admin                                   # 无参数进入交互模式（REPL）
npm run admin -- users list [--json] [--csv]    # 列出所有用户（支持 JSON/CSV 输出）
npm run admin -- users info 1                   # 查看用户详情（含中文物品名）
npm run admin -- users create 13800000000 123456   # 创建用户（模板复制）
npm run admin -- users grant 1 4001 100         # 发放物品（支持中文名/别名，如 "合成玉"）
npm run admin -- users grantchar 1 阿米娅       # 发放干员（支持中文名；重复按稀有度折算信物）
npm run admin -- users skin 1 char_002_amiya#2  # 解锁皮肤
npm run admin -- users chars 1                  # 干员列表
npm run admin -- users char 1 5 --level 90 --evolve 2 --potential 5 --skill 7   # 修改干员属性（免费）
npm run admin -- users maxout 1                 # 一键满配（资源/背包/干员/基建/皮肤，不覆盖阵容）
npm run admin -- users building 1 max           # 基建满级
npm run admin -- users backup 1                 # 备份存档（data/user/backups/）
npm run admin -- users backups 1                # 列出备份
npm run admin -- users restore 1 1-20260808-181345.json   # 从备份恢复
npm run admin -- users dump 1 [--pretty]        # 导出原始玩家数据 JSON
npm run admin -- mail send 1 标题 内容 --items 4001:100,4003:10   # 发送邮件
npm run admin -- mail send all 公告 内容 --items 4001:100         # 群发（全部用户）
npm run admin -- mail list 1                    # 查看用户邮件
npm run admin -- mail delete 1 1000000          # 删除单封邮件
npm run admin -- server status                  # 服务器状态与数据文件
npm run admin -- server refresh 1               # 触发每日/每周刷新（理智/任务重置）
npm run admin -- server save 1                  # 立即保存存档（缺省全部用户）
npm run admin -- logs show --last 20            # 查看管理操作审计日志
npm run admin -- config show                    # 查看配置
npm run admin -- config set admin.token mytoken # 修改配置（重启后生效）
```

> 物品发放支持三种写法：数字 ID（`4001`）、中文名（`龙门币`）、别名（`合成玉`）。
> 常用别名表见 `app/admin/admin-names.ts`（注意：**合成玉是 4003**，5001 是声望）。
> 所有变更操作写入审计日志 `data/admin/logs.jsonl`。

### Web Dashboard

1. 编辑 `data/config.json`：`"admin": { "enable": true, "token": "你的令牌" }`
2. 启动服务器后访问 `http://localhost:8443/admin/dashboard`
3. 输入管理令牌进入后台（10 秒自动刷新），支持：
   - **概览**：用户详情、资源/背包中文名、一键满配、基建满级、每日刷新、保存、备份/恢复
   - **干员**：干员列表 + 行内编辑（等级/精二/潜能/技能）
   - **邮件**：邮件列表/删除，弹窗支持群发（全部用户）
   - **数据**：完整玩家数据 JSON 只读查看
   - **统计**：等级分布 / 注册分布 / 资源合计（顶部区块）
   - **操作日志**：最近 50 条审计记录

> ⚠️ 管理接口默认关闭（安全默认）。开启后请使用强令牌，并仅在内网/本机暴露。

## 账号系统与模式切换（single ↔ real）

`data/config.json` 的 `authMode` 决定认证语义：

| 模式 | 语义 | 数据位置 |
|------|------|----------|
| `single`（默认） | 单账号私服：任意 token/secret 收敛到 `singleUid`；`singleAutoMaxAccount` 随版本刷新满配账号（合并式刷新保留进度，S1） | `data/user/databases/{singleUid}.json` |
| `real` | 多账号：token = 账号 secret（MD5(phone+固定key)）；有 secret 的账号拒绝 uid 数字直通（R1） | `data/user/databases/{uid}.json` + users 表 |

账号配置统一存 SQLite `data/user/social.db`（首次由 `data/user/users.json` 种子迁移）。社交数据（好友/申请/访问）以 `social.db` 为唯一事实源（R3）；战斗回放独立存 `replays` 表（R4）；密码以 `sha256$` 哈希存储，旧明文账号登录后自动升级（R7）。

**切换步骤**（修改 `authMode` 后重启生效）：

1. `single → real`：已有账号（含 single 固定号）仍在 users 表与 databases/ 中，可直接按 secret 登录。
2. `real → single`：所有账号数据保留不删，但只会访问 `singleUid` 指向的账号。
3. 切换 `singleUid`（如 1 → 2222 过渡）：旧号文件保留；新 uid 不存在时 `ensureSingleUser` 按 1.json → player_data.json 顺序找模板自动创建（S3），随后按版本生成满配账号。
4. **清理残留**：删除某账号 = 删 `data/user/databases/{uid}.json` + users 表行 + `social.db` 中该 uid 的 friends/requests/visited/replays 行。

**已知取舍（设计决策，非缺陷）**：

- **S4 多设备共享**：single 模式任意设备连上端口即同一账号——单机私服定位，无设备隔离；`config.Host` 控制暴露范围（`auto` 会绑定局域网 IP）。
- **S5 社交自锁**：single 单账号无法与自己加好友（`sendFriendRequest` 显式拒绝），社交功能仅 real 多账号有意义。
- **C1 syncData `user` 全量下发**：官方协议契约——`reference/tmp/account_syncData_response.00.json`、`account_syncData_res_1065.json` 两份官服抓包均为 `{ result, ts, user, playerDataDelta }`，`user` 是全量玩家数据（42-51 个顶层字段）；本服实现与官方一致，行为不改；契约已被 `tests/unit/router/account.test.ts` 锁定。
- **C3 版本校验 YAGNI**：`majorVersion` 已配置化（`config.majorVersion`，默认 446），clientVersion 校验不拦截。

## 开发命令

```bash
npm run test        # vitest 单元测试
npm run build       # tsc 编译
npm run hook        # frida-compile 编译 hook 脚本
```

## 文档

- `design-spec.md` — 项目设计规范（含第 9 章管理后台设计规范）
- `api.md` — 游戏协议 API 文档（含管理 API）
- `.trae/specs/` — 功能规格与任务清单
