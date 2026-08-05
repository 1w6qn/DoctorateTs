# DoctorateTs

明日方舟（Arknights）私服模拟器，TypeScript + Express 5 实现。数据全部本地 JSON，无数据库依赖。

## 快速开始

```bash
npm install
npm run update     # 拉取并生成游戏数据（离线环境用 npm run update:skip 或 --offline）
npm start          # 启动服务器（默认端口 8443，见 data/config.json）
```

三种启动模式：

| 模式 | 触发方式 | 说明 |
|------|----------|------|
| 在线更新（默认） | `npm start` | 拉取远程数据，失败自动回退本地缓存 |
| 跳过更新 | `--skip-update` / `-s` | 跳过 git，仍执行本地复制与类型生成 |
| 完全离线 | `--offline` / `-o`，或 `data/config.json` 中 `"offline": true` | 零网络，启动前校验本地 66 个数据文件 |

## 管理功能

### 命令行（无需启动服务器，完全离线可用）

```bash
npm run admin -- users list                        # 列出所有用户
npm run admin -- users info 1                      # 查看用户详情
npm run admin -- users create 13800000000 123456   # 创建用户（模板复制）
npm run admin -- users grant 1 4001 100            # 发放物品（4001=金币，以游戏为准）
npm run admin -- mail send 1 标题 内容 --items 4001:100,5001:10   # 发送邮件
npm run admin -- server status                     # 服务器状态与数据文件
npm run admin -- config show                       # 查看配置
npm run admin -- config set admin.token mytoken    # 修改配置（重启后生效）
```

### Web Dashboard

1. 编辑 `data/config.json`：`"admin": { "enable": true, "token": "你的令牌" }`
2. 启动服务器后访问 `http://localhost:8443/admin/dashboard`
3. 输入管理令牌进入后台，可查看用户列表/详情、发放物品、发送邮件、创建用户（10 秒自动刷新）

> ⚠️ 管理接口默认关闭（安全默认）。开启后请使用强令牌，并仅在内网/本机暴露。

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
