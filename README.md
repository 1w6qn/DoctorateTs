# DoctorateTs

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 项目介绍

**DoctorateTs** 是一个基于 TypeScript 实现的 **明日方舟（Arknights）私人服务器**，是对 [DoctoratePy](https://github.com/AKDoctorate/DoctoratePy/) 的 TypeScript 重写版本。

该项目旨在提供一个完整的明日方舟游戏服务端实现，支持游戏的核心功能，包括登录、抽卡、招募、任务、基建、社交等系统。

## 技术栈

| 分类 | 技术 | 版本 |
|------|------|------|
| 运行时 | Node.js | LTS |
| 语言 | TypeScript | 5.5.2 |
| 框架 | Express | 5.0.0 |
| 状态管理 | immer | 10.1.1 |
| 事件总线 | emmiterry | 1.0.3 |
| HTTP 请求 | axios | 1.7.2 |
| 数据库 | JSON 文件存储 | - |
| Hook 支持 | frida-il2cpp-bridge | 0.9.1 |

## 功能特性

- ✅ **登录系统** - 支持手机密码登录、U8 渠道登录
- ✅ **招募系统** - 完整的公开招募逻辑，支持标签筛选和加速
- ✅ **抽卡系统** - 支持普通卡池、限定卡池、联动卡池等多种类型
- ✅ **任务系统** - 日常任务、周常任务的管理和奖励发放
- ✅ **勋章系统** - 勋章获取、展示和自定义
- ✅ **商店系统** - 多种商店类型（普通、高级、限时、社交等）
- ⚠️ **肉鸽模式** - 框架已搭建，部分功能待完善
- ✅ **角色养成** - 角色升级、精英化、技能升级、潜能提升
- ✅ **主页主题** - 主题和背景切换
- ✅ **基建系统** - 基建管理、干员分配、制造和贸易
- ✅ **社交系统** - 好友添加、好友请求、线索分享

## 项目结构

```
DoctorateTs/
├── app/                    # 核心应用代码
│   ├── auth/               # 认证模块（登录、Token管理）
│   ├── config/             # 配置文件（生产环境配置）
│   ├── excel/              # Excel 数据表模型（游戏配置数据）
│   ├── game/               # 游戏核心逻辑
│   │   ├── controller/     # 控制器层（业务逻辑处理）
│   │   ├── manager/        # 管理器层（状态管理）
│   │   ├── model/          # 数据模型层（TypeScript 接口定义）
│   │   └── router/         # API 路由层（HTTP 接口定义）
│   └── utils/              # 工具函数（文件操作、加密、网络等）
├── data/                   # 游戏数据文件（JSON 格式）
│   ├── announce/           # 公告数据
│   ├── crisis/             # 危机合约数据
│   ├── crisisV2/           # 危机合约 V2 数据
│   ├── excel/              # Excel 数据表（游戏配置）
│   ├── rlv2/               # 肉鸽模式数据
│   ├── shop/               # 商店配置
│   ├── tower/              # 保全派驻数据
│   └── user/               # 用户数据
├── hook/                   # Frida Hook 脚本（客户端修改）
├── .gitignore
├── README.md               # 项目说明文档
├── api.md                  # API 接口文档
├── package.json
├── tsconfig.json
└── index.ts                # 项目入口文件
```

## 安装部署

### 环境要求

- Node.js >= 18.0.0
- npm >= 9.0.0

### 安装步骤

1. **克隆项目**

```bash
git clone https://github.com/1w6qn/DoctorateTs.git
cd DoctorateTs
```

2. **安装依赖**

```bash
npm install
```

3. **配置数据**

将游戏数据文件放置在 `data/` 目录下，包括：
- Excel 数据表（`data/excel/`）
- 用户数据（`data/user/`）
- 其他配置文件

4. **启动服务**

```bash
# 开发模式（自动重启）
npm start

# 生产模式（先编译）
npm run build
node build/index.js
```

5. **编译 Hook（可选）**

如果需要修改客户端行为，可以编译 Frida Hook 脚本：

```bash
npm run hook
```

## 配置说明

配置文件位于 `data/config.json`，包含以下配置项：

```json
{
  "Host": "0.0.0.0",
  "PORT": 8080,
  "version": {
    "resVersion": "1.0.0",
    "clientVersion": "1.0.0"
  },
  "assets": {
    "enableMods": true,
    "downloadLocally": true,
    "autoUpdate": true
  },
  "NetworkConfig": {}
}
```

## API 文档

详细的 API 接口文档请查看 [api.md](api.md)。

## 开发指南

### 代码规范

- 使用 TypeScript 严格模式（`strict: true`）
- 采用面向对象的编程风格
- 使用 JSDoc 格式添加代码注释
- 遵循 ESLint 和 Prettier 规范

### 添加新功能

1. 在 `app/game/model/` 中定义数据模型接口
2. 在 `app/game/manager/` 中实现业务逻辑
3. 在 `app/game/router/` 中定义 API 路由
4. 在 `app/excel/` 中添加必要的数据表

### 测试

```bash
npm test
```

## 参考项目

- [Arknights](https://ak.hypergryph.com/) - 明日方舟官方网站
- [DoctoratePy](https://github.com/AKDoctorate/DoctoratePy/) - 本项目的 Python 版本

## 注意事项

- 本项目仍在开发中，可能存在 Bug 或未实现的功能
- 部分游戏数据未包含在仓库中，请自行补充
- 请遵守相关法律法规，不要用于商业用途

## License

[MIT License](LICENSE)