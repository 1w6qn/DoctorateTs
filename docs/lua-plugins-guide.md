# 游戏内 Lua 插件系统 — 使用与真机验证指南

> 在明日方舟客户端内，用游戏原生 XLua 热更 + 纯 Lua hotfix + 游戏内 Lua UI，实现敌人血量显示、敌人属性面板、战斗辅助，并提供现代化插件管理面板。
> 设计见 `.trae/specs/lua-plugins/spec.md`；实施任务见 `tasks.md` / `checklist.md`。

## 1. 源码结构

```
lua/plugin/                    ← 插件明文源码
├── BasePlugin.lua             ← 插件基类（Load/Unload/OnLoad/OnUnload + Hotfix/Fix_ex）
├── PluginDefs.lua             ← 插件清单（id/name/desc/module）
├── PluginManager.lua          ← 注册表：加载/启停/配置持久化
├── PluginEntry.lua            ← 入口：init()/dispose()，由 PluginBootHotfixer 调用
├── PluginBootHotfixer.lua     ← 引导 hotfixer（挂进 DefinedFix，经游戏原生管线加载插件）
├── EnemyHpPlugin.lua          ← 敌人血量显示（UIUnitHUD.Attach）
├── EnemyInfoPlugin.lua        ← 敌人属性面板（动态 UnityEngine.UI）
├── BattleAssistPlugin.lua     ← 战斗辅助（时间轴/倍速/TAS）
└── PanelPlugin.lua            ← 插件管理面板（浮动按钮 + 列表开关）
```

## 2. 打包与下发（方案 A：重打包内置 Lua bundle）

客户端 Lua 由一个**内置主 bundle**（`anon/7d91430e114d86fef7d3b3511151e12d.bin`）承载，客户端启动时按其加载 `entry.lua`。要让插件生效，需把插件 merge 进该 bundle 并 patch `DefinedFix.lua`（经游戏原生 hotfix 管线引导）：

> ⚠️ 关于「从官方 hot_update_list 提取」：该内置 Lua bundle 是**客户端 base 资产**，**不在**官方 `hot_update_list.json` 的 abInfos 中（清单仅含可热更增量资产；当前 2.7.61 清单 14981 条无此 hash，CDN 各版本路径亦 404）。bundle 哈希由官方 `resource_manifest_idx.json`（ArknightsGameData）确认：全部 `gamedata/[uc]lua/*` 资产的 `bundleIndex=2246` → `bundles[2246].name = anon/7d91430e114d86fef7d3b3511151e12d.bin`。取数源只能是已装客户端内的该 bundle。

```powershell
# 1) 从已装客户端提取内置 bundle（ArkUnpacker 解包后定位该 .bin，或直接取 .dat）
#    得到 <内置bundle>.dat 或 .bin

# 1b)（可选）把内置 bundle 的明文 Lua 提取到参考目录，之后可用 --from-ref 免客户端重建：
pnpm run extract:lua -- --bundle <内置bundle.dat|.bin>
#    → 写入 reference/ArknightsGameData/zh_CN/gamedata/[uc]lua/（跳过 plugin/*，还原 DefinedFix 注入标记）

# 2) 重打包：merge lua/plugin/ + patch DefinedFix → mods/anon_7d91430e114d86fef7d3b3511151e12d.dat
pnpm run repack:lua -- --bundle <内置bundle.dat|.bin>   # 或：pnpm run repack:lua -- --from-ref

# 3) 脚本会自动打开 data/config.json 的 assets.enableMods
# 4) 重启服务，客户端热更拉取覆盖内置 bundle → 客户端启动即加载插件
```

> 说明：
> - `scripts/repack-lua-bundle.ts` 会 **merge** 内置 Lua 资产与 `lua/plugin/*.lua`，并向 `DefinedFix.lua` 清单注入引导 hotfixer `Plugin/PluginBootHotfixer`，经游戏原生 `HotfixProcesser.Do` 管线引导插件加载。
> - 插件资产统一用 `gamedata/[uc]lua/Plugin/` 前缀（大写 P），与 require 路径 `Plugin/…` 大小写一致，避免 loader 找不到资源。
> - 单独的 `pnpm run pack:lua-plugins`（产出 `mods/plugin_lua.dat`）仅用于**独立开发/调试**，不能单独替代内置 bundle（否则客户端会丢失全部内置 Lua）。
> - 若 `DefinedFix.lua` 锚点不匹配（版本漂移），脚本会报「未找到 … 锚点」，需人工校准锚点后重跑。

## 3. 启用流程（服务端）

- admin 端点（需 `adminAuth` 令牌，默认 `doctorate-admin`）：
  - `GET /admin/api/plugin`            → 插件列表（含启用状态）
  - `POST /admin/api/plugin/<id>/enable`  → 启用
  - `POST /admin/api/plugin/<id>/disable` → 停用
- 配置持久化于 `data/plugin/config.json`（`{ "enabled": { "<id>": bool } }`）。

## 4. 真机手动验证步骤

> 下列步骤需在已接入本私服的客户端（2.7.61）上执行。方法/字段名以真机 dump 校准为准（客户端版本可能漂移）。

### 4.1 敌人血量显示
1. 进入任意战斗关卡，部署干员并引出敌人。
2. 观察敌人血条旁是否出现红色「当前/最大」血量文本。
3. 启用/停用切换：面板或 admin 端点 `enable`/`disable` enemy_hp 后重新进图，验证文本出现/消失。

### 4.2 敌人属性面板
1. 战斗中按住 `Z` 键并点击敌人。
2. 观察左上/右上出现半透明面板，显示名字/ID/攻击/防御/法抗/移速/重量/目标点。

### 4.3 战斗辅助
- 右上角显示「战斗时间: x.xxxs」时间轴。
- 战斗中按 `X` 暂停/继续；`Alpha1` 单帧；`Alpha3` 三倍速。

### 4.4 插件管理面板
- 右下角出现「插件」浮动按钮，点击开合管理面板。
- 面板列出各插件，点「切换」实时启停，并持久化到客户端 `persistentDataPath/plugin_config.json`。

## 5. 版本漂移校准

`reference/arknights-2.7.61-csharp` 的 `.cs` 源文件已被 gitignore 移除（仅剩 csproj），方法签名以 `[uc]lua` hotfixer 与 Arknights-Assist JS 为准。若真机报错，按如下方式校准：

1. 用 Frida dump 客户端 il2cpp：`Il2Cpp.dump("d.cs")`（见 `hook/main.ts`）。
2. 搜索目标类（如 `Torappu.Battle.UI.UIUnitHUD`），核对字段/方法名（`_hpSlider`、`Attach`、`get_groupStatic` 等）。
3. 修正 `lua/plugin/*.lua` 中的类名/方法名后重新 `pnpm run pack:lua-plugins` 下发。

所有 hotfix 均经 `xpcall` 兜底，单点失败不会崩溃，仅记 `LogHotfixError`。

## 6. 本仓库可验证项 vs 真机验证项

| 项 | 验证方式 |
|---|---|
| `pack-lua-bundle` 多资产打包/解包 | vitest |
| `pack-lua-plugins` 产出结构 | vitest |
| `PluginConfigService` 读写/幂等/回退 | vitest |
| admin 插件端点 | vitest |
| Lua 插件实际加载/UI 显示/热更 | 真机手动（见 §4） |