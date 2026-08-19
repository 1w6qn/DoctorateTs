--[[
  BasePlugin.lua —— 插件热更基类（继承游戏原生 HotfixBase）
  对齐官服 hotfixer 模型：每个插件 = 一个自包含 hotfixer，直接逐条登记在
  DefinedFix.lua 清单，由 HotfixProcesser.Do 阶段 new() + Init()（→ OnInit()）驱动，
  不再经单一引导 hotfixer + PluginManager.Init 的冷启动链加载。

  生命周期（官方驱动）：
    - OnInit()：注册到 PluginManager，由管理器按启用态 Load（打补丁）。
    - Dispose()：从管理器注销并回滚本插件全部补丁（覆盖官方版本，
      因为本插件补丁经 PluginHotfix 共享注册表管理，非官方 _Record）。
    - Load / Unload：运行时启停（面板 / 管理端触发），幂等。

  补丁机制（经 PluginHotfix 共享注册表，见 Plugin/PluginHotfix）：
    - 多插件 hook 同一 C# 方法时共享一个 xlua.hotfix 包装器，卸载互不干扰；
    - Fix_ex(cls, method, fixFunc)：完整替换，fixFunc(self, ...) 取代原方法；
    - Hotfix(cls, method, fixFunc)：包装模式，fixFunc(self, orig, ...)，
      orig 为链上下一段实现，可调 orig(self, ...) 保留原行为。
    - 注册的 fixFunc 运行时统一经 xpcall 兜底（PluginHotfix 层），崩溃不冒泡到
      C# 调用栈——对齐官方 hotfixer 写法（如 ArkventHotfixer 每个 fix 内部 xpcall）。

  PrivateAccess(cls)：hotfix C# 私有成员/方法前调用，封装 xlua.private_accessible
  （官方 ArkventHotfixer 先 private_accessible 再 Fix_ex 私有方法的同一模式）。

  元数据：插件在类级声明 id/name/desc（Class 的实例经 __index 继承类字段），
  因此 new() 无参即可实例化；ctor 亦可被显式传参覆盖。
--]]
local BasePlugin = Class("BasePlugin", HotfixBase)
local eutil = CS.Torappu.Lua.Util
local PluginHotfix = require("Plugin/PluginHotfix")

-- 类级默认元数据（子类覆盖；无参 new() 时回退用）
BasePlugin.id = "base"
BasePlugin.name = "插件"
BasePlugin.desc = ""

--[[
  构造插件实例。
  @param id   插件唯一标识（缺省用类级 id）
  @param name 显示名（缺省用类级 name）
  @param desc 描述（缺省用类级 desc）
--]]
function BasePlugin:ctor(id, name, desc)
  self.id = id or self.id
  self.name = name or self.name
  self.desc = desc or self.desc
  self.enabled = false      -- 当前是否启用
  self._fixes = {}          -- 已注册补丁记录（{cls, method}），卸载/回滚时注销
  self._pluginManager = nil -- 所属管理器（OnInit 时绑定）
end

--[[
  官方 hotfixer 生命周期 OnInit：HotfixProcesser.Do → new() → Init() → OnInit()。
  注册到 PluginManager，由管理器按持久化启用态决定是否 Load（打补丁）。
--]]
function BasePlugin:OnInit()
  local pluginManager = require("Plugin/PluginManager")
  self._pluginManager = pluginManager
  pluginManager:Register(self)
end

--[[
  官方 hotfixer 生命周期 Dispose：从管理器注销并回滚本插件全部补丁。
  覆盖 HotfixBase.Dispose（本插件补丁经 PluginHotfix 共享注册表，非官方 _Record 记录）。
--]]
function BasePlugin:Dispose()
  if self._pluginManager ~= nil then
    self._pluginManager:Unregister(self)
    self._pluginManager = nil
  end
  self:Unload()
end

--[[
  解锁 C# 类型的私有成员访问（xlua.private_accessible）。
  对齐官方 hotfixer 模式：先 private_accessible 再 Fix_ex/Fix 私有方法或私有字段
  （如 ArkventHotfixer 对 ArkhubUnitSyncSystem._SyncSelfCaptureArea 的 hotfix）。
  幂等（xlua 内部重复调用安全）；失败只记日志，不中断插件加载。
  @param cls C# 类型
--]]
function BasePlugin:PrivateAccess(cls)
  local ok, err = pcall(function()
    if xlua ~= nil and xlua.private_accessible ~= nil then
      xlua.private_accessible(cls)
    end
  end, debug.traceback)
  if not ok then
    eutil.LogHotfixError("[BasePlugin] " .. self.id .. " PrivateAccess(" .. tostring(cls) .. ") 失败: " .. tostring(err))
  end
end

--[[
  完整替换模式：fixFunc 取代原方法，不保留原调用。
  fixFunc 签名 = function(self, ...)，与 C# 方法签名一致。
  @param cls     C# 类型
  @param method  方法名
  @param fixFunc 替换实现
--]]
function BasePlugin:Fix_ex(cls, method, fixFunc)
  local ok, err = xpcall(function()
    if not PluginHotfix.FixEx(cls, method, self, fixFunc) then
      error("目标方法不存在（版本漂移?）: " .. tostring(method))
    end
    self._fixes[#self._fixes + 1] = { cls = cls, method = method }
  end, debug.traceback)
  if not ok then
    eutil.LogHotfixError("[BasePlugin] " .. self.id .. " Fix_ex(" .. method .. ") 失败: " .. err)
  end
end

--[[
  包装模式：fixFunc 经 orig 调用原方法。
  fixFunc 签名 = function(self, orig, ...)，orig 为链上下一段实现。
  @param cls     C# 类型
  @param method  方法名
  @param fixFunc 包装实现（function(self, orig, ...)）
--]]
function BasePlugin:Hotfix(cls, method, fixFunc)
  local ok, err = xpcall(function()
    if not PluginHotfix.Hotfix(cls, method, self, fixFunc) then
      error("目标方法不存在（版本漂移?）: " .. tostring(method))
    end
    self._fixes[#self._fixes + 1] = { cls = cls, method = method }
  end, debug.traceback)
  if not ok then
    eutil.LogHotfixError("[BasePlugin] " .. self.id .. " Hotfix(" .. method .. ") 失败: " .. err)
  end
end

--[[
  注销本插件注册的全部补丁（幂等）。共享注册表会移除本插件的处理函数；
  仅当无其它插件使用同一方法时才还原原方法，因此不会破坏其它插件的 hook。
--]]
function BasePlugin:_UnregisterAll()
  for _, fix in ipairs(self._fixes) do
    xpcall(function() PluginHotfix.Unfix(fix.cls, fix.method, self) end, debug.traceback)
  end
  self._fixes = {}
end

--[[
  启用插件：置 enabled 并调用 OnLoad。失败则回滚 enabled 并注销已注册补丁
  （避免 OnLoad 中途失败留下半应用的 hook）。
--]]
function BasePlugin:Load()
  if self.enabled then return end
  self.enabled = true
  local ok, err = xpcall(function() self:OnLoad() end, debug.traceback)
  if not ok then
    self.enabled = false
    self:_UnregisterAll()
    eutil.LogHotfixError("[BasePlugin] " .. self.id .. " OnLoad 失败: " .. err)
  end
end

--[[
  停用插件：调用 OnUnload 并注销全部已注册补丁。
  即使处于停用态也会清理残留补丁（防御 Load 失败等异常路径）。
--]]
function BasePlugin:Unload()
  if not self.enabled then
    self:_UnregisterAll()
    return
  end
  local ok, err = xpcall(function() self:OnUnload() end, debug.traceback)
  self.enabled = false
  self:_UnregisterAll()
  if not ok then
    eutil.LogHotfixError("[BasePlugin] " .. self.id .. " OnUnload 失败: " .. err)
  end
end

--[[
  子类覆盖：插件启用时执行（打补丁 / 建 UI）。
--]]
function BasePlugin:OnLoad() end

--[[
  子类覆盖：插件停用时执行（清理临时状态）。
--]]
function BasePlugin:OnUnload() end

return BasePlugin