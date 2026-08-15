--[[
  BasePlugin.lua —— 插件基类
  封装插件生命周期（Load/Unload）与 HotfixBase 统一打补丁入口，
  子类实现 OnLoad/OnUnload 完成具体功能。所有异常用 xpcall 兜底并记日志。
  须在 Base/BaseModule（提供 Class / HotfixBase）之后加载。

  补丁模式：
    - Fix_ex(cls, method, fixFunc)：完整替换，fixFunc(self, ...) 取代原方法
      （内部用 xlua.util.hotfix_ex，不自带 orig 传递）。
    - Hotfix(cls, method, fixFunc)：包装模式，fixFunc(self, orig, ...)，
      orig 为原方法，可调 orig(self, ...) 保留原行为。
  两种模式均通过同一 HotfixBase 实例录制，Unload 时统一 Dispose 还原。
--]]
local BasePlugin = Class("BasePlugin")
local eutil = CS.Torappu.Lua.Util

--[[
  构造插件实例。
  @param id   插件唯一标识（如 "enemy_hp"，与 PluginDefs 一致）
  @param name 显示名（面板展示用）
  @param desc 描述（面板展示用）
--]]
function BasePlugin:ctor(id, name, desc)
  self.id = id
  self.name = name
  self.desc = desc
  self.enabled = false      -- 当前是否启用
  self._hotfixer = nil      -- 懒加载的 HotfixBase 实例，用于还原补丁
end

--[[
  懒加载并返回 HotfixBase 实例（首次调用创建）。
  @return HotfixBase 实例
--]]
function BasePlugin:_EnsureHotfixer()
  if self._hotfixer == nil then
    self._hotfixer = HotfixBase.new()
  end
  return self._hotfixer
end

--[[
  完整替换模式：fixFunc 取代原方法，不保留原调用。
  fixFunc 签名 = function(self, ...)，与 C# 方法签名一致。
  内部用 xlua.util.hotfix_ex，由 xlua 管理链式还原。
  @param cls     C# 类型
  @param method  方法名
  @param fixFunc 替换实现
--]]
function BasePlugin:Fix_ex(cls, method, fixFunc)
  local hf = self:_EnsureHotfixer()
  local ok, err = xpcall(function()
    hf:Fix_ex(cls, method, fixFunc)
  end, debug.traceback)
  if not ok then
    eutil.LogHotfixError("[BasePlugin] " .. self.id .. " Fix_ex(" .. method .. ") 失败: " .. err)
  end
end

--[[
  包装模式：fixFunc 经 orig 调用原方法。
  fixFunc 签名 = function(self, orig, ...)，orig 为原方法包装。
  内部用 xlua.hotfix + 手动捕获 orig，通过 HotfixBase 录制统一还原。
  @param cls     C# 类型
  @param method  方法名
  @param fixFunc 包装实现（function(self, orig, ...)）
--]]
function BasePlugin:Hotfix(cls, method, fixFunc)
  local hf = self:_EnsureHotfixer()
  local ok, err = xpcall(function()
    local orig = cls[method]
    hf:Fix(cls, method, function(self, ...)
      return fixFunc(self, orig, ...)
    end)
  end, debug.traceback)
  if not ok then
    eutil.LogHotfixError("[BasePlugin] " .. self.id .. " Hotfix(" .. method .. ") 失败: " .. err)
  end
end

--[[
  启用插件：置 enabled 并调用 OnLoad。失败则回滚 enabled 并记日志。
--]]
function BasePlugin:Load()
  if self.enabled then return end
  self.enabled = true
  local ok, err = xpcall(function() self:OnLoad() end, debug.traceback)
  if not ok then
    self.enabled = false
    eutil.LogHotfixError("[BasePlugin] " .. self.id .. " OnLoad 失败: " .. err)
  end
end

--[[
  停用插件：调用 OnUnload 并还原所有已经注册的 hotfix 补丁。
--]]
function BasePlugin:Unload()
  if not self.enabled then return end
  local ok, err = xpcall(function() self:OnUnload() end, debug.traceback)
  self.enabled = false
  if self._hotfixer ~= nil then
    xpcall(function() self._hotfixer:Dispose() end, debug.traceback)
    self._hotfixer = nil
  end
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