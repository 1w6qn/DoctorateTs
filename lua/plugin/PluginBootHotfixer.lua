--[[
  PluginBootHotfixer.lua —— 插件系统引导 hotfixer
  经游戏原生 DefinedFix 管线引导：HotfixProcesser.Do 阶段 new() + Init() → OnInit()。
  OnInit 里先建立全局依赖绑定（Class/HotfixBase 由游戏提供，插件自身模块用 local 定义，
  需显式挂 _G 供跨模块引用），再 require "Plugin/PluginEntry" 并初始化插件系统。
  将其加入内置 bundle 的 DefinedFix 清单（见 scripts/repack-lua-bundle.ts 的 patchDefinedFix）。
--]]
local PluginBootHotfixer = Class("PluginBootHotfixer", HotfixBase)
local eutil = CS.Torappu.Lua.Util

--[[
  建立插件系统全局依赖：把 local 定义的模块表挂到 _G，供跨模块以全局名引用。
  require 会走 xLua 模块缓存，重复 require 返回同一表，故幂等。
  顺序：PluginDefs → PluginManager → PluginEntry（依赖关系由后向前）。
--]]
local function _BootstrapGlobals()
  _G.PluginDefs = require "Plugin/PluginDefs"
  _G.PluginManager = require "Plugin/PluginManager"
  _G.PluginEntry = require "Plugin/PluginEntry"
end

--[[
  初始化插件系统（引导入口）。异常经 xpcall 兜底并记日志。
--]]
function PluginBootHotfixer:OnInit()
  local ok, err = xpcall(function()
    _BootstrapGlobals()
    PluginEntry.init()
  end, debug.traceback)
  if not ok then
    eutil.LogHotfixError("[PluginBootHotfixer] 插件系统引导失败: " .. err)
  end
end

return PluginBootHotfixer