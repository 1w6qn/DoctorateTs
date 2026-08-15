--[[
  PluginBootHotfixer.lua —— 插件系统引导 hotfixer
  经游戏原生 DefinedFix 管线引导：在 HotfixProcesser.Do 阶段被 new() + Init() 调用，
  OnInit 里 require "Plugin/PluginEntry" 并初始化插件系统。
  将其加入内置 bundle 的 DefinedFix 清单（见 scripts/repack-lua-bundle.ts 的 patchDefinedFix）。
--]]
local PluginBootHotfixer = Class("PluginBootHotfixer", HotfixBase)
local eutil = CS.Torappu.Lua.Util

--[[
  初始化插件系统（引导入口）。异常经 xpcall 兜底并记日志。
--]]
function PluginBootHotfixer:OnInit()
  local ok, err = xpcall(function()
    require "Plugin/PluginEntry"
    PluginEntry.init()
  end, debug.traceback)
  if not ok then
    eutil.LogHotfixError("[PluginBootHotfixer] 插件系统引导失败: " .. err)
  end
end

return PluginBootHotfixer