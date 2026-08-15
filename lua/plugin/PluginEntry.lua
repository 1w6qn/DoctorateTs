--[[
  PluginEntry.lua —— 插件系统入口
  提供显式的 init()/dispose()，由重打包后的 entry.lua 在 InitFeature/DisposeFeature 中调用
  （见 scripts/repack-lua-bundle.ts 对内置 bundle 的 entry.lua 补丁）。
  相比「包装 LuaEntry.Init」方案，直接调用更稳定，避免在 Init 执行期间重入。
--]]
local PluginEntry = {}
local eutil = CS.Torappu.Lua.Util

--[[
  初始化插件系统（按配置启停各插件）。
--]]
function PluginEntry.init()
  PluginManager.me:Init()
  eutil.Log("[PluginEntry] Lua 插件系统初始化完成")
end

--[[
  释放插件系统（停用全部插件）。
--]]
function PluginEntry.dispose()
  for _, p in ipairs(PluginManager.me:GetAll()) do
    p:Unload()
  end
  eutil.Log("[PluginEntry] Lua 插件系统已释放")
end

return PluginEntry