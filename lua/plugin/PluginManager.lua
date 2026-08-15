--[[
  PluginManager.lua —— 插件管理器（单例）
  按 PluginDefs 加载各插件，维护启用态并持久化到 persistentDataPath/plugin_config.json。
  提供 Init / GetPlugin / SetEnabled / GetAll 供面板与入口使用。
--]]
local PluginManager = Class("PluginManager")
local eutil = CS.Torappu.Lua.Util
local rapidjson = require("rapidjson")
local SystemIO = CS.System.IO.File

-- 单例
PluginManager.me = nil

--[[
  构造插件管理器（仅创建一次）。
--]]
function PluginManager:ctor()
  self._plugins = {}        -- [id] = BasePlugin 实例
  self._defs = {}           -- [id] = 定义表
  self._configPath = nil    -- 持久化文件路径（懒计算）
  self._initialized = false
end

--[[
  计算并返回配置持久化路径。
  @return 配置文件绝对路径
--]]
function PluginManager:_GetConfigPath()
  if self._configPath == nil then
    self._configPath = CS.UnityEngine.Application.persistentDataPath .. "/plugin_config.json"
  end
  return self._configPath
end

--[[
  读取持久化的启用态配置；文件不存在或解析失败时返回全启用默认值。
  @return table：[id] = bool
--]]
function PluginManager:_ReadConfig()
  local enabled = {}
  for _, def in ipairs(PluginDefs) do
    enabled[def.id] = true -- 默认全部启用
  end
  local path = self:_GetConfigPath()
  local okPath, exists = pcall(function() return SystemIO.Exists(path) end)
  if okPath and exists then
    local okRead, text = pcall(function() return SystemIO.ReadAllText(path) end)
    if okRead then
      local okParse, cfg = pcall(function() return rapidjson.decode(text) end)
      if okParse and type(cfg) == "table" and type(cfg.enabled) == "table" then
        for id, v in pairs(cfg.enabled) do
          enabled[id] = (v == true)
        end
      end
    end
  end
  return enabled
end

--[[
  把启用态配置写入磁盘（幂等；写入失败仅记日志，不阻断业务）。
--]]
function PluginManager:_SaveConfig()
  local payload = { enabled = {} }
  for defId, plugin in pairs(self._plugins) do
    payload.enabled[defId] = plugin.enabled
  end
  local ok, json = pcall(function() return rapidjson.encode(payload) end)
  if not ok then return end
  xpcall(function()
    CS.Torappu.FileUtil.WriteToFile(json, self:_GetConfigPath(), false)
  end, debug.traceback)
end

--[[
  初始化插件系统：按 PluginDefs 加载并依据配置启停各插件。
  可重复调用（幂等）。
--]]
function PluginManager:Init()
  if self._initialized then return end
  self._initialized = true
  local enabled = self:_ReadConfig()
  for _, def in ipairs(PluginDefs) do
    local ok, mod = pcall(function() return require(def.module) end)
    if not ok then
      eutil.LogHotfixError("[PluginManager] 加载插件模块失败 " .. def.module .. ": " .. tostring(mod))
    else
      local plugin = mod.new(def.id, def.name, def.desc)
      self._plugins[def.id] = plugin
      self._defs[def.id] = def
      if enabled[def.id] then
        plugin:Load()
      end
    end
  end
  eutil.Log("[PluginManager] 初始化完成，共 " .. self._Count() .. " 个插件")
end

--[[
  返回已加载插件数量。
  @return 数量
--]]
function PluginManager:_Count()
  local n = 0
  for _ in pairs(self._plugins) do n = n + 1 end
  return n
end

--[[
  按 id 获取插件实例；不存在返回 nil。
  @param id 插件标识
  @return 插件实例或 nil
--]]
function PluginManager:GetPlugin(id)
  return self._plugins[id]
end

--[[
  返回全部插件实例列表（保持 PluginDefs 顺序）。
  @return 插件实例数组
--]]
function PluginManager:GetAll()
  local list = {}
  for _, def in ipairs(PluginDefs) do
    local p = self._plugins[def.id]
    if p ~= nil then
      list[#list + 1] = p
    end
  end
  return list
end

--[[
  启停指定插件并持久化配置。
  @param id    插件标识
  @param value true 启用 / false 停用
--]]
function PluginManager:SetEnabled(id, value)
  local plugin = self._plugins[id]
  if plugin == nil then return end
  if value then
    plugin:Load()
  else
    plugin:Unload()
  end
  self:_SaveConfig()
end

-- 创建单例
PluginManager.me = PluginManager.new()

return PluginManager