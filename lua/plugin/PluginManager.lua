--[[
  PluginManager.lua —— 插件管理器（单例注册表）
  每个插件作为独立 hotfixer 在 DefinedFix 清单中由 HotfixProcesser.Do 实例化，
  OnInit() 里调用 Register 注册到本管理器；管理器按持久化启用态 Load/Unload，
  并提供 GetPlugin / SetEnabled / GetAll 供面板、心跳与管理端使用。
  单个插件加载失败不拖垮系统：记录错误状态，其余插件照常加载。

  模块加载期自举全局（替代原 PluginBootHotfixer 的 _BootstrapGlobals）：
    _G.PluginDefs / _G.PluginManager —— 供 PanelPlugin / PluginHeartbeat 以全局名引用。
  文件 IO / rapidjson 惰性获取（引导阶段可能不可用，pcall 兜底）。

  依赖：Base/BaseModule（Class）、Plugin/PluginDefs。
--]]
local PluginManager = Class("PluginManager")
local eutil = CS.Torappu.Lua.Util
local PluginDefs = require("Plugin/PluginDefs")

-- 顶层不再 require rapidjson / CS.System.IO.File：引导阶段可能不可用，
-- 若顶层 require 失败会拖垮整个插件系统。改为惰性获取 + pcall 兜底。
local _jsonMod = nil
local _fileType = nil

--[[
  惰性获取 rapidjson 模块（失败缓存 false，避免每次重试）。
  @return rapidjson 模块或 nil
--]]
local function _Json()
  if _jsonMod == nil then
    local ok, mod = pcall(function() return require("rapidjson") end)
    _jsonMod = ok and mod or false
  end
  return _jsonMod or nil
end

--[[
  惰性获取 System.IO.File 类型（失败缓存 false）。
  @return File 类型或 nil
--]]
local function _File()
  if _fileType == nil then
    local ok, f = pcall(function() return CS.System.IO.File end)
    _fileType = ok and f or false
  end
  return _fileType or nil
end

-- 单例
PluginManager.me = nil

--[[
  构造插件管理器（仅创建一次）。
--]]
function PluginManager:ctor()
  self._plugins = {}        -- [id] = 插件实例（已注册）
  self._errors = {}         -- [id] = 错误信息（加载失败）
  self._configPath = nil    -- 持久化文件路径（懒计算）
  self._enabled = nil       -- [id] = bool（持久化启用态；首次 Register 时加载）
  self._heartbeatScheduled = false
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
  读取持久化的启用态配置；文件不存在、依赖不可用或解析失败时返回全启用默认值。
  插件申明从 PluginDefs（模块加载期已 require）取，保证与面板/管理端目录一致。
  @return table：[id] = bool
--]]
function PluginManager:_ReadConfig()
  local enabled = {}
  for _, def in ipairs(PluginDefs) do
    enabled[def.id] = true -- 默认全部启用
  end
  local path = self:_GetConfigPath()
  local file = _File()
  if file ~= nil then
    local okPath, exists = pcall(function() return file.Exists(path) end)
    if okPath and exists then
      local okRead, text = pcall(function() return file.ReadAllText(path) end)
      if okRead then
        local json = _Json()
        if json ~= nil then
          local okParse, cfg = pcall(function() return json.decode(text) end)
          if okParse and type(cfg) == "table" and type(cfg.enabled) == "table" then
            for id, v in pairs(cfg.enabled) do
              enabled[id] = (v == true)
            end
          end
        end
      end
    end
  end
  return enabled
end

--[[
  把启用态配置写入磁盘（幂等；依赖不可用或写入失败仅静默，不阻断业务）。
  全量持久化：先并入既有配置（含加载失败插件的历史状态），再覆盖当前插件状态，
  避免加载失败插件的状态被误重置。
--]]
function PluginManager:_SaveConfig()
  local payload = { enabled = {} }
  -- 并入既有配置（含加载失败插件的历史启停状态）
  local prev = self:_ReadConfig()
  for id, v in pairs(prev) do
    payload.enabled[id] = v
  end
  -- 覆盖当前已注册插件的实际状态
  for defId, plugin in pairs(self._plugins) do
    payload.enabled[defId] = plugin.enabled
  end
  local json = _Json()
  if json == nil then return end
  local ok, text = pcall(function() return json.encode(payload) end)
  if not ok then return end
  xpcall(function()
    CS.Torappu.FileUtil.WriteToFile(text, self:_GetConfigPath(), false)
  end, debug.traceback)
end

--[[
  首次 Register 时一次性引导：读取启用态配置并调度心跳确认（网络就绪后自动重试）。
  幂等。
--]]
function PluginManager:_EnsureConfig()
  if self._enabled ~= nil then return end
  self._enabled = self:_ReadConfig()
  self:_ScheduleHeartbeat()
end

--[[
  引导一次插件心跳确认（best-effort，失败静默）。
  PluginHeartbeat 内置重试链（TimerModel 就绪后自动补发），此处无需等待。
--]]
function PluginManager:_ScheduleHeartbeat()
  if self._heartbeatScheduled then return end
  self._heartbeatScheduled = true
  xpcall(function()
    local hb = require("Plugin/PluginHeartbeat")
    if hb ~= nil and hb.ScheduleAuto ~= nil then
      hb.ScheduleAuto()
    end
  end, debug.traceback)
end

--[[
  注册插件实例并按其启用态决定是否应用补丁。
  单个插件 Load 失败记录错误，不阻断整体。
  @param plugin 插件实例（继承 BasePlugin，含 id/name/desc）
--]]
function PluginManager:Register(plugin)
  self:_EnsureConfig()
  self._plugins[plugin.id] = plugin
  if self:IsEnabled(plugin.id) then
    local okLoad, loadErr = pcall(function() plugin:Load() end)
    if not okLoad then
      self._errors[plugin.id] = "初始化失败: " .. tostring(loadErr)
    end
  end
end

--[[
  注销插件实例（从注册表移除以避免 Dispose 后仍被面板引用）。
  不在此执行 Unload（Dispose 已先回滚补丁）。
  @param plugin 插件实例
--]]
function PluginManager:Unregister(plugin)
  self._plugins[plugin.id] = nil
end

--[[
  查询插件是否启用（无记录时默认为启用）。
  @param id 插件标识
  @return 是否启用
--]]
function PluginManager:IsEnabled(id)
  self:_EnsureConfig()
  return self._enabled[id] ~= false
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
  查询插件加载错误信息；未失败返回 nil。
  @param id 插件标识
  @return 错误信息或 nil
--]]
function PluginManager:GetError(id)
  return self._errors[id]
end

--[[
  返回全部插件实例列表（保持 PluginDefs 顺序，仅含已注册插件）。
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
  启停指定插件并持久化配置，随后 best-effort 同步到服务端
  （经 PluginHeartbeat.PushState，路径编码 GET，见 Plugin/PluginHeartbeat）。
  @param id    插件标识
  @param value true 启用 / false 停用
--]]
function PluginManager:SetEnabled(id, value)
  local plugin = self._plugins[id]
  if plugin == nil then return end
  self:_EnsureConfig()
  if value then
    plugin:Load()
  else
    plugin:Unload()
  end
  self._enabled[id] = value
  self:_SaveConfig()
  local ok, hb = pcall(function() return require("Plugin/PluginHeartbeat") end)
  if ok and hb ~= nil and hb.PushState ~= nil then
    hb.PushState(id, value)
  end
end

-- 创建单例，并自举全局（替代原 PluginBootHotfixer 的 _BootstrapGlobals）
PluginManager.me = PluginManager.new()
_G.PluginDefs = PluginDefs
_G.PluginManager = PluginManager

return PluginManager