--[[
  PluginHeartbeat.lua —— 插件生效确认心跳 + 服务端状态同步
  插件系统在游戏内构建 UI 后，经游戏原生 UISender 向服务端发送请求：
    - GET  /plugin/heartbeat  生效确认（响应含服务端启停状态，best-effort 应用）
    - GET  /plugin/config/<id>/<0|1>  客户端启停状态推送（路径编码，无需参数表约定）
  用于真机验证「插件是否真正加载生效」，并让管理端/面板的启停状态保持同步。

  时序说明：内置 bundle 由 DefinedFix 在 HotfixProcesser.Do 阶段引导（先于
  ModelMgr.Init / 网络就绪）。因此：
    - TimerModel.me 可用时，ScheduleAuto 走延迟重试链（网络就绪后自动重试）；
    - 引导阶段 TimerModel 未就绪时，立即尝试一次，后续由进入战斗 UI 的
      UIController.Awake 兜底（必然晚于登录与网络就绪）触发自动确认；
    - 面板打开时由 PanelPlugin 显式调用 Send() 再次确认。
  全程 xpcall 兜底，绝不阻断游戏。
--]]
local PluginHeartbeat = {}
local eutil = CS.Torappu.Lua.Util
local PluginHotfix = require("Plugin/PluginHotfix")

local _MAX_RETRY = 6
local _RETRY_DELAY_SEC = 5
-- 每会话自动确认只发一次（战斗 UI 兜底 / 重试链共用）
local _autoConfirmed = false

--[[
  解析心跳响应并应用服务端启停状态（best-effort）。
  响应体可能直接为 {catalog=...}，也可能被游戏网络层包一层 {result=...}。
  @param data 心跳响应数据
--]]
local function _OnHeartbeatResponse(data)
  xpcall(function()
    if data == nil then return end
    local body = data
    if type(data.result) == "table" then
      body = data.result
    end
    local catalog = body.catalog
    if type(catalog) ~= "table" then return end
    for _, p in ipairs(catalog) do
      if type(p) == "table" and p.id ~= nil then
        local enabled = (p.enabled == true)
        local cur = PluginManager.me:GetPlugin(tostring(p.id))
        if cur ~= nil and cur.enabled ~= enabled then
          PluginManager.me:SetEnabled(tostring(p.id), enabled)
        end
      end
    end
  end, debug.traceback)
end

--[[
  带回调的心跳发送（尝试应用服务端状态）。
  UISender 回调参数位置依赖真机约定，依次尝试常见形式；全部失败返回 false，
  由调用方退化为无回调发送（保持原行为不回归）。
  @param url 请求路径
  @param fn  响应回调
  @return 发送是否被接受
--]]
local function _SendWithCallback(url, fn)
  local ok1 = pcall(function()
    UISender:SendGet(url, { callback = fn }, { useMask = false })
  end)
  if ok1 then return true end
  local ok2 = pcall(function()
    UISender:SendGet(url, fn, { useMask = false })
  end)
  return ok2
end

--[[
  核心发送：向服务端发送确认（可选应用服务端启停状态）。
  @param applyServerState 是否尝试带回调发送并应用服务端状态
  @return 发送是否被接受（UISender 就绪且调用成功）
--]]
local function _SendOnce(applyServerState)
  local okSend = xpcall(function()
    if UISender == nil or UISender.SendGet == nil then
      eutil.LogHotfixError("[PluginHeartbeat] UISender 未就绪，跳过心跳")
      return
    end
    if applyServerState then
      local ok = _SendWithCallback("/plugin/heartbeat", _OnHeartbeatResponse)
      if ok then
        eutil.Log("[PluginHeartbeat] 已向服务端发送插件生效确认（含状态同步）")
        return
      end
    end
    UISender:SendGet("/plugin/heartbeat", nil, { useMask = false })
    eutil.Log("[PluginHeartbeat] 已向服务端发送插件生效确认")
  end, debug.traceback)
  return okSend
end

--[[
  每会话一次的自动确认（重试链 / 战斗 UI 兜底共用）。
  仅当发送被接受（UISender 就绪）才标记已确认，保证引导阶段失败后
  后续重试 / 战斗 UI 兜底仍能补发。
--]]
local function _AutoConfirm()
  if _autoConfirmed then return end
  if _SendOnce(true) then
    _autoConfirmed = true
  end
end

--[[
  安装战斗 UI 兜底确认：hook UIController.Awake（必然晚于登录与网络就绪），
  经共享注册表与其它插件同方法 hook 链式共存；_autoConfirmed 保证只确认一次。
--]]
local _battleHookInstalled = false
local function _InstallBattleConfirm()
  if _battleHookInstalled then return end
  _battleHookInstalled = true
  xpcall(function()
    PluginHotfix.Hotfix(CS.Torappu.Battle.UI.UIController, "Awake", PluginHeartbeat, function(selfCtrl, orig)
      orig(selfCtrl)
      _AutoConfirm()
    end)
  end, debug.traceback)
end

--[[
  对外发送入口：立即发送一次并尝试应用服务端状态（面板打开等显式场景）。
  发送成功后标记自动确认已达成，避免战斗 UI 兜底重复发送。
--]]
function PluginHeartbeat.Send()
  if _SendOnce(true) then
    _autoConfirmed = true
  end
end

--[[
  自动确认：引导阶段调用。TimerModel.me 可用时走延迟重试链（网络就绪后
  自动重试 _MAX_RETRY 次）；不可用（ModelMgr 未初始化）时立即尝试一次，
  后续由战斗 UI 兜底确认。
--]]
function PluginHeartbeat.ScheduleAuto()
  _InstallBattleConfirm()
  local ok, tm = pcall(function()
    if TimerModel ~= nil and TimerModel.me ~= nil then return TimerModel.me end
    return nil
  end)
  if not ok or tm == nil then
    _AutoConfirm()
    return
  end
  _AutoConfirm()
  local retries = 0
  local function retry()
    retries = retries + 1
    _AutoConfirm()
    if retries < _MAX_RETRY and TimerModel.me ~= nil then
      TimerModel.me:Delay(_RETRY_DELAY_SEC, retry)
    end
  end
  tm:Delay(_RETRY_DELAY_SEC, retry)
end

--[[
  客户端启停状态推送：面板切换插件后调用，best-effort 同步到服务端
  data/plugin/config.json（路径编码，避免依赖 UISender 参数表约定）。
  @param id    插件标识
  @param value true 启用 / false 停用
--]]
function PluginHeartbeat.PushState(id, value)
  xpcall(function()
    if UISender == nil or UISender.SendGet == nil then
      return
    end
    local v = value and "1" or "0"
    UISender:SendGet("/plugin/config/" .. tostring(id) .. "/" .. v, nil, { useMask = false })
  end, debug.traceback)
end

return PluginHeartbeat
