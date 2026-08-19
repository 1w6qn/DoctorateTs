--[[
  PanelPlugin.lua —— 插件管理面板插件
  动态构建一个现代化管理面板：浮动开关按钮 + 插件列表（名称/描述/启停开关），
  通过 PluginManager:SetEnabled 实时启停插件。面板用 UnityEngine.UI 动态构建。

  时序说明：插件系统在 DefinedFix 引导阶段初始化（早于登录与主 UI 创建），
  此时 Canvas 尚不存在。因此 OnLoad 不直接构建，而是：
    - 立即尝试一次；
    - TimerModel 可用时按间隔重试（上限 _MAX_RETRY 次）；
    - 兜底 hook UIController.Awake（进入战斗 UI，必然晚于主界面）时再尝试。
  面板构建成功（或重建）后均会重新挂载，场景切换导致 Canvas 销毁时也能自愈。
--]]
local PanelPlugin = Class("PanelPlugin", require("Plugin/BasePlugin"))
local eutil = CS.Torappu.Lua.Util
local PluginHeartbeat = require("Plugin/PluginHeartbeat")

-- 类级元数据（管理器/面板/管理端目录以此为准；与 PluginDefs.lua 保持一致）
PanelPlugin.id = "plugin_panel"
PanelPlugin.name = "插件管理面板"
PanelPlugin.desc = "现代化插件启停管理面板"

local UnityEngine = CS.UnityEngine
local UGUI = CS.UnityEngine.UI

-- 重试上限与间隔（TimerModel 可用时）
local _MAX_RETRY = 20
local _RETRY_DELAY_SEC = 3

--[[
  创建带背景的 UI 对象。
  @param parent 父 Transform
  @param name   对象名
  @param pos    位置（Vector3）
  @param size   尺寸（Vector2）
  @param color  背景色
  @return 对象（Image 组件）
--]]
local function _CreateImage(parent, name, pos, size, color)
  local obj = UnityEngine.GameObject(name)
  obj.transform:SetParent(parent, false)
  local img = obj:AddComponent(typeof(UGUI.Image))
  local rect = obj:GetComponent(typeof(UnityEngine.RectTransform))
  rect.anchoredPosition3D = pos
  rect.localScale = UnityEngine.Vector3.one
  rect.sizeDelta = size
  img.color = color
  return obj, img
end

--[[
  创建文本组件。
  @param parent 父 Transform
  @param name   对象名
  @param pos    位置
  @param size   尺寸
  @param fontSize 字号
  @param color  颜色
  @return 文本组件
--]]
local function _CreateText(parent, name, pos, size, fontSize, color)
  local obj = UnityEngine.GameObject(name)
  obj.transform:SetParent(parent, false)
  local text = obj:AddComponent(typeof(UGUI.Text))
  local rect = obj:GetComponent(typeof(UnityEngine.RectTransform))
  rect.anchoredPosition3D = pos
  rect.localScale = UnityEngine.Vector3.one
  rect.sizeDelta = size
  text.fontSize = fontSize
  text.color = color
  return text
end

--[[
  插件启用：尝试构建面板；失败则延迟重试 + 战斗 UI 兜底。
--]]
function PanelPlugin:OnLoad()
  self._open = false
  self._root = nil
  self._floatBtn = nil
  self._canvas = nil
  self._retryCount = 0

  self:_EnsureCanvasAndBuild()

  -- 兜底：进入战斗 UI（必然晚于登录与主界面）时再次尝试构建
  self:Hotfix(CS.Torappu.Battle.UI.UIController, "Awake", function(selfCtrl, orig)
    orig(selfCtrl)
    self:_EnsureCanvasAndBuild()
  end)
  eutil.Log("[PanelPlugin] 插件管理面板已启用")
end

--[[
  确保面板已构建：查找 Canvas，缺失则调度重试；已构建则无操作。
  根节点/按钮被销毁（场景切换）时自动重建。
--]]
function PanelPlugin:_EnsureCanvasAndBuild()
  if self._root ~= nil and self._floatBtn ~= nil then return end
  self:_FindCanvas()
  if self._canvas == nil then
    self:_ScheduleRetry()
    return
  end
  if self._floatBtn == nil then
    self:_BuildFloatingButton()
  end
  if self._root == nil then
    self:_BuildPanel()
  end
end

--[[
  调度延迟重试（TimerModel 可用时）。引导阶段 TimerModel 未就绪时静默，
  由 UIController.Awake 兜底触发。
--]]
function PanelPlugin:_ScheduleRetry()
  if self._retryCount >= _MAX_RETRY then return end
  self._retryCount = self._retryCount + 1
  local ok, tm = pcall(function()
    if TimerModel ~= nil and TimerModel.me ~= nil then return TimerModel.me end
    return nil
  end)
  if not ok or tm == nil then
    return
  end
  tm:Delay(_RETRY_DELAY_SEC, function()
    if not self.enabled then return end
    self:_EnsureCanvasAndBuild()
  end)
end

--[[
  定位主 UI Canvas（优先 LuaUIRoot，其次场景内 Canvas）。
--]]
function PanelPlugin:_FindCanvas()
  self._canvas = nil
  local ok, luaRoot = pcall(function()
    return UnityEngine.GameObject.Find("UI/Main/LuaUIRoot")
  end)
  if ok and luaRoot ~= nil then
    self._canvas = luaRoot.transform
    return
  end
  local ok2, canvas = pcall(function()
    return UnityEngine.Object.FindObjectOfType(typeof(UnityEngine.Canvas))
  end)
  if ok2 and canvas ~= nil then
    self._canvas = canvas.transform
  end
end

--[[
  构建右下角浮动开关按钮（点击开合面板）。按钮对象保存到 self._floatBtn，
  供 OnUnload 销毁（避免停用后按钮残留）。
--]]
function PanelPlugin:_BuildFloatingButton()
  local btnObj, _ = _CreateImage(self._canvas, "PluginToggle(Clone)", UnityEngine.Vector3(-300, -160, 0), UnityEngine.Vector2(120, 60), UnityEngine.Color(0.1, 0.1, 0.1, 0.8))
  local btnText = _CreateText(btnObj.transform, "Text", UnityEngine.Vector3.zero, UnityEngine.Vector2(120, 60), 22, UnityEngine.Color(1, 1, 1, 1))
  btnText.alignment = UnityEngine.TextAnchor.MiddleCenter
  btnText.text = "插件"
  local btn = btnObj:AddComponent(typeof(UGUI.Button))
  btn.onClick:AddListener(function()
    self:TogglePanel()
  end)
  self._floatBtn = btnObj
end

--[[
  构建面板主体（初始隐藏）。
--]]
function PanelPlugin:_BuildPanel()
  local root, _ = _CreateImage(self._canvas, "PluginPanel(Clone)", UnityEngine.Vector3(-260, 0, 0), UnityEngine.Vector2(460, 420), UnityEngine.Color(0.05, 0.05, 0.08, 0.92))
  local title = _CreateText(root.transform, "Title", UnityEngine.Vector3(0, 180, 0), UnityEngine.Vector2(440, 40), 26, UnityEngine.Color(0.9, 0.9, 1, 1))
  title.alignment = UnityEngine.TextAnchor.MiddleCenter
  title.text = "Lua 插件管理"
  self._root = root
  self._root:SetActive(false)
  self:Refresh()
end

--[[
  重建插件列表（每次开合/启停后调用，保证状态实时）。
--]]
function PanelPlugin:Refresh()
  if self._root == nil then return end
  -- 清空旧的列表子节点
  local trans = self._root.transform
  for i = trans.childCount - 1, 0, -1 do
    UnityEngine.Object.Destroy(trans:GetChild(i).gameObject)
  end
  -- 逐插件渲染行（遍历 PluginDefs 以覆盖加载失败的插件）
  local mgr = PluginManager.me
  local y = 140
  for _, def in ipairs(PluginDefs) do
    local plugin = mgr:GetPlugin(def.id)
    local err = mgr:GetError(def.id)
    local rowBg, _ = _CreateImage(trans, "Row", UnityEngine.Vector3(0, y, 0), UnityEngine.Vector2(420, 64), UnityEngine.Color(0.2, 0.2, 0.25, 0.6))
    local nameText = _CreateText(rowBg.transform, "Name", UnityEngine.Vector3(-150, 18, 0), UnityEngine.Vector2(260, 24), 20, UnityEngine.Color(1, 1, 1, 1))
    nameText.text = def.name
    local descText = _CreateText(rowBg.transform, "Desc", UnityEngine.Vector3(-150, -8, 0), UnityEngine.Vector2(260, 20), 13, UnityEngine.Color(0.7, 0.7, 0.7, 1))
    descText.text = err ~= nil and err or def.desc
    descText.color = err ~= nil and UnityEngine.Color(1, 0.5, 0.5, 1) or UnityEngine.Color(0.7, 0.7, 0.7, 1)
    -- 状态/错误标记
    local state = _CreateText(rowBg.transform, "State", UnityEngine.Vector3(150, 18, 0), UnityEngine.Vector2(70, 24), 16, UnityEngine.Color(0.4, 1, 0.4, 1))
    state.alignment = UnityEngine.TextAnchor.MiddleCenter
    if plugin == nil then
      state.text = "ERR"
      state.color = UnityEngine.Color(1, 0.3, 0.3, 1)
    else
      state.text = plugin.enabled and "ON" or "OFF"
      state.color = plugin.enabled and UnityEngine.Color(0.4, 1, 0.4, 1) or UnityEngine.Color(1, 0.4, 0.4, 1)
    end
    -- 开关按钮（加载失败的插件无可启停对象，禁用）
    local btnObj, _ = _CreateImage(rowBg.transform, "Toggle", UnityEngine.Vector3(150, -8, 0), UnityEngine.Vector2(64, 28), plugin == nil and UnityEngine.Color(0.4, 0.4, 0.4, 1) or UnityEngine.Color(0.3, 0.6, 1, 1))
    local btnText = _CreateText(btnObj.transform, "Text", UnityEngine.Vector3.zero, UnityEngine.Vector2(64, 28), 14, UnityEngine.Color(1, 1, 1, 1))
    btnText.alignment = UnityEngine.TextAnchor.MiddleCenter
    btnText.text = "切换"
    if plugin ~= nil then
      local btn = btnObj:AddComponent(typeof(UGUI.Button))
      local pluginId = def.id
      local selfRef = self
      btn.onClick:AddListener(function()
        PluginManager.me:SetEnabled(pluginId, not plugin.enabled)
        selfRef:Refresh()
      end)
    end
    y = y - 78
  end
end

--[[
  开合面板（面板未构建时先尝试构建，失败则静默返回）。
--]]
function PanelPlugin:TogglePanel()
  if self._root == nil then
    self:_EnsureCanvasAndBuild()
    if self._root == nil then
      eutil.LogHotfixError("[PanelPlugin] 面板未构建，无法开合（Canvas 尚不可用）")
      return
    end
  end
  self._open = not self._open
  self._root:SetActive(self._open)
  if self._open then
    self:Refresh()
    -- 面板打开（登录后、网络就绪）时再次发送插件生效确认，作为可复现的服务端日志依据
    PluginHeartbeat.Send()
  end
end

--[[
  插件停用：销毁面板与浮动按钮。
--]]
function PanelPlugin:OnUnload()
  if self._root ~= nil then
    UnityEngine.Object.Destroy(self._root)
  end
  if self._floatBtn ~= nil then
    UnityEngine.Object.Destroy(self._floatBtn)
  end
  self._root = nil
  self._floatBtn = nil
  self._canvas = nil
  self._open = false
  eutil.Log("[PanelPlugin] 插件管理面板已停用")
end

return PanelPlugin
