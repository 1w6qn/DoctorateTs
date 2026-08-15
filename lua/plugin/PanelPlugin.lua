--[[
  PanelPlugin.lua —— 插件管理面板插件
  动态构建一个现代化管理面板：浮动开关按钮 + 插件列表（名称/描述/启停开关），
  通过 PluginManager:SetEnabled 实时启停插件。面板用 UnityEngine.UI 动态构建。
--]]
local PanelPlugin = Class("PanelPlugin", require("Plugin/BasePlugin"))
local eutil = CS.Torappu.Lua.Util

local UnityEngine = CS.UnityEngine
local UGUI = CS.UnityEngine.UI

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
  插件启用：找到常驻 UI 根节点，构建面板与浮动开关。
--]]
function PanelPlugin:OnLoad()
  self._open = false
  self._root = nil
  self._canvas = nil

  -- 找主 UI 画布（LuaUIRoot 或场景主 Canvas）
  self:_FindCanvas()
  if self._canvas == nil then
    eutil.LogHotfixError("[PanelPlugin] 未找到 UI Canvas，面板无法构建")
    return
  end
  self:_BuildFloatingButton()
  self:_BuildPanel()
  eutil.Log("[PanelPlugin] 插件管理面板已启用")
end

--[[
  定位主 UI Canvas（优先 LuaUIRoot，其次场景内 Canvas）。
--]]
function PanelPlugin:_FindCanvas()
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
  构建右下角浮动开关按钮（点击开合面板）。
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
  -- 逐插件渲染行
  local plugins = PluginManager.me:GetAll()
  local y = 140
  for _, plugin in ipairs(plugins) do
    local rowBg, _ = _CreateImage(trans, "Row", UnityEngine.Vector3(0, y, 0), UnityEngine.Vector2(420, 64), UnityEngine.Color(0.2, 0.2, 0.25, 0.6))
    local nameText = _CreateText(rowBg.transform, "Name", UnityEngine.Vector3(-150, 18, 0), UnityEngine.Vector2(260, 24), 20, UnityEngine.Color(1, 1, 1, 1))
    nameText.text = plugin.name
    local descText = _CreateText(rowBg.transform, "Desc", UnityEngine.Vector3(-150, -8, 0), UnityEngine.Vector2(260, 20), 13, UnityEngine.Color(0.7, 0.7, 0.7, 1))
    descText.text = plugin.desc
    local state = _CreateText(rowBg.transform, "State", UnityEngine.Vector3(150, 18, 0), UnityEngine.Vector2(70, 24), 16, UnityEngine.Color(0.4, 1, 0.4, 1))
    state.alignment = UnityEngine.TextAnchor.MiddleCenter
    state.text = plugin.enabled and "ON" or "OFF"
    state.color = plugin.enabled and UnityEngine.Color(0.4, 1, 0.4, 1) or UnityEngine.Color(1, 0.4, 0.4, 1)
    -- 开关按钮
    local btnObj, _ = _CreateImage(rowBg.transform, "Toggle", UnityEngine.Vector3(150, -8, 0), UnityEngine.Vector2(64, 28), UnityEngine.Color(0.3, 0.6, 1, 1))
    local btnText = _CreateText(btnObj.transform, "Text", UnityEngine.Vector3.zero, UnityEngine.Vector2(64, 28), 14, UnityEngine.Color(1, 1, 1, 1))
    btnText.alignment = UnityEngine.TextAnchor.MiddleCenter
    btnText.text = "切换"
    local btn = btnObj:AddComponent(typeof(UGUI.Button))
    local pluginId = plugin.id
    local selfRef = self
    btn.onClick:AddListener(function()
      PluginManager.me:SetEnabled(pluginId, not plugin.enabled)
      selfRef:Refresh()
    end)
    y = y - 78
  end
end

--[[
  开合面板。
--]]
function PanelPlugin:TogglePanel()
  self._open = not self._open
  if self._root ~= nil then
    self._root:SetActive(self._open)
    if self._open then self:Refresh() end
  end
end

--[[
  插件停用：销毁面板与浮动按钮。
--]]
function PanelPlugin:OnUnload()
  if self._root ~= nil then
    UnityEngine.Object.Destroy(self._root)
  end
  self._root = nil
  self._open = false
  eutil.Log("[PanelPlugin] 插件管理面板已停用")
end

return PanelPlugin