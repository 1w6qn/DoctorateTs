--[[
  BattleAssistPlugin.lua —— 战斗辅助插件
  提供：战斗时间轴文本、3 倍速、TAS 暂停（X 键暂停/继续，Alpha1 单帧）。参考 Arknights-Assist TASHook。
  高风险项（高倍速）默认关闭。API 随版本可能漂移，已做 pcall 兜底。
--]]
local BattleAssistPlugin = Class("BattleAssistPlugin", require("Plugin/BasePlugin"))
local eutil = CS.Torappu.Lua.Util

local UnityEngine = CS.UnityEngine
local UGUI = CS.UnityEngine.UI

--[[
  创建屏幕角落文本（时间轴显示）。
  @param parent 父 Transform
  @param name   对象名
  @param pos    位置
  @param fontSize 字号
  @return 文本组件
--]]
local function _CreateHudText(parent, name, pos, fontSize)
  local obj = UnityEngine.GameObject(name)
  obj.transform:SetParent(parent, false)
  local text = obj:AddComponent(typeof(UGUI.Text))
  local rect = obj:GetComponent(typeof(UnityEngine.RectTransform))
  rect.anchoredPosition3D = UnityEngine.Vector3(pos.x, pos.y, 0)
  rect.localScale = UnityEngine.Vector3.one
  rect.sizeDelta = UnityEngine.Vector2(400, 40)
  text.fontSize = fontSize
  text.color = UnityEngine.Color(1, 1, 1, 1)
  return text
end

--[[
  插件启用：创建 HUD 文本并 hook 战斗更新逻辑。
--]]
function BattleAssistPlugin:OnLoad()
  self._timeText = nil
  self._paused = false
  self._frameCount = 0

  -- 在战斗 UI 创建时挂时间轴文本
  self:Fix_ex(CS.Torappu.Battle.UI.UIController, "Awake", function(selfCtrl)
    local groupStatic = selfCtrl:get_groupStatic()
    self._timeText = _CreateHudText(groupStatic, "BattleTime(Clone)", UnityEngine.Vector3(-560, 300, 0), 24)
  end, nil)

  -- 每帧执行辅助逻辑
  self:Hotfix(CS.Torappu.Battle.BattleController, "Update", function(selfCtrl, orig)
    orig(selfCtrl)
    self:_Update(selfCtrl)
  end)
  eutil.Log("[BattleAssistPlugin] 战斗辅助已启用")
end

--[[
  每帧辅助逻辑：时间轴刷新、键盘指令（暂停/单帧/三倍速）。
  @param ctrl BattleController 实例
--]]
function BattleAssistPlugin:_Update(ctrl)
  local input = UnityEngine.Input
  -- 时间轴文本
  if self._timeText ~= nil then
    local ok, t = pcall(function() return ctrl:get_fixedPlayTime() end)
    if ok then
      self._timeText.text = "战斗时间: " .. tostring(t) .. "s"
    end
  end
  -- 暂停/继续（X 键）
  if input:GetKeyDown(UnityEngine.KeyCode.X) then
    self:_SetPaused(ctrl, not self._paused)
  end
  -- 单帧（Alpha1）：暂停状态下每帧放行一帧
  if input:GetKeyDown(UnityEngine.KeyCode.Alpha1) then
    self:_SetPaused(ctrl, true)
    self._frameCount = 0
  end
  -- 三倍速（Alpha3）
  if input:GetKeyDown(UnityEngine.KeyCode.Alpha3) then
    self:_SetSpeed(ctrl, "SUPER_FAST")
  end
  -- 单帧放行逻辑
  if self._paused and self._frameCount >= 0 then
    self._frameCount = self._frameCount + 1
    if self._frameCount >= 2 then -- 每 2 帧放行 1 次后回归暂停
      self:_SetPaused(ctrl, false)
      self._frameCount = -1
    end
  end
end

--[[
  设置暂停状态。
  @param ctrl  BattleController
  @param value true 暂停 / false 继续
--]]
function BattleAssistPlugin:_SetPaused(ctrl, value)
  self._paused = value
  xpcall(function() ctrl:SetPaused(value, false, false) end, debug.traceback)
end

--[[
  设置战斗速度档位。
  @param ctrl   BattleController
  @param levelName 速度档枚举名（如 SUPER_FAST）
--]]
function BattleAssistPlugin:_SetSpeed(ctrl, levelName)
  xpcall(function()
    local level = CS.Torappu.Battle.SpeedLevel[levelName]
    ctrl:set_speedLevel(level)
  end, debug.traceback)
end

--[[
  插件停用：清空时间轴文本。
--]]
function BattleAssistPlugin:OnUnload()
  if self._timeText ~= nil then
    self._timeText.gameObject:SetActive(false)
  end
  self._timeText = nil
  self._paused = false
  eutil.Log("[BattleAssistPlugin] 战斗辅助已停用")
end

return BattleAssistPlugin