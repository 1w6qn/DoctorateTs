--[[
  EnemyHpPlugin.lua —— 敌人血量显示插件
  参考 Arknights-Assist 的 EnemyHpSliderHook：hotfix Torappu.Battle.UI.UIUnitHUD.Attach，
  对非 Character/Token 的单位，在血条（_hpSlider）下动态创建「当前/最大」血量文本。
  注：方法/字段名以真机 dump 校准为准（客户端版本可能漂移），此处已做 pcall 兜底。
--]]
local EnemyHpPlugin = Class("EnemyHpPlugin", require("Plugin/BasePlugin"))
local eutil = CS.Torappu.Lua.Util

-- 全局字体（懒取一次，供血量文本使用）
EnemyHpPlugin._font = nil

--[[
  解析 UITextSlider.TextMode.A_SLASH_B 枚举值；解析失败返回 nil。
  @return 枚举值或 nil
--]]
local function _ResolveTextMode()
  local ok, mode = pcall(function()
    return CS.Torappu.UI.UITextSlider.TextMode.A_SLASH_B
  end)
  return ok and mode or nil
end

--[[
  获取血量文本字体（懒加载）。优先取内置 Arial，失败返回 nil（用 Unity 默认字体）。
  @return UnityEngine.Font 或 nil
--]]
local function _GetFont()
  if EnemyHpPlugin._font == nil then
    local ok, font = pcall(function()
      return CS.UnityEngine.Resources.GetBuiltinResource(typeof(CS.UnityEngine.Font), "Arial.ttf")
    end)
    EnemyHpPlugin._font = ok and font or nil
  end
  return EnemyHpPlugin._font
end

--[[
  在指定血条下动态创建血量文本子节点并挂到 _hpSlider。
  @param hp  UITextSlider（_hpSlider 字段）
--]]
local function _CreateHpText(hp)
  local obj = CS.UnityEngine.GameObject("HpText_C(Clone)")
  obj.transform:SetParent(hp.transform, false)
  local text = obj:AddComponent(typeof(CS.UnityEngine.UI.Text))
  local rect = obj:GetComponent(typeof(CS.UnityEngine.RectTransform))
  rect.anchoredPosition3D = CS.UnityEngine.Vector3(155, -15, 0)
  rect.localScale = CS.UnityEngine.Vector3.one
  rect.sizeDelta = CS.UnityEngine.Vector2(400, 20)
  local font = _GetFont()
  if font ~= nil then text.font = font end
  text.fontSize = 16
  text.color = CS.UnityEngine.Color(1, 0, 0, 1)
  hp._text = text
  local mode = _ResolveTextMode()
  if mode ~= nil then hp._textMode = mode end
end

--[[
  UIUnitHUD.Attach 的替换实现：为敌人附加血量文本后调用原 Attach。
  @param selfHud  UIUnitHUD 实例
  @param orig     原 Attach 方法
  @param owner    要附加的单位
--]]
local function _AttachFix(selfHud, orig, owner)
  local ok, err = xpcall(function()
    local isCharacter = owner:GetType() == typeof(CS.Torappu.Battle.Character)
    local isToken = owner:GetType() == typeof(CS.Torappu.Battle.Token)
    if not isCharacter and not isToken then
      local hp = selfHud._hpSlider
      if hp ~= nil and hp._text == nil then
        _CreateHpText(hp)
      end
    end
  end, debug.traceback)
  if not ok then
    eutil.LogHotfixError("[EnemyHpPlugin] Attach fix 失败: " .. err)
  end
  return orig(selfHud, owner)
end

--[[
  插件启用：hotfix UIUnitHUD.Attach。
--]]
function EnemyHpPlugin:OnLoad()
  self:Hotfix(CS.Torappu.Battle.UI.UIUnitHUD, "Attach", _AttachFix)
  eutil.Log("[EnemyHpPlugin] 敌人血量显示已启用")
end

--[[
  插件停用：清理（补丁由 BasePlugin 统一还原）。
--]]
function EnemyHpPlugin:OnUnload()
  eutil.Log("[EnemyHpPlugin] 敌人血量显示已停用")
end

return EnemyHpPlugin