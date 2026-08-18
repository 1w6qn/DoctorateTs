--[[
  PluginDefs.lua —— 插件清单
  供 PluginManager 加载：module 为 require 路径（对齐打包后的 m_Name，如 "Plugin/EnemyHpPlugin"）。
--]]
local PluginDefs = {
  {
    id = "network_redirect",
    name = "私服引导",
    desc = "将客户端网络路由与签名校验重定向到本私服（保持启用，关闭则连不回私服）",
    module = "Plugin/NetworkRedirectPlugin",
  },
  {
    id = "enemy_hp",
    name = "敌人血量显示",
    desc = "在敌人血条旁显示具体血量数值",
    module = "Plugin/EnemyHpPlugin",
  },
  {
    id = "enemy_info",
    name = "敌人属性面板",
    desc = "战斗中长按并点击敌人查看属性与路线",
    module = "Plugin/EnemyInfoPlugin",
  },
  {
    id = "battle_assist",
    name = "战斗辅助",
    desc = "战斗时间轴 / 倍速 / TAS 暂停帧",
    module = "Plugin/BattleAssistPlugin",
  },
  {
    id = "plugin_panel",
    name = "插件管理面板",
    desc = "现代化插件启停管理面板",
    module = "Plugin/PanelPlugin",
  },
}

return PluginDefs